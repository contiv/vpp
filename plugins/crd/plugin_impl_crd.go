// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/crd.proto

package crd

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	vppnodemodel "github.com/contiv/vpp/plugins/nodesync/vppnode"

	"github.com/namsral/flag"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/contiv/vpp/plugins/crd/utils"
	"go.ligato.io/cn-infra/v2/config"
	"go.ligato.io/cn-infra/v2/datasync"
	"go.ligato.io/cn-infra/v2/datasync/resync"
	"go.ligato.io/cn-infra/v2/db/keyval/etcd"
	"go.ligato.io/cn-infra/v2/infra"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/rpc/rest"
	"go.ligato.io/cn-infra/v2/servicelabel"
	"go.ligato.io/cn-infra/v2/utils/safeclose"

	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache"
	"github.com/contiv/vpp/plugins/crd/controller"
	"github.com/contiv/vpp/plugins/crd/handler/customconfiguration"
	"github.com/contiv/vpp/plugins/crd/handler/customnetwork"
	"github.com/contiv/vpp/plugins/crd/handler/externalinterface"
	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/nodeconfig"
	"github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain"
	"github.com/contiv/vpp/plugins/crd/handler/telemetry"
	"github.com/contiv/vpp/plugins/crd/validator"

	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	nodeconfigv1 "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	telemetryv1 "github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"

	factory "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
)

const (
	k8sResyncInterval = 10 * time.Minute
)

// Plugin implements NodeConfig and TelemetryReport CRDs.
type Plugin struct {
	Deps

	resyncChan chan datasync.ResyncEvent
	changeChan chan datasync.ChangeEvent

	watchConfigReg datasync.WatchRegistration

	resyncLock sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// delay resync until the contiv plugin has been re-synchronized.
	resyncCounter  uint
	pendingResync  datasync.ResyncEvent
	pendingChanges []datasync.ChangeEvent

	telemetryController            *controller.CrdController
	nodeConfigController           *controller.CrdController
	customNetworkController        *controller.CrdController
	externalInterfaceController    *controller.CrdController
	serviceFunctionChainController *controller.CrdController
	customConfigController         *controller.CrdController
	cache                          *cache.ContivTelemetryCache
	processor                      api.ContivTelemetryProcessor
	verbose                        bool

	crdClient     *crdClientSet.Clientset
	apiclientset  *apiextcs.Clientset
	sharedFactory factory.SharedInformerFactory
}

// Deps defines dependencies of CRD plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI

	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig

	Resync resync.Subscriber

	HTTP rest.HTTPHandlers

	/* both Publish and Watcher are prefixed for KSR-published K8s state data */
	Watcher datasync.KeyValProtoWatcher
	Etcd    *etcd.Plugin // etcd plugin is specifically required for election and raw-data support
}

const electionPrefix = "/contiv-crd/election"

// Init initializes policy layers and caches and starts watching contiv-etcd for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)
	p.verbose = flag.Lookup("verbose").Value.String() == "true"

	netctlRESTdisabled := os.Getenv("DISABLE_NETCTL_REST")
	if netctlRESTdisabled == "" {
		p.HTTP.RegisterHTTPHandler("/netctl", utils.HandleNetctlCommand, "POST")
	}

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	p.ctx, p.cancel = context.WithCancel(context.Background())

	kubeconfig := p.KubeConfig.GetConfigName()
	p.Log.WithField("kubeconfig", kubeconfig).Info("Loading kubernetes client config")
	k8sClientConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	p.crdClient, err = crdClientSet.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build crd Client: %s", err)
	}

	p.apiclientset, err = apiextcs.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build api Client: %s", err)
	}

	p.sharedFactory = factory.NewSharedInformerFactory(p.crdClient, k8sResyncInterval)

	err = p.initializeTelemetry()
	if err != nil {
		return err
	}

	go p.watchEvents()
	err = p.subscribeWatcher()
	if err != nil {
		return err
	}

	// init and start CRD controllers only after connection with etcd has been established
	p.Etcd.OnConnect(p.onEtcdConnect)
	return nil
}

// initializeCRDs initializes and starts controllers for all CRDs except for Telemetry (which is initialized
// by initializeTelemetry()).
// Must be run *after* (first) connection with etcd has been established.
func (p *Plugin) initializeCRDs() error {
	nodeConfigInformer := p.sharedFactory.Nodeconfig().V1().NodeConfigs().Informer()
	p.nodeConfigController = &controller.CrdController{
		Deps: controller.Deps{
			Log:       p.Log.NewLogger("nodeConfigController"),
			APIClient: p.apiclientset,
			Informer:  nodeConfigInformer,
			EventHandler: &kvdbreflector.KvdbReflector{
				Deps: kvdbreflector.Deps{
					Log:          p.Log.NewLogger("nodeConfigHandler"),
					ServiceLabel: p.ServiceLabel,
					Publish:      p.Etcd.RawAccess(),
					Informer:     nodeConfigInformer,
					Handler: &nodeconfig.Handler{
						CrdClient: p.crdClient,
					},
				},
			},
		},
		Spec: controller.CrdSpec{
			TypeName: reflect.TypeOf(nodeconfigv1.NodeConfig{}).Name(),
			Group:    nodeconfigv1.CRDGroup,
			Version:  nodeconfigv1.CRDGroupVersion,
			Plural:   nodeconfigv1.CRDContivNodeConfigPlural,
		},
	}

	customNetworkInformer := p.sharedFactory.Contivpp().V1().CustomNetworks().Informer()
	p.customNetworkController = &controller.CrdController{
		Deps: controller.Deps{
			Log:       p.Log.NewLogger("customNetworkController"),
			APIClient: p.apiclientset,
			Informer:  customNetworkInformer,
			EventHandler: &kvdbreflector.KvdbReflector{
				Deps: kvdbreflector.Deps{
					Log:          p.Log.NewLogger("customNetworkHandler"),
					ServiceLabel: p.ServiceLabel,
					Publish:      p.Etcd.RawAccess(),
					Informer:     customNetworkInformer,
					Handler: &customnetwork.Handler{
						CrdClient: p.crdClient,
					},
				},
			},
		},
		Spec: controller.CrdSpec{
			TypeName:   reflect.TypeOf(v1.CustomNetwork{}).Name(),
			Group:      contivppio.GroupName,
			Version:    "v1",
			Plural:     "customnetworks",
			Validation: customnetwork.Validation(),
		},
	}

	externalInterfaceInformer := p.sharedFactory.Contivpp().V1().ExternalInterfaces().Informer()
	p.externalInterfaceController = &controller.CrdController{
		Deps: controller.Deps{
			Log:       p.Log.NewLogger("externalInterfaceController"),
			APIClient: p.apiclientset,
			Informer:  externalInterfaceInformer,
			EventHandler: &kvdbreflector.KvdbReflector{
				Deps: kvdbreflector.Deps{
					Log:          p.Log.NewLogger("externalInterfaceHandler"),
					ServiceLabel: p.ServiceLabel,
					Publish:      p.Etcd.RawAccess(),
					Informer:     externalInterfaceInformer,
					Handler: &externalinterface.Handler{
						CrdClient: p.crdClient,
					},
				},
			},
		},
		Spec: controller.CrdSpec{
			TypeName:   reflect.TypeOf(v1.ExternalInterface{}).Name(),
			Group:      contivppio.GroupName,
			Version:    "v1",
			Plural:     "externalinterfaces",
			Validation: externalinterface.Validation(),
		},
	}

	serviceFunctionChainInformer := p.sharedFactory.Contivpp().V1().ServiceFunctionChains().Informer()
	p.serviceFunctionChainController = &controller.CrdController{
		Deps: controller.Deps{
			Log:       p.Log.NewLogger("serviceFunctionChainController"),
			APIClient: p.apiclientset,
			Informer:  serviceFunctionChainInformer,
			EventHandler: &kvdbreflector.KvdbReflector{
				Deps: kvdbreflector.Deps{
					Log:          p.Log.NewLogger("serviceFunctionChainHandler"),
					ServiceLabel: p.ServiceLabel,
					Publish:      p.Etcd.RawAccess(),
					Informer:     serviceFunctionChainInformer,
					Handler: &servicefunctionchain.Handler{
						CrdClient: p.crdClient,
					},
				},
			},
		},
		Spec: controller.CrdSpec{
			TypeName:   reflect.TypeOf(v1.ServiceFunctionChain{}).Name(),
			Group:      contivppio.GroupName,
			Version:    "v1",
			Plural:     "servicefunctionchains",
			Validation: servicefunctionchain.Validation(),
		},
	}

	customConfigInformer := p.sharedFactory.Contivpp().V1().CustomConfigurations().Informer()
	customConfigLog := p.Log.NewLogger("customConfigHandler")
	p.customConfigController = &controller.CrdController{
		Deps: controller.Deps{
			Log:       p.Log.NewLogger("customConfigController"),
			APIClient: p.apiclientset,
			Informer:  customConfigInformer,
			EventHandler: &kvdbreflector.KvdbReflector{
				Deps: kvdbreflector.Deps{
					Log:          customConfigLog,
					ServiceLabel: p.ServiceLabel,
					Publish:      p.Etcd.RawAccess(),
					Informer:     customConfigInformer,
					Handler: &customconfiguration.Handler{
						Log:       customConfigLog,
						CrdClient: p.crdClient,
					},
				},
			},
		},
		Spec: controller.CrdSpec{
			TypeName:   reflect.TypeOf(v1.CustomConfiguration{}).Name(),
			Group:      contivppio.GroupName,
			Version:    "v1",
			Plural:     "customconfigurations",
			Validation: customconfiguration.Validation(),
		},
	}

	p.nodeConfigController.Init()
	p.customNetworkController.Init()
	p.externalInterfaceController.Init()
	p.serviceFunctionChainController.Init()
	p.customConfigController.Init()

	if p.verbose {
		p.customNetworkController.Log.SetLevel(logging.DebugLevel)
		p.nodeConfigController.Log.SetLevel(logging.DebugLevel)
		p.externalInterfaceController.Log.SetLevel(logging.DebugLevel)
		p.serviceFunctionChainController.Log.SetLevel(logging.DebugLevel)
		p.customConfigController.Log.SetLevel(logging.DebugLevel)
		customConfigLog.SetLevel(logging.DebugLevel)
	}

	return nil
}

func (p *Plugin) initializeTelemetry() error {
	// Time interval for periodic report collection
	collectionInterval := 5 * time.Minute
	configuredInterval, err := strconv.Atoi(os.Getenv("CONTIV_CRD_VALIDATE_INTERVAL"))
	if err == nil {
		collectionInterval = time.Duration(configuredInterval) * time.Minute
	}

	// Agent state to dump and validate
	validateState := os.Getenv("CONTIV_CRD_VALIDATE_STATE")
	if validateState != "internal" && validateState != "NB" && validateState != "SB" {
		if validateState != "" {
			p.Log.WithField("validateState", validateState).Warn(
				"Unrecognized value set for CONTIV_CRD_VALIDATE_STATE, defaulting to \"SB\"")
		}
		validateState = "SB"
	}

	telemetryInformer := p.sharedFactory.Telemetry().V1().TelemetryReports().Informer()
	telemetryLister := p.sharedFactory.Telemetry().V1().TelemetryReports().Lister()
	p.telemetryController = &controller.CrdController{
		Deps: controller.Deps{
			Log:          p.Log.NewLogger("telemetryController"),
			APIClient:    p.apiclientset,
			Informer:     telemetryInformer,
			EventHandler: &telemetry.Handler{},
		},
		Spec: controller.CrdSpec{
			TypeName: reflect.TypeOf(telemetryv1.TelemetryReport{}).Name(),
			Group:    telemetryv1.CRDGroup,
			Version:  telemetryv1.CRDGroupVersion,
			Plural:   telemetryv1.CRDContivTelemetryReportPlural,
		},
	}

	p.cache = cache.NewTelemetryCache(p.Log, collectionInterval, validateState, p.verbose)
	p.cache.Init()

	validatorLog := p.Log.NewLogger("telemetryProcessor")
	l2ValidatorLog := p.Log.NewLogger("telemetryProcessorL2")
	l3ValidatorLog := p.Log.NewLogger("telemetryProcessorL3")

	p.processor = &validator.Validator{
		Deps: validator.Deps{
			Log:   validatorLog,
			L2Log: l2ValidatorLog,
			L3Log: l3ValidatorLog,
		},
		VppCache: p.cache.VppCache,
		K8sCache: p.cache.K8sCache,
		Report:   p.cache.Report,
	}

	p.cache.Processor = p.processor

	controllerReport := &telemetry.CRDReport{
		Deps: telemetry.Deps{
			Log:                p.Log.NewLogger("telemetryReporter"),
			CollectionInterval: collectionInterval,
			CrdClient:          p.crdClient,
			Lister:             telemetryLister,
			VppCache:           p.cache.VppCache,
			K8sCache:           p.cache.K8sCache,
			Report:             p.cache.Report,
		},
	}
	p.cache.ControllerReport = controllerReport

	if p.verbose {
		p.telemetryController.Log.SetLevel(logging.DebugLevel)
		p.cache.Log.SetLevel(logging.DebugLevel)

		validatorLog.SetLevel(logging.DebugLevel)
		l2ValidatorLog.SetLevel(logging.DebugLevel)
		l3ValidatorLog.SetLevel(logging.DebugLevel)
	} else {
		p.telemetryController.Log.SetLevel(logging.ErrorLevel)
		p.cache.Log.SetLevel(logging.ErrorLevel)

		validatorLog.SetLevel(logging.ErrorLevel)
		l2ValidatorLog.SetLevel(logging.ErrorLevel)
		l3ValidatorLog.SetLevel(logging.ErrorLevel)
	}
	return p.telemetryController.Init()
}

// AfterInit registers to the ResyncOrchestrator.
func (p *Plugin) AfterInit() error {
	if p.Resync != nil {
		reg := p.Resync.Register(string(p.PluginName))
		go p.handleResync(reg.StatusChan())
	}
	return nil
}

// onEtcdConnect is called when the connection with etcd is made.
// CRD controllers are initialized and started.
func (p *Plugin) onEtcdConnect() error {
	// Init and run the controllers
	err := p.initializeCRDs()
	if err != nil {
		return err
	}
	go func() {
		p.Log.Info("Start campaign in crd leader election")
		_, err := p.Etcd.CampaignInElection(p.ctx, electionPrefix)
		if err != nil {
			p.Log.Error(err)
			return
		}
		p.Log.Info("The instance was elected as leader.")
		go p.telemetryController.Run(p.ctx.Done())
		go p.nodeConfigController.Run(p.ctx.Done())
		go p.customNetworkController.Run(p.ctx.Done())
		go p.externalInterfaceController.Run(p.ctx.Done())
		go p.serviceFunctionChainController.Run(p.ctx.Done())
		go p.customConfigController.Run(p.ctx.Done())
	}()
	return nil
}

func (p *Plugin) subscribeWatcher() (err error) {
	p.watchConfigReg, err = p.Watcher.
		Watch("ContivTelemetry Resources", p.changeChan, p.resyncChan,
			podmodel.KeyPrefix(), nodemodel.KeyPrefix(), vppnodemodel.KeyPrefix)
	return err
}

func (p *Plugin) watchEvents() {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case resyncConfigEv := <-p.resyncChan:
			p.resyncLock.Lock()
			p.resyncCounter++
			p.pendingResync = resyncConfigEv
			p.pendingChanges = []datasync.ChangeEvent{}
			resyncConfigEv.Done(nil)
			p.Log.WithField("config", resyncConfigEv).Info("Delaying RESYNC config")
			p.resyncLock.Unlock()

		case dataChngEv := <-p.changeChan:
			p.resyncLock.Lock()
			if p.resyncCounter == 0 {
				p.Log.WithField("config", dataChngEv).
					Info("Ignoring data-change received before the first RESYNC")
				p.resyncLock.Unlock()
				break
			}
			if p.pendingResync != nil {
				p.pendingChanges = append(p.pendingChanges, dataChngEv)
				dataChngEv.Done(nil)
				p.Log.WithField("config", dataChngEv).Info("Delaying data-change")
			} else {
				err := p.cache.Update(dataChngEv)
				dataChngEv.Done(err)
			}
			p.resyncLock.Unlock()

		case <-p.ctx.Done():
			p.Log.Debug("Stop watching events")
			return
		}
	}
}

func (p *Plugin) handleResync(resyncChan <-chan resync.StatusEvent) {

	for {
		select {
		case ev := <-resyncChan:
			var err error
			status := ev.ResyncStatus()
			if status == resync.Started {
				p.resyncLock.Lock()
				if p.pendingResync != nil {
					p.Log.WithField("config", p.pendingResync).Info("Applying delayed RESYNC config")
					err = p.cache.Resync(p.pendingResync)
					if err != nil {
						p.Log.Error(err)
						// TODO: fatal error: we need to either restart ourselves or keep resyncing until we succeed
					}
					for i := 0; err == nil && i < len(p.pendingChanges); i++ {
						dataChngEv := p.pendingChanges[i]
						p.Log.WithField("config", dataChngEv).Info("Applying delayed data-change")
						err = p.cache.Update(dataChngEv)
						if err != nil {
							p.Log.Error(err)
							// TODO: fatal error: we need to either restart ourselves or keep resyncing until we succeed
						}
					}
					p.pendingResync = nil
					p.pendingChanges = []datasync.ChangeEvent{}
				}
				p.resyncLock.Unlock()
			}
			ev.Ack()
		case <-p.ctx.Done():
			return
		}
	}
}

// Close stops the processor and watching.
func (p *Plugin) Close() error {
	p.cancel()
	p.wg.Wait()
	safeclose.CloseAll(p.watchConfigReg, p.resyncChan, p.changeChan)
	return nil
}
