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
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache"
	"github.com/contiv/vpp/plugins/crd/controller/nodeconfig"
	"github.com/contiv/vpp/plugins/crd/controller/telemetry"
	"github.com/contiv/vpp/plugins/crd/validator"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"
	"github.com/namsral/flag"
	"os"
	"strconv"
	"sync"
	"time"

	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	vppnodemodel "github.com/contiv/vpp/plugins/nodesync/vppnode"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/contiv/vpp/plugins/crd/controller/customnetwork"
	"github.com/contiv/vpp/plugins/crd/controller/servicefunctionchain"
	"github.com/contiv/vpp/plugins/crd/utils"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/rpc/rest"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
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

	telemetryController            *telemetry.Controller
	nodeConfigController           *nodeconfig.Controller
	customNetworkController        *customnetwork.Controller
	serviceFunctionChainController *servicefunctionchain.Controller
	cache                          *cache.ContivTelemetryCache
	processor                      api.ContivTelemetryProcessor
	verbose                        bool
}

// Deps defines dependencies of CRD plugin.
type Deps struct {
	infra.PluginDeps
	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig

	Resync resync.Subscriber

	HTTP rest.HTTPHandlers

	/* both Publish and Watcher are prefixed for KSR-published K8s state data */
	Watcher datasync.KeyValProtoWatcher
	Publish *kvdbsync.Plugin // KeyProtoValWriter does not define Delete
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

	crdClient, err := crdClientSet.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build crd Client: %s", err)
	}

	apiclientset, err := apiextcs.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build api Client: %s", err)
	}

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

	p.telemetryController = &telemetry.Controller{
		CollectionInterval: collectionInterval,
		Deps: telemetry.Deps{
			Log: p.Log.NewLogger("-telemetryController"),
		},
		CrdClient: crdClient,
		APIClient: apiclientset,
	}

	// This where we initialize all layers
	p.cache = cache.NewTelemetryCache(p.Log, collectionInterval, validateState, p.verbose)

	p.cache.Init()

	validatorLog := p.Log.NewLogger("-telemetryProcessor")
	l2ValidatorLog := p.Log.NewLogger("-telemetryProcessorL2")
	l3ValidatorLog := p.Log.NewLogger("-telemetryProcessorL3")

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
			Log: p.Log.NewLogger("-telemetryReporter"),
		},
		VppCache: p.cache.VppCache,
		K8sCache: p.cache.K8sCache,
		Report:   p.cache.Report,
		Ctlr:     p.telemetryController,
	}
	p.cache.ControllerReport = controllerReport

	p.nodeConfigController = &nodeconfig.Controller{
		Deps: nodeconfig.Deps{
			Log:     p.Log.NewLogger("-nodeConfigController"),
			Publish: p.Publish,
		},
		CrdClient: crdClient,
		APIClient: apiclientset,
	}

	p.customNetworkController = &customnetwork.Controller{
		Deps: customnetwork.Deps{
			Log:     p.Log.NewLogger("-customNetworkController"),
			Publish: p.Publish,
		},
		CrdClient: crdClient,
		APIClient: apiclientset,
	}

	p.serviceFunctionChainController = &servicefunctionchain.Controller{
		Deps: servicefunctionchain.Deps{
			Log:     p.Log.NewLogger("-serviceFunctionChainController"),
			Publish: p.Publish,
		},
		CrdClient: crdClient,
		APIClient: apiclientset,
	}

	// Init and run the controllers
	p.telemetryController.Init()
	p.nodeConfigController.Init()
	p.customNetworkController.Init()
	p.serviceFunctionChainController.Init()

	if p.verbose {
		p.customNetworkController.Log.SetLevel(logging.DebugLevel)
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

	go p.watchEvents()
	err = p.subscribeWatcher()
	if err != nil {
		return err
	}

	return nil
}

// AfterInit registers to the ResyncOrchestrator. The registration is done in this phase
// in order to ensure that the resync for this plugin is triggered only after
// resync of the Contiv plugin has finished.
func (p *Plugin) AfterInit() error {
	if p.Resync != nil {
		reg := p.Resync.Register(string(p.PluginName))
		go p.handleResync(reg.StatusChan())
	}
	go func() {
		if etcdPlugin, ok := p.Publish.KvPlugin.(*etcd.Plugin); ok {
			p.Log.Info("Start campaign in crd leader election")

			_, err := etcdPlugin.CampaignInElection(p.ctx, electionPrefix)
			if err != nil {
				p.Log.Error(err)
				return
			}
			p.Log.Info("The instance was elected as leader.")

		} else {
			p.Log.Warn("leader election is not supported for a kv-store different from etcd")
		}
		go p.telemetryController.Run(p.ctx.Done())
		go p.nodeConfigController.Run(p.ctx.Done())
		go p.customNetworkController.Run(p.ctx.Done())
		go p.serviceFunctionChainController.Run(p.ctx.Done())

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
