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

package crd

import (
	"context"
	"fmt"
	"sync"

	"github.com/contiv/vpp/plugins/crd/cache"
	"github.com/contiv/vpp/plugins/crd/controller"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"

	"k8s.io/client-go/kubernetes"

	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	"k8s.io/client-go/tools/clientcmd"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in policies, pods and namespaces and applies rules into extendable
// set of network stacks.
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

	controller *controller.ContivTelemetryController
	cache      *cache.ContivTelemetryCache
	processor  cache.Processor
}

// Deps defines dependencies of policy plugin.
type Deps struct {
	local.PluginInfraDeps
	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig

	Resync  resync.Subscriber
	Watcher datasync.KeyValProtoWatcher /* prefixed for KSR-published K8s state data */
}

// Init initializes policy layers and caches and starts watching contiv-etcd for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	p.ctx, p.cancel = context.WithCancel(context.Background())

	kubeconfig := p.KubeConfig.GetConfigName()
	p.Log.WithField("kubeconfig", kubeconfig).Info("Loading kubernetes client config")
	k8sClientConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	k8sClient, err := kubernetes.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	crdClient, err := crdClientSet.NewForConfig(k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build crd Client: %s", err)
	}

	p.controller = &controller.ContivTelemetryController{
		Deps: controller.Deps{
			Log: p.Log.NewLogger("-crdController"),
		},
		K8sClient: k8sClient,
		CrdClient: crdClient,
	}
	p.controller.Log.SetLevel(logging.DebugLevel)

	// Init and run the controller
	p.controller.Init()
	go p.controller.Run(p.ctx.Done())

	// This where we initialize all layers
	p.cache = &cache.ContivTelemetryCache{
		Deps: cache.Deps{
			Log: p.Log.NewLogger("-telemetryCache"),
		},
		Synced:   false,
		VppCache: cache.NewVppDataStore(),
		K8sCache: cache.NewK8sDataStore(),
		Report: &cache.Report{
			Log:  p.Log.NewLogger("-report"),
			Data: make(map[string][]string),
		},
	}
	p.cache.Log.SetLevel(logging.DebugLevel)
	p.cache.Init()

	p.processor = &cache.Validator{
		Deps: cache.Deps{
			Log: p.Log.NewLogger("-telemetryProcessor"),
		},
		VppCache: p.cache.VppCache,
		K8sCache: p.cache.K8sCache,
		Report:   p.cache.Report,
	}
	// p.processor.Init()
	p.cache.Processor = p.processor

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
	return nil
}

func (p *Plugin) subscribeWatcher() (err error) {
	p.watchConfigReg, err = p.Watcher.
		Watch("ContivTelemetry Resources", p.changeChan, p.resyncChan,
			podmodel.KeyPrefix(), nodemodel.KeyPrefix(), nodeinfomodel.AllocatedIDsKeyPrefix)
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

func (p *Plugin) handleResync(resyncChan chan resync.StatusEvent) {

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
