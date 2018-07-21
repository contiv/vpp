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
	"syscall"

	"github.com/contiv/vpp/plugins/contiv"
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
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	k8sCache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"

	"os"
	"os/signal"

	"github.com/contiv/vpp/plugins/crd/handler"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	crdResourceInformer "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/contivtelemetry/v1"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in policies, pods and namespaces and applies rules into extendable
// set of network stacks.
type Plugin struct {
	Deps

	k8sClientConfig *rest.Config
	k8sClient       *kubernetes.Clientset

	crdClient *crdClientSet.Clientset

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
	// processor  *processor.ContivTelemetryProcessor
}

// Deps defines dependencies of policy plugin.
type Deps struct {
	local.PluginInfraDeps
	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig

	Contiv  contiv.Plugin
	Resync  resync.Subscriber
	Watcher datasync.KeyValProtoWatcher /* prefixed for KSR-published K8s state data */
}

// Init initializes policy layers and caches and starts watching contiv-etcd for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	kubeconfig := p.KubeConfig.GetConfigName()
	p.Log.WithField("kubeconfig", kubeconfig).Info("Loading kubernetes client config")
	p.k8sClientConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	p.k8sClient, err = kubernetes.NewForConfig(p.k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	p.crdClient, err = crdClientSet.NewForConfig(p.k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build crd Client: %s", err)
	}

	// Create a custom resource informer (generated from the code generator)
	// Pass the custom resource client, while looking all namespaces for listing and watching.
	informer := crdResourceInformer.NewContivTelemetryInformer(
		p.crdClient,
		meta_v1.NamespaceAll,
		0,
		k8sCache.Indexers{},
	)

	// Create a new queue in that when the informer gets a resource from listing or watching,
	// adding the identifying key to the queue for the handler
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Add event handlers to handle the three types of events for resources (add, update, delete)
	informer.AddEventHandler(k8sCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// Converting the resource object into a key
			key, err := k8sCache.MetaNamespaceKeyFunc(obj)
			p.Log.Infof("Add ContivTelemetry resource: %s", key)
			if err == nil {
				// Adding the key to the queue for the handler to get
				queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := k8sCache.MetaNamespaceKeyFunc(newObj)
			p.Log.Infof("Update ContivTelemetry resource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := k8sCache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			p.Log.Infof("Delete ContivTelemetry resource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	// Init Controller object to handle logging, connections, informing (listing and watching),
	// the queue, and the handler
	p.controller = &controller.ContivTelemetryController{
		Log:          p.Log,
		Clientset:    p.k8sClient,
		Queue:        queue,
		Informer:     informer,
		EventHandler: &handler.Default{},
	}

	// use a channel to synchronize the finalization for a graceful shutdown
	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go p.controller.Run(stopCh)

	// use a channel to handle OS signals to terminate and gracefully shut
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm

	// This where we initialize all layers
	//p.cache.Init()
	//p.processor.Init()

	p.ctx, p.cancel = context.WithCancel(context.Background())

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
			podmodel.KeyPrefix(), nodemodel.KeyPrefix())
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
	// block until NodeIP is set
	nodeIPWatcher := make(chan string, 1)
	p.Contiv.WatchNodeIP(nodeIPWatcher)
	nodeIP, nodeNet := p.Contiv.GetNodeIP()
	if nodeIP == nil || nodeNet == nil {
		<-nodeIPWatcher
	}

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
					for i := 0; err == nil && i < len(p.pendingChanges); i++ {
						dataChngEv := p.pendingChanges[i]
						p.Log.WithField("config", dataChngEv).Info("Applying delayed data-change")
						err = p.cache.Update(dataChngEv)
					}
					p.pendingResync = nil
					p.pendingChanges = []datasync.ChangeEvent{}
				}
				p.resyncLock.Unlock()
			}
			if err != nil {
				p.Log.Error(err)
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
