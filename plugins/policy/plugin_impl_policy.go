// Copyright (c) 2017 Cisco and/or its affiliates.
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

package policy

import (
	"context"
	"sync"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/govppmux"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/contiv/vpp/plugins/policy/processor"
	"github.com/contiv/vpp/plugins/policy/renderer/acl"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
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
	pendingResync  datasync.ResyncEvent
	pendingChanges []datasync.ChangeEvent

	// Policy Plugin consists of multiple layers.
	// The plugin itself is layer 1.

	// Policy Cache: layers 1-3
	policyCache *cache.PolicyCache

	// Policy Processor: layer 2
	processor *processor.PolicyProcessor

	// Policy Configurator: layer 3
	configurator *configurator.PolicyConfigurator

	// Policy Renderers: layer 4
	//  -> ACL Renderer
	aclRenderer *acl.Renderer
	//  -> VPPTCP Renderer
	vppTCPRenderer *vpptcp.Renderer
	// New renderers should come here ...
}

// Deps defines dependencies of policy plugin.
type Deps struct {
	local.PluginInfraDeps
	Resync  resync.Subscriber
	Watcher datasync.KeyValProtoWatcher /* prefixed for KSR-published K8s state data */
	Contiv  contiv.API                  /* for GetIfName() */
	VPP     defaultplugins.API          /* for DumpACLs() */
	GoVPP   govppmux.API                /* for VPPTCP Renderer */
}

// Init initializes policy layers and caches and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	// Inject dependencies between layers.
	p.policyCache = &cache.PolicyCache{
		Deps: cache.Deps{
			Log:        p.Log.NewLogger("-policyCache"),
			PluginName: p.PluginName,
		},
	}
	p.policyCache.Log.SetLevel(logging.DebugLevel)

	p.configurator = &configurator.PolicyConfigurator{
		Deps: configurator.Deps{
			Log:   p.Log.NewLogger("-policyConfigurator"),
			Cache: p.policyCache,
		},
	}
	p.configurator.Log.SetLevel(logging.DebugLevel)

	p.processor = &processor.PolicyProcessor{
		Deps: processor.Deps{
			Log:          p.Log.NewLogger("-policyProcessor"),
			Contiv:       p.Contiv,
			Cache:        p.policyCache,
			Configurator: p.configurator,
		},
	}
	p.processor.Log.SetLevel(logging.DebugLevel)

	p.aclRenderer = &acl.Renderer{
		Deps: acl.Deps{
			Log:        p.Log.NewLogger("-aclRenderer"),
			LogFactory: p.Log,
			Contiv:     p.Contiv,
			VPP:        p.VPP,
			ACLTxnFactory: func() linux.DataChangeDSL {
				return localclient.DataChangeRequest(p.PluginName)
			},
		},
	}
	p.aclRenderer.Log.SetLevel(logging.DebugLevel)

	const goVPPChanBufSize = 1 << 12
	goVppCh, err := p.GoVPP.NewAPIChannelBuffered(goVPPChanBufSize, goVPPChanBufSize)
	if err != nil {
		return err
	}
	p.vppTCPRenderer = &vpptcp.Renderer{
		Deps: vpptcp.Deps{
			Log:              p.Log.NewLogger("-vppTcpRenderer"),
			LogFactory:       p.Log,
			Contiv:           p.Contiv,
			GoVPPChan:        goVppCh,
			GoVPPChanBufSize: goVPPChanBufSize,
		},
	}
	p.vppTCPRenderer.Log.SetLevel(logging.DebugLevel)

	// Initialize layers.
	p.policyCache.Init()
	p.processor.Init()
	p.configurator.Init(false) // Do not render in parallel while we do lot of debugging.
	p.aclRenderer.Init()
	if !p.Contiv.IsTCPstackDisabled() {
		p.vppTCPRenderer.Init()
	}

	// Register renderers.
	p.configurator.RegisterRenderer(p.aclRenderer)
	if !p.Contiv.IsTCPstackDisabled() {
		p.configurator.RegisterRenderer(p.vppTCPRenderer)
	}

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
		Watch("K8s policies", p.changeChan, p.resyncChan,
			nsmodel.KeyPrefix(), podmodel.KeyPrefix(), policymodel.KeyPrefix())
	return err
}

func (p *Plugin) watchEvents() {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case resyncConfigEv := <-p.resyncChan:
			p.resyncLock.Lock()
			p.pendingResync = resyncConfigEv
			p.pendingChanges = []datasync.ChangeEvent{}
			resyncConfigEv.Done(nil)
			p.Log.WithField("config", resyncConfigEv).Info("Delaying RESYNC config")
			p.resyncLock.Unlock()

		case dataChngEv := <-p.changeChan:
			p.resyncLock.Lock()
			if p.pendingResync != nil {
				p.pendingChanges = append(p.pendingChanges, dataChngEv)
				dataChngEv.Done(nil)
				p.Log.WithField("config", dataChngEv).Info("Delaying data-change")
			} else {
				err := p.policyCache.Update(dataChngEv)
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
					err = p.policyCache.Resync(p.pendingResync)
					for i := 0; err == nil && i < len(p.pendingChanges); i++ {
						dataChngEv := p.pendingChanges[i]
						p.Log.WithField("config", dataChngEv).Info("Applying delayed data-change")
						err = p.policyCache.Update(dataChngEv)
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
