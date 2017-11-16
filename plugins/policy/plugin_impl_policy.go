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
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/govppmux"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/contiv/vpp/plugins/policy/processor"
	"github.com/contiv/vpp/plugins/policy/renderer/acl"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in policies, pods and namespaces and applies rules into extendable
// set of network stacks.
type Plugin struct {
	Deps

	resyncChan chan datasync.ResyncEvent
	changeChan chan datasync.ChangeEvent

	watchConfigReg datasync.WatchRegistration

	cancel context.CancelFunc
	wg     sync.WaitGroup

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

	goVppCh, err := p.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}
	p.vppTCPRenderer = &vpptcp.Renderer{
		Deps: vpptcp.Deps{
			Log:        p.Log.NewLogger("-vppTcpRenderer"),
			LogFactory: p.Log,
			Contiv:     p.Contiv,
			GoVPPChan:  goVppCh,
		},
	}
	p.vppTCPRenderer.Log.SetLevel(logging.DebugLevel)

	// Initialize layers.
	p.policyCache.Init()
	p.processor.Init()
	p.configurator.Init(false) // Do not render in parallel while we do lot of debugging.
	p.aclRenderer.Init()
	p.vppTCPRenderer.Init()

	// Register renderers.
	p.configurator.RegisterRenderer(p.aclRenderer)
	p.configurator.RegisterRenderer(p.vppTCPRenderer)

	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())

	go p.watchEvents(ctx)
	err = p.subscribeWatcher()
	if err != nil {
		return err
	}

	return nil
}

func (p *Plugin) subscribeWatcher() (err error) {
	p.watchConfigReg, err = p.Watcher.
		Watch("K8s resources", p.changeChan, p.resyncChan, namespace.KeyPrefix())
	return err
}

func (p *Plugin) watchEvents(ctx context.Context) {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case resyncConfigEv := <-p.resyncChan:
			//err := p.policyCache.Resync(resyncConfigEv)
			//resyncConfigEv.Done(err)
			p.Log.Info(resyncConfigEv)
		case dataChngEv := <-p.changeChan:
			err := p.policyCache.Update(dataChngEv)
			dataChngEv.Done(err)

		case <-ctx.Done():
			p.Log.Debug("Stop watching events")
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
