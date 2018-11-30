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
	"github.com/ligato/cn-infra/infra"

	"github.com/contiv/vpp/plugins/contiv"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/contiv/vpp/plugins/policy/processor"
	"github.com/contiv/vpp/plugins/policy/renderer/acl"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in policies, pods and namespaces and applies rules into extendable
// set of network stacks.
type Plugin struct {
	Deps

	// ongoing transaction
	resyncTxn  controller.ResyncOperations
	updateTxn  controller.UpdateOperations
	withChange bool

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
	// New renderers should come here ...
}

// Deps defines dependencies of policy plugin.
type Deps struct {
	infra.PluginDeps
	Contiv contiv.API /* for GetIfName() */

	// Note: L4 was removed from Contiv but may be re-added in the future
	// GoVPP   govppmux.API  /* for VPPTCP Renderer */
}

// Init initializes policy layers and caches and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	// Inject dependencies between layers.
	p.policyCache = &cache.PolicyCache{
		Deps: cache.Deps{
			Log: p.Log.NewLogger("-policyCache"),
		},
	}

	p.configurator = &configurator.PolicyConfigurator{
		Deps: configurator.Deps{
			Log:    p.Log.NewLogger("-policyConfigurator"),
			Cache:  p.policyCache,
			Contiv: p.Contiv,
		},
	}

	p.processor = &processor.PolicyProcessor{
		Deps: processor.Deps{
			Log:          p.Log.NewLogger("-policyProcessor"),
			Contiv:       p.Contiv,
			Cache:        p.policyCache,
			Configurator: p.configurator,
		},
	}

	p.aclRenderer = &acl.Renderer{
		Deps: acl.Deps{
			Log:        p.Log.NewLogger("-aclRenderer"),
			LogFactory: p.Log,
			Contiv:     p.Contiv,
			UpdateTxnFactory: func() controller.UpdateOperations {
				p.withChange = true
				return p.updateTxn
			},
			ResyncTxnFactory: func() controller.ResyncOperations {
				return p.resyncTxn
			},
		},
	}

	/* Note: L4 was removed from Contiv but may be re-added in the future
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
	*/

	// Initialize layers.
	p.policyCache.Init()
	p.processor.Init()
	p.configurator.Init(false) // Do not render in parallel while we do lot of debugging.
	p.aclRenderer.Init()

	// Register renderers.
	p.configurator.RegisterRenderer(p.aclRenderer)
	return nil
}

// HandlesEvent selects DBResync and KubeStateChange for specific resources to handle.
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case namespace.NamespaceKeyword:
			return true
		case pod.PodKeyword:
			return true
		case policy.PolicyKeyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}

	// unhandled event
	return false
}

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (p *Plugin) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {

	p.resyncTxn = txn
	p.updateTxn = nil
	return p.policyCache.Resync(kubeStateData)
}

// Update is called for KubeStateChange.
func (p *Plugin) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	p.resyncTxn = nil
	p.updateTxn = txn
	p.withChange = false
	kubeStateChange := event.(*controller.KubeStateChange)
	err = p.policyCache.Update(kubeStateChange)
	if p.withChange {
		changeDescription = "refresh policies"
	}
	return changeDescription, err
}

// Revert does nothing here - plugin handles only BestEffort events.
func (p *Plugin) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP.
func (p *Plugin) Close() error {
	return nil
}
