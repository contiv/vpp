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

package sfc

import (
	"strings"

	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/plugins/govppmux"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/processor"
	"github.com/contiv/vpp/plugins/service/renderer/ipv6route"
	"github.com/contiv/vpp/plugins/service/renderer/nat44"
	"github.com/contiv/vpp/plugins/service/renderer/srv6"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in services, endpoints and pods and updates the NAT configuration
// in the VPP accordingly.
type Plugin struct {
	Deps

	config *config.Config

	// ongoing transaction
	resyncTxn controller.ResyncOperations
	updateTxn controller.UpdateOperations
	changes   []string

	// layers of the service plugin
	processor         *processor.ServiceProcessor
	nat44Renderer     *nat44.Renderer
	ipv6RouteRenderer *ipv6route.Renderer
	srv6Renderer      *srv6.Renderer
}

// Deps defines dependencies of the service plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel    servicelabel.ReaderAPI
	ContivConf      contivconf.API
	IPAM            ipam.API
	IPNet           ipnet.API          /* to get the Node IP and all interface names */
	NodeSync        nodesync.API       /* to get the list of all node IPs for nodePort services */
	PodManager      podmanager.API     /* to get the list or running pods which determines frontend interfaces */
	GoVPP           govppmux.API       /* used for direct NAT binary API calls */
	Stats           statscollector.API /* used for exporting the statistics */
	ConfigRetriever controller.ConfigRetriever
}

// Init initializes the service plugin and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	var err error

	// load configuration
	p.config = config.DefaultConfig()
	_, err = p.Cfg.LoadValue(p.config)
	if err != nil {
		return err
	}
	p.Log.Infof("Service plugin configuration: %+v", *p.config)

	const goVPPChanBufSize = 1 << 12
	goVppCh, err := p.GoVPP.NewAPIChannelBuffered(goVPPChanBufSize, goVPPChanBufSize)
	if err != nil {
		return err
	}

	p.processor = &processor.ServiceProcessor{
		Deps: processor.Deps{
			Log:          p.Log.NewLogger("-serviceProcessor"),
			ServiceLabel: p.ServiceLabel,
			ContivConf:   p.ContivConf,
			IPAM:         p.IPAM,
			IPNet:        p.IPNet,
			NodeSync:     p.NodeSync,
			PodManager:   p.PodManager,
		},
	}
	p.processor.Init()

	if !p.ContivConf.GetIPAMConfig().UseIPv6 {
		// use NAT44 renderer
		p.nat44Renderer = &nat44.Renderer{
			Deps: nat44.Deps{
				Log:        p.Log.NewLogger("-nat44Renderer"),
				Config:     p.config,
				ContivConf: p.ContivConf,
				IPAM:       p.IPAM,
				IPNet:      p.IPNet,
				GoVPPChan:  goVppCh,
				UpdateTxnFactory: func(change string) controller.UpdateOperations {
					p.changes = append(p.changes, change)
					return p.updateTxn
				},
				ResyncTxnFactory: func() controller.ResyncOperations {
					return p.resyncTxn
				},
				Stats: p.Stats,
			},
		}

		p.nat44Renderer.Init(false)
		// Register renderer.
		p.processor.RegisterRenderer(p.nat44Renderer)
	} else {
		if p.ContivConf.GetRoutingConfig().UseSRv6Interconnect { // use SRv6 renderer
			p.srv6Renderer = &srv6.Renderer{
				Deps: srv6.Deps{
					Log:             p.Log.NewLogger("-SRv6Renderer"),
					ContivConf:      p.ContivConf,
					NodeSync:        p.NodeSync,
					PodManager:      p.PodManager,
					IPAM:            p.IPAM,
					IPNet:           p.IPNet,
					ConfigRetriever: p.ConfigRetriever,
					UpdateTxnFactory: func(change string) controller.UpdateOperations {
						p.changes = append(p.changes, change)
						return p.updateTxn
					},
					ResyncTxnFactory: func() controller.ResyncOperations {
						return p.resyncTxn
					},
				},
			}

			p.srv6Renderer.Init(false)
			// Register renderer.
			p.processor.RegisterRenderer(p.srv6Renderer)
		} else { // use IPv6 route renderer
			p.ipv6RouteRenderer = &ipv6route.Renderer{
				Deps: ipv6route.Deps{
					Log:             p.Log.NewLogger("-IPv6RouteRenderer"),
					Config:          p.config,
					ContivConf:      p.ContivConf,
					NodeSync:        p.NodeSync,
					PodManager:      p.PodManager,
					IPAM:            p.IPAM,
					IPNet:           p.IPNet,
					ConfigRetriever: p.ConfigRetriever,
					UpdateTxnFactory: func(change string) controller.UpdateOperations {
						p.changes = append(p.changes, change)
						return p.updateTxn
					},
					ResyncTxnFactory: func() controller.ResyncOperations {
						return p.resyncTxn
					},
				},
			}

			p.ipv6RouteRenderer.Init(false)
			// Register renderer.
			p.processor.RegisterRenderer(p.ipv6RouteRenderer)
		}
	}

	return nil
}

// AfterInit registers to the ResyncOrchestrator. The registration is done in this phase
// in order to ensure that the resync for this plugin is triggered only after
// resync of the Contiv plugin has finished.
func (p *Plugin) AfterInit() error {
	p.processor.AfterInit()

	if p.nat44Renderer != nil {
		p.nat44Renderer.AfterInit()
	}
	return nil
}

// HandlesEvent selects:
//  - any resync event
//  - KubeStateChange for service-related data
//  - AddPod & DeletePod
//  - NodeUpdate event
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case epmodel.EndpointsKeyword:
			return true
		case svcmodel.ServiceKeyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	if _, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return true
	}
	if _, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return true
	}
	if _, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return true
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
	return p.processor.Resync(kubeStateData)
}

// Update is called for:
//  - KubeStateChange for service-related data
//  - AddPod & DeletePod
//  - NodeUpdate event
func (p *Plugin) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	p.resyncTxn = nil
	p.updateTxn = txn
	p.changes = []string{}
	err = p.processor.Update(event)
	changeDescription = strings.Join(p.changes, ", ")
	return changeDescription, err
}

// Revert is called for failed AddPod event.
func (p *Plugin) Revert(event controller.Event) error {
	return p.processor.Revert(event)
}

// Close is NOOP.
func (p *Plugin) Close() error {
	return nil
}
