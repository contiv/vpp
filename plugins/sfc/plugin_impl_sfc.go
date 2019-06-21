// Copyright (c) 2019 Cisco and/or its affiliates.
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
	sfcmodel "github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/processor"
	"github.com/contiv/vpp/plugins/sfc/renderer/l2xconn"
)

// Plugin watches configuration of K8s resources (as reflected by KSR+CRD into ETCD)
// for changes in SFCs and pods and updates the chaining configuration in the VPP accordingly.
type Plugin struct {
	Deps

	config *config.Config

	// ongoing transaction
	resyncTxn controller.ResyncOperations
	updateTxn controller.UpdateOperations
	changes   []string

	// layers of the SFC plugin
	processor       *processor.SFCProcessor
	l2xconnRenderer *l2xconn.Renderer
}

// Deps defines dependencies of the SFC plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel    servicelabel.ReaderAPI
	ContivConf      contivconf.API
	IPAM            ipam.API
	IPNet           ipnet.API
	NodeSync        nodesync.API
	PodManager      podmanager.API
	GoVPP           govppmux.API
	Stats           statscollector.API
	ConfigRetriever controller.ConfigRetriever
}

// Init initializes the SFC plugin and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	var err error

	// load configuration
	p.config = config.DefaultConfig()
	_, err = p.Cfg.LoadValue(p.config)
	if err != nil {
		return err
	}
	p.Log.Infof("SFC plugin configuration: %+v", *p.config)

	p.processor = &processor.SFCProcessor{
		Deps: processor.Deps{
			Log:          p.Log.NewLogger("-sfcProcessor"),
			ServiceLabel: p.ServiceLabel,
			ContivConf:   p.ContivConf,
			IPAM:         p.IPAM,
			IPNet:        p.IPNet,
			NodeSync:     p.NodeSync,
			PodManager:   p.PodManager,
		},
	}
	err = p.processor.Init()
	if err != nil {
		return err
	}

	// TODO: in case of multiple renederers, use the renderer based on the config
	p.l2xconnRenderer = &l2xconn.Renderer{
		Deps: l2xconn.Deps{
			Log:        p.Log.NewLogger("-sfcL2xconnRenderer"),
			Config:     p.config,
			ContivConf: p.ContivConf,
			IPAM:       p.IPAM,
			IPNet:      p.IPNet,
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
	// init & register the renderer
	p.l2xconnRenderer.Init(false)
	p.processor.RegisterRenderer(p.l2xconnRenderer)

	return nil
}

// AfterInit registers to the ResyncOrchestrator. The registration is done in this phase
// in order to ensure that the resync for this plugin is triggered only after
// resync of the Contiv plugin has finished.
func (p *Plugin) AfterInit() error {
	p.processor.AfterInit()

	// renderers that need after init
	p.l2xconnRenderer.AfterInit()

	return nil
}

// HandlesEvent selects:
//  - any resync event
//  - KubeStateChange for SFCs and pods
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case sfcmodel.Keyword:
			return true
		case podmodel.PodKeyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	// unhandled event
	return false
}

// Resync is called by Controller to handle event that requires full re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify run-time resync.
func (p *Plugin) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {

	p.resyncTxn = txn
	p.updateTxn = nil
	return p.processor.Resync(kubeStateData)
}

// Update is called for:
//  - KubeStateChange for or SFCs and pods
func (p *Plugin) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	p.resyncTxn = nil
	p.updateTxn = txn
	p.changes = []string{}
	err = p.processor.Update(event)
	changeDescription = strings.Join(p.changes, ", ")
	return changeDescription, err
}

// Revert is NOOP.
func (p *Plugin) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP.
func (p *Plugin) Close() error {
	return nil
}
