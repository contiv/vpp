/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package l2xconn

import (
	"fmt"
	"net"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"

	vpp_l2 "github.com/ligato/vpp-agent/api/models/vpp/l2"
)

// Renderer implements L2 cross-connect -based rendering of SFC in Contiv-VPP.
type Renderer struct {
	Deps

	/* dynamic SNAT */
	defaultIfName string
	defaultIfIP   net.IP
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit does nothing for this renderer.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddChain is called for a newly added service function chain.
func (rndr *Renderer) AddChain(sfc *renderer.ContivSFC) error {
	rndr.Log.Infof("Add SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add SFC '%s'", sfc.Name))

	config := rndr.renderChain(sfc)
	controller.PutAll(txn, config)

	return nil
}

// UpdateChain informs renderer about a change in the configuration or in the state of a service function chain.
func (rndr *Renderer) UpdateChain(oldSFC, newSFC *renderer.ContivSFC) error {
	rndr.Log.Infof("Update SFC: %v", newSFC)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update SFC '%s'", newSFC.Name))

	oldConfig := rndr.renderChain(oldSFC)
	newConfig := rndr.renderChain(newSFC)

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

	return nil
}

// DeleteChain is called for every removed service function chain.
func (rndr *Renderer) DeleteChain(sfc *renderer.ContivSFC) error {

	rndr.Log.Infof("Delete SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete SFC chain '%s'", sfc.Name))

	config := rndr.renderChain(sfc)
	controller.DeleteAll(txn, config)

	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// resync SFC configuration
	for _, sfc := range resyncEv.Chains {
		config := rndr.renderChain(sfc)
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)
	var prevSF *renderer.ServiceFunction

	for _, sf := range sfc.Chain {
		// get interface names of this and previous service function
		iface := rndr.getSFInterface(sf, true)
		prevIface := ""
		if prevSF != nil {
			prevIface = rndr.getSFInterface(prevSF, false)
		}

		// TODO: this works only for local pods, inter-node chains are not supported yet (will be skipped)
		if iface != "" && prevIface != "" {
			// cross-connect the interfaces in both directions
			xconn := &vpp_l2.XConnectPair{
				ReceiveInterface:  prevIface,
				TransmitInterface: iface,
			}
			key := vpp_l2.XConnectKey(prevIface)
			config[key] = xconn

			xconn = &vpp_l2.XConnectPair{
				ReceiveInterface:  iface,
				TransmitInterface: prevIface,
			}
			key = vpp_l2.XConnectKey(iface)
			config[key] = xconn
		}
		prevSF = sf
	}

	return config
}

func (rndr *Renderer) getSFInterface(sf *renderer.ServiceFunction, input bool) string {
	if sf.Type != renderer.Pod {
		return "" // TODO: implement external interfaces as well
	}
	if len(sf.Pods) == 0 {
		return ""
	}
	pod := sf.Pods[0] // TODO: handle chains with multiple pod instances per service function?

	podInterface := ""
	if input {
		podInterface = pod.InputInterface
	} else {
		podInterface = pod.OutputInterface
	}

	vppIfName, exists := rndr.IPNet.GetPodCustomIfName(pod.ID.Namespace, pod.ID.Name, podInterface)
	if !exists {
		return ""
	}
	return vppIfName
}
