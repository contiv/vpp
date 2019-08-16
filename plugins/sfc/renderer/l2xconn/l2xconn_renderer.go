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

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/api/models/vpp/l2"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
)

// Renderer implements L2 cross-connect -based rendering of SFC in Contiv-VPP.
type Renderer struct {
	Deps
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
func (rndr *Renderer) Init() error {
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
	for sfIdx, sf := range sfc.Chain {
		// get interface names of this and previous service function (works only for local SFs, else returns "")
		iface := rndr.getSFInterface(sf, true)
		prevIface := ""
		if prevSF != nil {
			prevIface = rndr.getSFInterface(prevSF, false)
		}

		if iface != "" && prevIface != "" {
			if rndr.isNodeLocalSF(sf) && rndr.isNodeLocalSF(prevSF) {
				// the two SFs (prevSF and SF) are local - cross-connect the interfaces in both directions
				xconnect := rndr.crossConnectIfaces(iface, prevIface)
				rndr.mergeConfiguration(config, xconnect)

			} else if rndr.isNodeLocalSF(sf) || rndr.isNodeLocalSF(prevSF) {
				// one of the SFs (prevSF or SF) is local and the other not - use VXLAN to interconnect between them
				// allocate a VNI for this SF interconnection - each SF may need an exclusive VNI
				vxlanName := fmt.Sprintf("sfc-%s-%d", sfc.Name, sfIdx)
				vni, err := rndr.getOrAllocateVxlanVNI(vxlanName)
				if err != nil {
					rndr.Log.Infof("Unable to allocate VXLAN VNI: %v", err)
					break
				}
				if rndr.isNodeLocalSF(sf) { // sf is local
					// create vxlan and connect sf to vxlan in both directions
					vxlanConfig := rndr.vxlanToRemoteSF(prevSF, vxlanName, vni)
					rndr.mergeConfiguration(config, vxlanConfig)

					// cross-connect between the SF interface and vxlan interface
					xconnect := rndr.crossConnectIfaces(iface, vxlanName)
					rndr.mergeConfiguration(config, xconnect)
				} else { // prevSF is local
					// create vxlan and connect prevSF to vxlan in both directions
					vxlanConfig := rndr.vxlanToRemoteSF(sf, vxlanName, vni)
					rndr.mergeConfiguration(config, vxlanConfig)

					// cross-connect between the prevSF interface and vxlan interface
					xconnect := rndr.crossConnectIfaces(prevIface, vxlanName)
					rndr.mergeConfiguration(config, xconnect)
				}
			}
		}
		prevSF = sf
	}
	return config
}

// getPreferredSFPod returns a pod of a SF that is preferred to chain with.
func (rndr *Renderer) getPreferredSFPod(sf *renderer.ServiceFunction) *renderer.PodSF {
	if len(sf.Pods) == 0 {
		return nil
	}
	// try to use a local pod if possible
	for _, pod := range sf.Pods {
		if pod.Local {
			return pod
		}
	}
	// otherwise use the first pod
	return sf.Pods[0]
}

// getPreferredSFPod returns an external interface of a SF that is preferred to chain with.
func (rndr *Renderer) getPreferredSFInterface(sf *renderer.ServiceFunction) *renderer.InterfaceSF {
	if len(sf.ExternalInterfaces) == 0 {
		return nil
	}
	// try to use a local interface if possible
	for _, iface := range sf.ExternalInterfaces {
		if iface.Local {
			return iface
		}
	}
	// otherwise use the first interface
	return sf.ExternalInterfaces[0]
}

// getSFInterface returns a service function input/output interface which should be used for chaining.
func (rndr *Renderer) getSFInterface(sf *renderer.ServiceFunction, input bool) string {
	switch sf.Type {
	case renderer.Pod:
		pod := rndr.getPreferredSFPod(sf)
		if pod == nil {
			return ""
		}
		if input {
			return pod.InputInterface
		}
		return pod.OutputInterface

	case renderer.ExternalInterface:
		iface := rndr.getPreferredSFInterface(sf)
		if iface == nil {
			return ""
		}
		return iface.InterfaceName
	}
	return ""
}

// getSFNodeID returns the node ID for the given SF.
func (rndr *Renderer) getSFNodeID(sf *renderer.ServiceFunction) uint32 {
	switch sf.Type {
	case renderer.Pod:
		pod := rndr.getPreferredSFPod(sf)
		if pod == nil {
			return 0
		}
		return pod.NodeID

	case renderer.ExternalInterface:
		iface := rndr.getPreferredSFInterface(sf)
		if iface == nil {
			return 0
		}
		return iface.NodeID
	}
	return 0
}

// isNodeLocalSF checks weather the given SF is node-local or not.
func (rndr *Renderer) isNodeLocalSF(sf *renderer.ServiceFunction) bool {
	switch sf.Type {
	case renderer.Pod:
		pod := rndr.getPreferredSFPod(sf)
		if pod == nil {
			return false
		}
		return pod.Local

	case renderer.ExternalInterface:
		iface := rndr.getPreferredSFInterface(sf)
		if iface == nil {
			return false
		}
		return iface.Local
	}
	return false
}

// crossConnectIfaces returns the config for cross-connecting the given interfaces in both directions.
func (rndr *Renderer) crossConnectIfaces(iface1 string, iface2 string) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	xconn := &vpp_l2.XConnectPair{
		ReceiveInterface:  iface1,
		TransmitInterface: iface2,
	}
	key := vpp_l2.XConnectKey(iface1)
	config[key] = xconn

	xconn = &vpp_l2.XConnectPair{
		ReceiveInterface:  iface2,
		TransmitInterface: iface1,
	}
	key = vpp_l2.XConnectKey(iface2)
	config[key] = xconn
	return config
}

// vxlanToRemoteSF returns VXLAN configuration to a remote service function.
func (rndr *Renderer) vxlanToRemoteSF(sf *renderer.ServiceFunction, vxlanName string, vni uint32) (
	config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	srcAddr, _ := rndr.IPNet.GetNodeIP()
	dstAdr, _, err := rndr.IPAM.NodeIPAddress(rndr.getSFNodeID(sf))
	if err != nil {
		return
	}
	vxlan := &vpp_interfaces.Interface{
		Name: vxlanName,
		Type: vpp_interfaces.Interface_VXLAN_TUNNEL,
		Link: &vpp_interfaces.Interface_Vxlan{
			Vxlan: &vpp_interfaces.VxlanLink{
				SrcAddress: srcAddr.String(),
				DstAddress: dstAdr.String(),
				Vni:        vni,
			},
		},
		Enabled: true,
		Vrf:     rndr.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key := vpp_interfaces.InterfaceKey(vxlan.Name)
	config[key] = vxlan
	return
}

// mergeConfiguration merges sourceConf into destConf.
func (rndr *Renderer) mergeConfiguration(destConf, sourceConf controller.KeyValuePairs) {
	for k, v := range sourceConf {
		destConf[k] = v
	}
}

// getOrAllocateVxlanVNI returns the allocated VNI number for the given VXLAN.
// Allocates a new VNI if not already allocated.
func (rndr *Renderer) getOrAllocateVxlanVNI(vxlanName string) (vni uint32, err error) {
	// return existing VNI if already allocated
	vni, found := rndr.IPAM.GetVxlanVNI(vxlanName)
	if found {
		return vni, nil
	}

	// allocate new VNI
	vni, err = rndr.IPAM.AllocateVxlanVNI(vxlanName)
	if err != nil {
		rndr.Log.Errorf("VNI allocation error: %v", err)
	}
	return vni, err
}
