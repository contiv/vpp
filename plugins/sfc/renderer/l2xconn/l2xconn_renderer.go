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

	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
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
	rndr.Log.Infof("By Adel 1 - Add SFC: %v AfterSFC", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("By Adel 2 - add SFC '%s'", sfc.Name))

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
		// get interface names of this and previous service function (work only for local SFs else return "")
		iface := rndr.getSFInterface(sf, true)
		prevIface := ""
		if prevSF != nil {
			prevIface = rndr.getSFInterface(prevSF, false)
		}

		if iface != "" && prevIface != "" {
			if rndr.checkSFNodeLocal(sf) && rndr.checkSFNodeLocal(prevSF) {
				// The two SFs are local
				//for local pods do: only cross-connect the interfaces in both directions

				configCrossCt := rndr.crossConnectIfaces(iface, prevIface)
				rndr.mergeConfiguration(config, configCrossCt)
			} else {
				if rndr.checkSFNodeLocal(sf) || rndr.checkSFNodeLocal(prevSF) { // If  one of the SFs (prevSF or SF) is local
					// If sf local create vxlan in the two direction the nodes
					// and cross-connect each SF and prev SF to these vxlans else do the same with prefSF

					// allocate custom vxlan vni for the actual SFC instance(reconized by SFC name, SFC instance number), if not always alocated else get it
					// those vxlan vnis are >=5000
					vni, err := rndr.IPAM.AllocateVNI(sfc.Name, 1) // TODO: handle chains with multiple pod instances per service function? untill now only one SFC instance is considered
					if err != nil {
						rndr.Log.Infof("Unable to allocate SFC VNI: %v", err)
						break
					}
					if rndr.checkSFNodeLocal(sf) { // sf is local
						// create vxlan and connect sf to vxlan in both directions
						// direction 1
						vxlanName, vxlanConfig := rndr.vxlanSFC(sf, prevSF, vni)
						rndr.mergeConfiguration(config, vxlanConfig)

						xconnect := rndr.connectIfaces(iface, vxlanName)
						rndr.mergeConfiguration(config, xconnect)

						// direction 2
						xconnect = rndr.connectIfaces(vxlanName, iface)
						rndr.mergeConfiguration(config, xconnect)
					} else { // prevSF is local
						// create vxlan and connect prevSF to vxlan in both directions
						vxlanName, vxlanConfig := rndr.vxlanSFC(prevSF, sf, vni)
						rndr.mergeConfiguration(config, vxlanConfig)

						//direction 1
						xconnect := rndr.connectIfaces(vxlanName, prevIface)
						rndr.mergeConfiguration(config, xconnect)
						//rndr.Log.Infof("By Adel Config3: %v", config)

						//direction 2
						xconnect = rndr.connectIfaces(prevIface, vxlanName)
						rndr.mergeConfiguration(config, xconnect)
					}
				}
			} 
		}
		prevSF = sf
	}
	return config
}

// getSFInterface returns a service function input/output interface which should be used for chaining.
func (rndr *Renderer) getSFInterface(sf *renderer.ServiceFunction, input bool) string {

	switch sf.Type {
	case renderer.Pod:
		if len(sf.Pods) == 0 {
			return ""
		}
		pod := sf.Pods[0] // TODO: handle chains with multiple pod instances per service function?
		if input {
			return pod.InputInterface
		}
		return pod.OutputInterface

	case renderer.ExternalInterface:
		// find first local interface
		for _, extIf := range sf.ExternalInterfaces {
			if extIf.Local {
				return extIf.InterfaceName
			}
		}
		// TODO: chain to a remote external interface?
		return ""
	}
	return ""
}

//*******************************************
// Functions added to manage multi-node SFCs
//*******************************************

// Return the node ID for the given SF
func (rndr *Renderer) getSFNodeID(sf *renderer.ServiceFunction) uint32 {
	switch sf.Type {
	case renderer.Pod:
		if len(sf.Pods) == 0 {
			return 0
		}
		pod := sf.Pods[0] // TODO: handle chains with multiple pod instances per service function?
		return pod.NodeID

	case renderer.ExternalInterface: // TODO : check if the returned  nodeID  is correct (the required one) for ExternalInterface
		// return nodeID of the first local interface
		for _, extIf := range sf.ExternalInterfaces {
			if extIf.Local {
				return extIf.NodeID
			}
		}
		// TODO: chain to a remote external interface?
		return 0
	}
	return 0

}

// Check weather the given sf is in the local node or not
func (rndr *Renderer) checkSFNodeLocal(sf *renderer.ServiceFunction) bool {
	if sf.Type != renderer.Pod {
		return false // TODO: to be checked if is it possible:  no render for the SFC
	}
	if len(sf.Pods) == 0 {
		return false // TODO: to be checked if is it possible:  no node for the SF????
	}
	pod := sf.Pods[0] // TODO: handle chains with multiple pod instances per service function?
	return pod.Local
}

// nameForSFCVxlanToOtherNode returns logical name to use for the SFC VXLAN interface
// connecting this node with the given other node.
func (rndr *Renderer) nameForSFCVxlanToOtherNode(otherNodeID uint32, vniSFC uint32) string {
	return fmt.Sprintf("vxlan%dSFC%d", otherNodeID, vniSFC)
}

// getNodeIP calculates the (statically selected) IP address of the given node
func (rndr *Renderer) getNodeIP(nodeID uint32) (net.IP, error) {
	nodeIP, _, err := rndr.IPAM.NodeIPAddress(nodeID)
	if err != nil {
		err := fmt.Errorf("Failed to get Node IP address for node ID %v, error: %v ", nodeID, err)
		rndr.Log.Error(err)
		return nodeIP, err
	}
	return nodeIP, nil
}

// connectIfaces return the configuration that Connect the given interfaces in one direction iface1-iface2
func (rndr *Renderer) connectIfaces(iface1 string, iface2 string) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)
	xconn := &vpp_l2.XConnectPair{
		ReceiveInterface:  iface1,
		TransmitInterface: iface2,
	}
	key := vpp_l2.XConnectKey(iface1)
	config[key] = xconn
	return config
}

//crossConnectIfaces return the config for  cross-connecting the given interfaces in both directions
func (rndr *Renderer) crossConnectIfaces(iface1 string, iface2 string) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)
	//err = nil // TODOD: check weather there cases for errors
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

// vxlanSFC return SFC vxlan from sf1 to sf2
func (rndr *Renderer) vxlanSFC(sf1 *renderer.ServiceFunction, sf2 *renderer.ServiceFunction, vni uint32) (nameVxLan string, config controller.KeyValuePairs) {
	// first vxlan from node sf1 to node sf2
	config = make(controller.KeyValuePairs)
	srcAdr, errSrcAdr := rndr.getNodeIP(rndr.getSFNodeID(sf1))
	dstAdr, errDestAdr := rndr.getNodeIP(rndr.getSFNodeID(sf2))
	if errSrcAdr == nil && errDestAdr == nil {
		vxlan := &vpp_interfaces.Interface{
			Name: rndr.nameForSFCVxlanToOtherNode(rndr.getSFNodeID(sf2), vni),
			Type: vpp_interfaces.Interface_VXLAN_TUNNEL,
			Link: &vpp_interfaces.Interface_Vxlan{
				Vxlan: &vpp_interfaces.VxlanLink{
					SrcAddress: srcAdr.String(),
					DstAddress: dstAdr.String(),
					Vni:        vni,
				},
			},
			Enabled: true,
			Vrf:     rndr.ContivConf.GetRoutingConfig().MainVRFID,
		}
		key := vpp_interfaces.InterfaceKey(vxlan.Name)
		config[key] = vxlan
		nameVxLan = vxlan.Name
	}
	return nameVxLan, config
}

// merge the configurations
func (rndr *Renderer) mergeConfiguration(destConf, sourceConf controller.KeyValuePairs) {
	for k, v := range sourceConf {
		destConf[k] = v
	}
}
