/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
 * // Other Contributors: 1. Adel Bouridah,  Abdelhafid Boussouf University - Mila - Algeria, a.bouridah@centre-univ-mila.dz
 * // 2. Nadjib Aitsaadi, Universite Paris Est Creteil, nadjib.aitsaadi@u-pec.fr
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
	"sort"
	"strings"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/pkg/errors"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/idalloc"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
)

// ServiceFunctionSelectable is holder for one k8s resource that can be used as ServiceFunction in SFC
// chain (i.e. one pod or one external interface)
type ServiceFunctionSelectable interface {
}

// Renderer implements L2 cross-connect -based rendering of SFC in Contiv-VPP.
type Renderer struct {
	Deps
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IDAlloc          idalloc.API
	IPAM             ipam.API
	IPNet            ipnet.API
	NodeSync         nodesync.API
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

	config, _ := rndr.renderChain(sfc, false)
	controller.PutAll(txn, config)

	return nil
}

// UpdateChain informs renderer about a change in the configuration or in the state of a service function chain.
func (rndr *Renderer) UpdateChain(oldSFC, newSFC *renderer.ContivSFC) error {
	rndr.Log.Infof("Update SFC: %v", newSFC)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update SFC '%s'", newSFC.Name))

	oldConfig, _ := rndr.renderChain(oldSFC, true)
	newConfig, _ := rndr.renderChain(newSFC, false)

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

	return nil
}

// DeleteChain is called for every removed service function chain.
func (rndr *Renderer) DeleteChain(sfc *renderer.ContivSFC) error {

	rndr.Log.Infof("Delete SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete SFC chain '%s'", sfc.Name))

	config, _ := rndr.renderChain(sfc, true)
	controller.DeleteAll(txn, config)

	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// resync SFC configuration
	for _, sfc := range resyncEv.Chains {
		config, _ := rndr.renderChain(sfc, false)
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC, isDelete bool) (config controller.KeyValuePairs, err error) {
	/********************************************************************************************************/
	/**** Modified Render that allow creation of multipath SFC 																					*****/
	/**** Inspired from the Old one path l2xconnect render + SRv6 Render  															*****/
	/********************************************************************************************************/

	// SFC configuration correctness checks
	config = make(controller.KeyValuePairs)
	if sfc == nil {
		return config, errors.New("can't create sfc chain configuration due to missing sfc information")
	}
	if sfc.Chain == nil || len(sfc.Chain) == 0 {
		return config, errors.New("can't create sfc chain configuration due to missing chain information")
	}
	if len(sfc.Chain) < 2 {
		return config, errors.New("can't create sfc chain configuration due to missing information " +
			"on start and end chain links (chain has less than 2 links)")
	}
	/*if len(sfc.Chain) == 2 {
		rndr.Log.Warnf("sfc chain %v doesn't have inner links, it has only start and end links", sfc.Name)
	}*/

	// compute concrete paths from resources selected for SFC chain
	paths, err := rndr.computePaths(sfc)
	if err != nil {
		return config, errors.Wrapf(err, "can't compute paths for SFC chain with name %v", sfc.Name)
	}

	// Create the needed l2xconnect, vxlan for all paths
	rndr.Log.Infof("Number of paths is %v for SFC chain with name %v", len(paths), sfc.Name)
	var prevSfSelectable ServiceFunctionSelectable
	for pathIdx, path := range paths {
		// Chain pod/externalinterface of each path - l2xconnect (crossconnect/vxlan)
		for sfIdx, sfSelectable := range path {
			rndr.Log.Infof("path size %v for path %v", len(path), sfIdx)
			// get interface names of this and previous service function (works only for local SFs, else returns "")
			iface := rndr.getSfSelectableInterface(sfSelectable, true)
			prevIface := ""
			if prevSfSelectable != nil {
				prevIface = rndr.getSfSelectableInterface(prevSfSelectable, false)
			}
			if iface != "" && prevIface != "" {
				if isLocal(sfSelectable) && isLocal(prevSfSelectable) {

					rndr.Log.Infof("The path number %v for SFC chain with name %v crooss-connect pod %v with pod %v", sfIdx, sfc.Name, sfIdentifier(prevSfSelectable), sfIdentifier(sfSelectable))

					xconnect := rndr.crossConnectIfaces(prevIface, iface, sfc.Unidirectional)
					rndr.mergeConfiguration(config, xconnect)
				} else if isLocal(sfSelectable) || isLocal(prevSfSelectable) { //
					// one of the SFs (prevSfSelectable or SFSelectable) is local and the other not - use VXLAN to interconnect between them
					// allocate a VNI for this SF interconnection - each SF may need an exclusive VNI
					vxlanName := fmt.Sprintf("sfc-%s-%d-%d", sfc.Name, sfIdx, pathIdx)
					vni, err := rndr.IPNet.GetOrAllocateVxlanVNI(vxlanName)
					if isDelete {
						rndr.IPNet.ReleaseVxlanVNI(vxlanName)
					}
					if err != nil {
						rndr.Log.Infof("Unable to allocate VXLAN VNI: %v", err)
						break
					}
					rndr.Log.Infof("The path number %v for SFC chain with name %v crooss-connect pod %v with pod %v over the vxlan %v", sfIdx, sfc.Name, sfIdentifier(prevSfSelectable), sfIdentifier(sfSelectable), vxlanName)
					if isLocal(sfSelectable) { // sfSelectable is local
						// create vxlan and connect sf to vxlan interface
						vxlanConfig := rndr.vxlanToRemoteSelectableSF(prevSfSelectable, vxlanName, vni)
						rndr.mergeConfiguration(config, vxlanConfig)

						// cross-connect between the vxlan interface and the SF interface
						xconnect := rndr.crossConnectIfaces(vxlanName, iface, sfc.Unidirectional)
						rndr.mergeConfiguration(config, xconnect)
					} else { // prevSF is local
						// create vxlan and connect prevSF to vxlan in both directions
						vxlanConfig := rndr.vxlanToRemoteSelectableSF(sfSelectable, vxlanName, vni)
						rndr.mergeConfiguration(config, vxlanConfig)

						// cross-connect between the prevSF interface and vxlan interface
						xconnect := rndr.crossConnectIfaces(prevIface, vxlanName, sfc.Unidirectional)
						rndr.mergeConfiguration(config, xconnect)
					}
				}
			}
			// go to next link
			prevSfSelectable = sfSelectable
		}
		// go to next path
		prevSfSelectable = nil
	}
	return config, nil
}

// crossConnectIfaces returns the config for cross-connecting the given interfaces.
// If unidirectional is true, connects iface1 to iface2 only, otherwise connects in both directions.
func (rndr *Renderer) crossConnectIfaces(iface1 string, iface2 string, unidirectional bool) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	xconn := &vpp_l2.XConnectPair{
		ReceiveInterface:  iface1,
		TransmitInterface: iface2,
	}
	key := vpp_l2.XConnectKey(iface1)
	config[key] = xconn

	if !unidirectional {
		xconn = &vpp_l2.XConnectPair{
			ReceiveInterface:  iface2,
			TransmitInterface: iface1,
		}
		key = vpp_l2.XConnectKey(iface2)
		config[key] = xconn
	}
	return config
}

// mergeConfiguration merges sourceConf into destConf.
func (rndr *Renderer) mergeConfiguration(destConf, sourceConf controller.KeyValuePairs) {
	for k, v := range sourceConf {
		destConf[k] = v
	}
}

/**********************************************************************************************/
/************** Added for multipath rendering 																						*****/
/**********************************************************************************************/
// computePaths takes all resources selected for each SFC link and computes concrete paths for SFC chain
func (rndr *Renderer) computePaths(sfc *renderer.ContivSFC) ([][]ServiceFunctionSelectable, error) {
	filteredChain := rndr.filterOnlyUsableServiceInstances(sfc)
	rndr.Log.Debugf("creation of SFC chain %v will use only these service function instances: %v",
		sfc.Name, strings.Join(rndr.toStringSlice(filteredChain), ","))

	// path validation
	for _, link := range filteredChain {
		if link.Type == renderer.Pod {
			if len(link.Pods) == 0 {
				return nil, errors.Errorf("there is no valid path because link %v has no usable "+
					"pods", link)
			}
		} else {
			if len(link.ExternalInterfaces) == 0 {
				return nil, errors.Errorf("there is no valid path because link %v has no usable "+
					"interfaces", link)
			}
		}
	}

	// sorting chain pod/interfaces to get the same path results on each node
	rndr.sortPodsAndInterfaces(filteredChain)

	// get path count
	// Note: SRv6 proxy localsid (pod/interface for inner link in SFC chain) can be used only by one path
	// due to nature of dynamic SRv6 proxy (cache filled by incomming packed and applied to whatever comes
	// out of service -> crossing path here means to possibly applying SRv6 header from cache to packet
	// from different path)
	// That means that path count is limited only by minimum of pods/interfaces selected for each link (
	// pods/interfaces selected for end link can be reused unlimited times in paths)
	pathCount := 1<<31 - 1               // more than possible selected pods count
	for _, link := range filteredChain { // only inner links of original SFC chain ---> changed take into account all links
		if len(link.Pods) < pathCount {
			pathCount = len(link.Pods)
		}
	}

	// compute paths
	paths := make([][]ServiceFunctionSelectable, 0)
	for i := 0; i < pathCount; i++ {
		path := make([]ServiceFunctionSelectable, 0)
		for _, link := range filteredChain {
			// Note: modulo will possibly do something only for end link
			if link.Type == renderer.Pod {
				path = append(path, link.Pods[i%len(link.Pods)])
			} else {
				path = append(path, link.ExternalInterfaces[i%len(link.ExternalInterfaces)])
			}
		}
		paths = append(paths, path)
	}

	return paths, nil
}

// filterOnlyUsableServiceInstances filters out pods/interfaces that are not usable in SFC chain (
// For instance, as futur option for multiSFC system -->  Pods/interface used in other SFC may be excluded )
func (rndr *Renderer) filterOnlyUsableServiceInstances(sfc *renderer.ContivSFC) []*renderer.ServiceFunction {
	filteredChain := make([]*renderer.ServiceFunction, 0, len(sfc.Chain)-1)
	for _, link := range sfc.Chain {
		switch link.Type {
		case renderer.Pod:
			filteredChain = append(filteredChain, &renderer.ServiceFunction{
				Type: link.Type,
				Pods: link.Pods,
			})
		case renderer.ExternalInterface:
			filteredChain = append(filteredChain, &renderer.ServiceFunction{
				Type:               link.Type,
				ExternalInterfaces: link.ExternalInterfaces,
			})
		}
	}
	return filteredChain
}

func (rndr *Renderer) toStringSlice(chain []*renderer.ServiceFunction) []string {
	result := make([]string, len(chain))
	for i, v := range chain {
		result[i] = v.String()
	}
	return result
}

// sortPodsAndInterfaces makes inplace sort of pods and external interfaces in given chain
func (rndr *Renderer) sortPodsAndInterfaces(chain []*renderer.ServiceFunction) {
	for _, link := range chain {
		// sort pods by podID
		if len(link.Pods) > 1 {
			sort.Slice(link.Pods, func(i, j int) bool {
				return link.Pods[i].ID.String() < link.Pods[j].ID.String()
			})
		}

		// sort external interfaces by NodeID and Interface name
		if len(link.ExternalInterfaces) > 1 {
			sort.Slice(link.ExternalInterfaces, func(i, j int) bool {
				id1 := fmt.Sprintf("%v # %v", link.ExternalInterfaces[i].NodeID,
					link.ExternalInterfaces[i].CRDName)
				id2 := fmt.Sprintf("%v # %v", link.ExternalInterfaces[j].NodeID,
					link.ExternalInterfaces[j].CRDName)
				return id1 < id2
			})
		}
	}
}

// isLocal finds out whether this ServiceFunctionSelectable is local (pod/external interface)
func isLocal(sfSelectable ServiceFunctionSelectable) bool {
	switch selectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := selectable
		return pod.Local
	case *renderer.InterfaceSF:
		extif := selectable
		return extif.Local
	default:
		return false
	}
}

// getSfSelectableInterface returns a service function input/output interface which should be used for chaining.
func (rndr *Renderer) getSfSelectableInterface(sfSelectable ServiceFunctionSelectable, input bool) string {
	switch selectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := selectable
		if pod == nil {
			return ""
		}
		if input {
			return pod.InputInterface.ConfigName
		}
		return pod.OutputInterface.ConfigName

	case *renderer.InterfaceSF:
		iface := selectable
		if iface == nil {
			return ""
		}
		return iface.ConfigName
	}
	return ""
}

// nodeIdentifier provides identification of node where this ServiceFunctionSelectable is located
func nodeIdentifier(sfSelectable ServiceFunctionSelectable) uint32 {
	switch selectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := selectable
		return pod.NodeID
	case *renderer.InterfaceSF:
		iface := selectable
		return iface.NodeID
	default:
		return 0
	}
}

// vxlanToRemoteSelectableSF returns VXLAN configuration to a remote service function.
func (rndr *Renderer) vxlanToRemoteSelectableSF(sfSelectable ServiceFunctionSelectable, vxlanName string, vni uint32) (
	config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	srcAddr, _ := rndr.IPNet.GetNodeIP()
	dstAdr, _, err := rndr.IPAM.NodeIPAddress(nodeIdentifier(sfSelectable))
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

// for test
// nodeIdentifier provides identification of node where this ServiceFunctionSelectable is located
func sfIdentifier(sfSelectable ServiceFunctionSelectable) string {
	switch selectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := selectable
		return pod.ID.Name
	case *renderer.InterfaceSF:
		iface := selectable
		return iface.CRDName
	default:
		return ""
	}
}
