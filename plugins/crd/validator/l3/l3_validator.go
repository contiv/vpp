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
//

package l3

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
	"github.com/ligato/cn-infra/logging"

	"regexp"
	"strings"
)

const (
	routeNotValidated = iota
	routeInvalid      = iota
	routeValid        = iota
)

// Validator is the implementation of the ContivTelemetryProcessor interface.
type Validator struct {
	Log logging.Logger

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

// Vrf is a type declaration to help simplify a map of maps
type Vrf map[string]telemetrymodel.NodeIPRoute

// VrfMap keeps the routing table organized by VRF IDs
type VrfMap map[uint32]Vrf

// RouteMap defines the structure for keeping track of validated/valid/invalid
// routes
type RouteMap map[uint32]map[string]int

//Validate will validate each nodes and pods l3 connectivity for any errors
func (v *Validator) Validate() {
	nodeList := v.VppCache.RetrieveAllNodes()
	numErrs := 0

	for _, node := range nodeList {

		vrfMap, err := v.createVrfMap(node)
		if err != nil {
			v.Report.LogErrAndAppendToNodeReport(node.Name, err.Error())
		}
		routeMap := v.createValidationMap(vrfMap)

		// Validate routes to local pods (they are all on vrf 1).
		numErrs += v.validateVrf1PodRoutes(node, vrfMap, routeMap)

		// Validate the vrf1 route to the local loop interface
		numErrs += v.validateRouteToLocalLoopInterface(node, vrfMap, routeMap)

		// Validate local nodes gigE routes
		numErrs += v.validateVrf0GigERoutes(node, vrfMap, routeMap)

		// Validate vrf 0 local routes
		numErrs += v.validateVrf0LocalHostRoute(node, vrfMap, routeMap)

		// Validate vrf 1 default route
		numErrs += v.validateVrf1DefaultRoute(node, vrfMap, routeMap)

		// Validate routes to all remote nodes for vrf 1 and vrf 0
		numErrs += v.validateRemoteNodeRoutes(node, vrfMap, routeMap)

		// Validate podSubnetCIDR routes
		numErrs += v.validatePodSubnetCIDR(node, vrfMap, routeMap)

		for vIdx, vrf := range routeMap {
			var notValidated, invalid, valid int

			for _, rteStatus := range vrf {
				switch rteStatus {
				case routeNotValidated:
					notValidated++
				case routeInvalid:
					invalid++
				case routeValid:
					valid++
				}
			}

			report := fmt.Sprintf("Rte report VRF%d: total %d, notValidated %d, invalid: %d, valid:%d",
				vIdx, len(vrf), notValidated, invalid, valid)
			v.Report.AppendToNodeReport(node.Name, report)
		}

		fmt.Println(node.Name + ":")
		printValidationMap(routeMap)
	}

	if numErrs == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, "success validating l3 info.")
	} else {
		errString := fmt.Sprintf("%d Errors in L3 validation...", numErrs)
		v.Report.AppendToNodeReport(api.GlobalMsg, errString)
	}
}

func (v *Validator) createVrfMap(node *telemetrymodel.Node) (VrfMap, error) {
	vrfMap := make(VrfMap, 0)
	for _, route := range node.NodeStaticRoutes {
		vrf, ok := vrfMap[route.Ipr.VrfID]
		if !ok {
			vrfMap[route.Ipr.VrfID] = make(Vrf, 0)
			vrf = vrfMap[route.Ipr.VrfID]
		}

		if !strings.Contains(route.IprMeta.TableName, "-VRF:") {
			continue
		}
		vrf[route.Ipr.DstAddr] = route
	}
	return vrfMap, nil
}

func (v *Validator) createValidationMap(vm map[uint32]Vrf) RouteMap {
	valMap := make(RouteMap, 0)

	for vIdx, vrf := range vm {
		vrfRoutes := make(map[string]int, 0)
		for _, rte := range vrf {
			vrfRoutes[rte.Ipr.DstAddr] = routeNotValidated
		}
		valMap[vIdx] = vrfRoutes
	}

	return valMap
}

func (v *Validator) validateVrf1PodRoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {

	numErrs := 0
	for _, pod := range node.PodMap {

		// Skip over host network pods
		if pod.IPAddress == node.ManIPAddr {
			continue
		}

		// Validate routes to local Pods
		// Lookup the Pod route in VRF1; it must have mask length = 32
		numErrs += v.validateRoute(pod.IPAddress+"/32", 1, vrfMap, routeMap, node.Name,
			pod.VppIfName, pod.VppSwIfIdx, pod.IPAddress)

		// make sure pod that the route for the pod-facing tap interface in vpp
		// exists and is valid
		numErrs += v.validateRoute(pod.VppIfIPAddr, 1, vrfMap, routeMap, node.Name,
			pod.VppIfName, pod.VppSwIfIdx, strings.Split(pod.VppIfIPAddr, "/")[0])
	}

	return numErrs
}

func (v *Validator) validateVrf0GigERoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {
	numErrs := 0

	var gigEIfName string
	var ifIdx int
	var ifc telemetrymodel.NodeInterface
	for ifIdx, ifc = range node.NodeInterfaces {
		match, err := regexp.Match(`GigabitEthernet[0-9]/[0-9]*/[0-9]`, []byte(ifc.If.Name))
		if err != nil {
			numErrs++
			errString := fmt.Sprintf("GigE interface lookup match error %s", err)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			return numErrs
		}
		if match {
			gigEIfName = ifc.If.Name
			break
		}
	}

	if gigEIfName == "" {
		numErrs++
		errString := fmt.Sprintf("GigE interface not found")
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		return numErrs
	}

	// Validate the route to the local subnet
	numErrs += v.validateRoute(node.IPAddr, 0, vrfMap, routeMap, node.Name, gigEIfName, uint32(ifIdx),
		"0.0.0.0")

	// Validate routes to all VPP nodes (remote and local) that are connected
	// to the GigE subnet
	nodeList := v.VppCache.RetrieveAllNodes()
	for _, node := range nodeList {
		dstIP, _ := separateIPandMask(node.IPAddr)
		numErrs += v.validateRoute(dstIP+"/32", 0, vrfMap, routeMap, node.Name, gigEIfName, uint32(ifIdx), dstIP)
	}

	return numErrs
}

func (v *Validator) validateRemoteNodeRoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {
	//validate remote nodes connectivity to current node
	numErrs := 0
	nodeList := v.VppCache.RetrieveAllNodes()
	for _, othNode := range nodeList {
		if othNode.Name == node.Name {
			continue
		}

		podNwIP := othNode.NodeIPam.PodNetwork
		route, ok := vrfMap[1][podNwIP]
		if !ok {
			errString := fmt.Sprintf("Route for pod network for node %s with ip %s not found",
				othNode.Name, podNwIP)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
		}

		// Assume that the route will be valid. Each failed check flips
		// the status
		routeMap[1][route.Ipr.DstAddr] = routeValid

		//look for vxlanBD, make sure the route outgoing interface idx points to vxlanBVI
		for _, bd := range node.NodeBridgeDomains {
			if bd.Bd.Name == "vxlanBD" {
				if bd.BdMeta.BdID2Name[route.IprMeta.OutgoingIfIdx] != "vxlanBVI" {
					numErrs++
					routeMap[1][route.Ipr.DstAddr] = routeInvalid
					errString := fmt.Sprintf("vxlanBD outgoing interface for ipr index %d for route "+
						"with pod network ip %s is not vxlanBVI", route.IprMeta.OutgoingIfIdx, podNwIP)
					v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
				}
			}
			for _, intf := range bd.Bd.Interfaces {
				if intf.Name == "vxlanBVI" {
					if !intf.BVI {
						numErrs++
						routeMap[1][route.Ipr.DstAddr] = routeInvalid
						errString := fmt.Sprintf("Bridge domain %s interface %s BVI is %+v, expected true",
							bd.Bd.Name, intf.Name, intf.BVI)
						v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
					}
				}
			}
		}
		//find remote node vxlanBD, find the interface which the idx points to, make sure that one of the
		//ip addresses is the same as the main nodes routes next hop ip
		for _, bd := range othNode.NodeBridgeDomains {
			for id, name := range bd.BdMeta.BdID2Name {
				if name == "vxlanBVI" {
					intf := othNode.NodeInterfaces[int(id)]
					matchingIPFound := false
					for _, ip := range intf.If.IPAddresses {
						if ip == route.Ipr.NextHopAddr+"/24" {
							matchingIPFound = true
						}
					}
					if !matchingIPFound {
						numErrs++
						routeMap[1][route.Ipr.DstAddr] = routeInvalid
						errString := fmt.Sprintf("no matching ip found in remote node %s interface "+
							"%s to match current node %s route next hop %s",
							othNode.Name, intf.If.Name, node.Name, route.Ipr.NextHopAddr)
						v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
					}
				}
			}
		}
		//validate vrf 0 to vrf 1 connection exists
		vrf0ToRemoteRoute, ok := vrfMap[0][othNode.ManIPAddr+"/32"]
		if !ok {
			errString := fmt.Sprintf("could not find route to node %s with ip %s from vrf0",
				othNode.Name, othNode.ManIPAddr+"/32")
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			//err
			numErrs++
		}

		// Assume that the route will be valid. Each failed check flips
		// the status
		routeMap[0][vrf0ToRemoteRoute.Ipr.DstAddr] = routeValid

		if vrf0ToRemoteRoute.Ipr.DstAddr != othNode.ManIPAddr+"/32" {
			//err wrong dest.
			numErrs++
			routeMap[0][vrf0ToRemoteRoute.Ipr.DstAddr] = routeInvalid
			errString := fmt.Sprintf("vrf0 to remote route dst ip %s is different than node %s man ip %s",
				vrf0ToRemoteRoute.Ipr.DstAddr, node.Name, node.ManIPAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		}

		if vrf0ToRemoteRoute.Ipr.ViaVRFID != 1 {
			//err expected id of via vrf to be 1
			numErrs++
			routeMap[0][vrf0ToRemoteRoute.Ipr.DstAddr] = routeInvalid
			errString := fmt.Sprintf("invalid route %s - bad vrf id %d",
				vrf0ToRemoteRoute.Ipr.DstAddr, vrf0ToRemoteRoute.Ipr.ViaVRFID)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		}
	}
	return numErrs
}

func (v *Validator) validateVrf0LocalHostRoute(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {

	//validate local route to host and that the interface is correct
	numErrs := 0
	localRoute, ok := vrfMap[0][node.ManIPAddr+"/32"]
	if !ok {
		numErrs++
		errString := fmt.Sprintf("missing route with dst IP %s for node %s", node.ManIPAddr+"/32", node.Name)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		return numErrs
	}
	tapIntf := node.NodeInterfaces[int(localRoute.IprMeta.OutgoingIfIdx)]
	var nextHop string
	for _, arpEntry := range node.NodeIPArp {
		if arpEntry.AeMeta.IfIndex == tapIntf.IfMeta.SwIfIndex {
			nextHop = arpEntry.Ae.IPAddress
			break
		}
	}

	return v.validateRoute(node.ManIPAddr+"/32", 0, vrfMap, routeMap, node.Name,
		"tap-vpp2", tapIntf.IfMeta.SwIfIndex, nextHop)
}

func (v *Validator) validateVrf1DefaultRoute(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {

	return v.validateRoute("0.0.0.0/0", 1, vrfMap, routeMap, node.Name,
		"", 0, "0.0.0.0")
}

func (v *Validator) validateRouteToLocalLoopInterface(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {

	numErrs := 0
	loopIf, err := datastore.GetNodeLoopIFInfo(node)
	if err != nil {
		numErrs++
		v.Report.LogErrAndAppendToNodeReport(node.Name, err.Error())
		return numErrs
	}

	//validateRouteToLocalNodeLoopInterface
	for _, ip := range loopIf.If.IPAddresses {
		numErrs += v.validateRoute(ip, 1, vrfMap, routeMap, node.Name,
			loopIf.IfMeta.Tag, loopIf.IfMeta.SwIfIndex, "0.0.0.0")
	}
	return numErrs
}

func (v *Validator) validatePodSubnetCIDR(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {
	numErrs := 0

	podSubnetCidrRte := node.NodeIPam.Config.PodSubnetCIRDR

	numErrs += v.validateRoute(podSubnetCidrRte, 0, vrfMap, routeMap, node.Name,
		"", 0, "0.0.0.0")
	numErrs += v.validateRoute(podSubnetCidrRte, 1, vrfMap, routeMap, node.Name,
		"local0", 0, "0.0.0.0")
	return numErrs
}

func (v *Validator) validateRoute(rteID string, vrfID uint32, vrfMap VrfMap, rtMap RouteMap, nodeName string,
	eOutIface string, eOutgoingIfIdx uint32, eNextHopAddr string) int {

	numErrs := 0

	route, ok := vrfMap[vrfID][rteID]
	if !ok {
		numErrs++
		errString := fmt.Sprintf("missing route to PodSubnet %s in VRF%d", rteID, vrfID)
		v.Report.LogErrAndAppendToNodeReport(nodeName, errString)

		return numErrs
	}

	rtMap[vrfID][route.Ipr.DstAddr] = routeValid

	matched, err := regexp.Match(eOutIface, []byte(route.Ipr.OutIface))
	if err != nil {
		numErrs++
		rtMap[vrfID][route.Ipr.DstAddr] = routeInvalid
		errString := fmt.Sprintf("failed to match route %s outgoing interface (ifName %s) in VRF%d",
			route.Ipr.DstAddr, route.Ipr.OutIface, vrfID)
		v.Report.LogErrAndAppendToNodeReport(nodeName, errString)
	} else if !matched {
		numErrs++
		rtMap[vrfID][route.Ipr.DstAddr] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad outgoing if - "+
			"have '%s', expecting '%s'", route.Ipr.DstAddr, vrfID, route.Ipr.OutIface, eOutIface)
		v.Report.LogErrAndAppendToNodeReport(nodeName, errString)
	}

	if route.IprMeta.OutgoingIfIdx != eOutgoingIfIdx {
		numErrs++
		rtMap[vrfID][route.Ipr.DstAddr] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad outgoing swIndex - "+
			"have '%d', expecting '%d'", route.Ipr.DstAddr, vrfID, route.IprMeta.OutgoingIfIdx, eOutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(nodeName, errString)
	}

	// eNextHop is empty if the next hop should not be validated
	if (eNextHopAddr != "") && (route.Ipr.NextHopAddr != eNextHopAddr) {
		numErrs++
		rtMap[vrfID][route.Ipr.DstAddr] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad nextHop -"+
			"have '%s', expecting '%s", route.Ipr.DstAddr, vrfID, route.Ipr.NextHopAddr, eNextHopAddr)
		v.Report.LogErrAndAppendToNodeReport(nodeName, errString)
	}

	return numErrs
}

func separateIPandMask(ipAddress string) (string, string) {
	s := strings.Split(ipAddress, "/")
	if len(s) == 2 {
		return s[0], s[1]
	}
	return s[0], ""
}

func printS(errCnt int) string {
	if errCnt > 0 {
		return "s"
	}
	return ""
}

func printValidationMap(routeMap map[uint32]map[string]int) {
	for idx, vrf := range routeMap {
		fmt.Printf("VRF%d: routes %d\n", idx, len(vrf))
		for rte, sts := range vrf {
			if sts == routeNotValidated {
				fmt.Printf("x ")
			} else {
				fmt.Printf("  ")
			}

			fmt.Printf("{%s, %d}\n", rte, sts)
		}
		fmt.Println("")
	}
	fmt.Println("")

}
