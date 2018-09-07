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

	"strconv"
	"strings"
)

// Validator is the implementation of the ContivTelemetryProcessor interface.
type Validator struct {
	Log logging.Logger

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

//Vrf is a type declaration to help simplify a map of maps
type Vrf = map[string]telemetrymodel.NodeIPRoute

//Validate will validate each nodes and pods l3 connectivity for any errors
func (v *Validator) Validate() {
	nodeList := v.VppCache.RetrieveAllNodes()
	numErrs := 0
	routeMap := make(map[string]bool)

	for _, node := range nodeList {

		vrfMap, err := v.createVrfMap(node)
		if err != nil {
			v.Report.LogErrAndAppendToNodeReport(node.Name, err.Error())
		}

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

	}

	for routeIP, bl := range routeMap {
		if !bl {
			errString := fmt.Sprintf("Error validating L3 connectivity for route %s:", routeIP)
			v.Report.AppendToNodeReport(api.GlobalMsg, errString)
		}
	}

	if numErrs == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, "success validating l3 info.")
	} else {
		errString := fmt.Sprintf("%d Errors in L3 validation...", numErrs)
		v.Report.AppendToNodeReport(api.GlobalMsg, errString)
	}
}

func (v *Validator) createVrfMap(node *telemetrymodel.Node) (map[uint32]Vrf, error) {
	vrfMap := make(map[uint32]Vrf, 0)
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

func (v *Validator) validateVrf1PodRoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {

	numErrs := 0
	for _, pod := range node.PodMap {

		// Skip over host network pods
		if pod.IPAddress == node.ManIPAddr {
			continue
		}

		// Validate routes to local Pods
		lookUpRoute, ok := vrfMap[1][pod.IPAddress + "/32"]
		if !ok {
			numErrs++
			errString := fmt.Sprintf("missing route for Pod '%s' with IP Address %s",
				pod.Name, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		if lookUpRoute.Ipr.NextHopAddr != pod.IPAddress {
			numErrs++
			errString := fmt.Sprintf("invalid route for Pod '%s' - bad next hop; have %s, expecting %s",
				pod.Name, lookUpRoute.Ipr.NextHopAddr, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			routeMap[lookUpRoute.Ipr.DstAddr] = false
		}

		if pod.VppSwIfIdx != lookUpRoute.IprMeta.OutgoingIfIdx {
			numErrs++
			errString := fmt.Sprintf("Pod interface index %d does not match static route interface index %d",
				pod.VppSwIfIdx, lookUpRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			routeMap[lookUpRoute.Ipr.DstAddr] = false
		}
		if pod.VppIfName != lookUpRoute.Ipr.OutIface {
			errString := fmt.Sprintf("Name of pod interface %s differs from route interface name %s",
				pod.VppIfInternalName, lookUpRoute.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
			routeMap[lookUpRoute.Ipr.DstAddr] = false
		}

		//make sure pod vpp interface route exists and is valid
		podIfIProute, ok := vrfMap[1][pod.VppIfIPAddr]
		if !ok {
			numErrs++
			errString := fmt.Sprintf("route for Pod %s with vppIfIP Address %s does not exist ",
				pod.Name, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		if podIfIProute.Ipr.NextHopAddr+"/32" != pod.VppIfIPAddr {
			numErrs++
			errString := fmt.Sprintf("Pod %s IP %s does not match with route %+v next hop IP %s",
				pod.Name, pod.IPAddress, lookUpRoute, lookUpRoute.Ipr.NextHopAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			routeMap[podIfIProute.Ipr.DstAddr] = false
		}
		if pod.VppSwIfIdx != podIfIProute.IprMeta.OutgoingIfIdx {
			numErrs++
			errString := fmt.Sprintf("Pod interface index %d does not match static route interface index %d",
				pod.VppSwIfIdx, lookUpRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			routeMap[podIfIProute.Ipr.DstAddr] = false
		}

		if pod.VppIfName != lookUpRoute.Ipr.OutIface {
			numErrs++
			errString := fmt.Sprintf("Name of pod interface %s differs from route interface name %s",
				pod.VppIfInternalName, lookUpRoute.Ipr.OutIface)

			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			routeMap[podIfIProute.Ipr.DstAddr] = false
		}

		_, ok = routeMap[lookUpRoute.Ipr.DstAddr]
		if !ok {
			routeMap[lookUpRoute.Ipr.DstAddr] = true
		}

		_, ok = routeMap[podIfIProute.Ipr.DstAddr]
		if !ok {
			routeMap[podIfIProute.Ipr.DstAddr] = true
		}

	}
	return numErrs
}

func (v *Validator) validateVrf0GigERoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {
	numErrs := 0
	//begin validation of gigE routes, beginning with local one
	gigeRoute, ok := vrfMap[0][node.IPAddr]
	if !ok {
		errString := fmt.Sprintf("route with dst ip %s not found", node.IPAddr)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}
	if gigeRoute.Ipr.DstAddr != node.IPAddr {
		errString := fmt.Sprintf("route %s has different dst ip %s than node %s ip %s",
			gigeRoute.IprMeta.TableName, gigeRoute.Ipr.DstAddr, node.Name, node.IPAddr)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}
	if !strings.Contains(gigeRoute.Ipr.OutIface, "GigabitEthernet") {
		errString := fmt.Sprintf("route with dst IP %s had different out interface %s than "+
			"expected GigabitEthernet0/8/0", gigeRoute.Ipr.DstAddr, gigeRoute.Ipr.OutIface)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}

	//make sure interface index in route points to valid node interface
	intf := node.NodeInterfaces[int(gigeRoute.IprMeta.OutgoingIfIdx)]
	if intf.IfMeta.SwIfIndex != gigeRoute.IprMeta.OutgoingIfIdx {
		errString := fmt.Sprintf("interface %s has different interface index %d than route "+
			"with dst ip %s interface index %d",
			intf.IfMeta.Tag, intf.IfMeta.SwIfIndex, gigeRoute.Ipr.DstAddr, gigeRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}

	gigEIPFound := false
	for _, ip := range intf.If.IPAddresses {
		if ip == node.IPAddr {
			gigEIPFound = true
		}
	}

	if !gigEIPFound {
		errString := fmt.Sprintf("interface %s with index %d does not have a matching ip for dst ip %s",
			intf.IfMeta.Tag, intf.IfMeta.SwIfIndex, gigeRoute.Ipr.DstAddr)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}

	//Validate local nodes gigabit ethernet routes to other nodes
	nodeList := v.VppCache.RetrieveAllNodes()
	for _, otherNode := range nodeList {
		dstIP, _ := separateIPandMask(otherNode.IPAddr)
		route, ok := vrfMap[0][dstIP+"/32"]
		if !ok {
			errString := fmt.Sprintf("route with dst ip %s not found", dstIP+"/32")
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
		}
		ip, _ := separateIPandMask(route.Ipr.DstAddr)
		if ip != route.Ipr.NextHopAddr {
			errString := fmt.Sprintf("Dst IP %s and next hop IP %s dont match for route %s",
				route.Ipr.NextHopAddr, route.Ipr.DstAddr, route.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
		}

		if !strings.Contains(route.Ipr.OutIface, "GigabitEthernet") {
			errString := fmt.Sprintf("Route with dst IP %s has an out interface %s instead of"+
				"GigabitEthernet0/8/0", otherNode.IPAddr, route.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
		}

		if route.IprMeta.OutgoingIfIdx != gigeRoute.IprMeta.OutgoingIfIdx {
			errString := fmt.Sprintf("Route %s has an outgoing interface index of %d instead of %d",
				route.IprMeta.TableName, route.IprMeta.OutgoingIfIdx, gigeRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
		}
	}
	return numErrs
}

func (v *Validator) validateRemoteNodeRoutes(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {
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

		//look for vxlanBD, make sure the route outgoing interface idx points to vxlanBVI
		for _, bd := range node.NodeBridgeDomains {
			if bd.Bd.Name == "vxlanBD" {
				if bd.BdMeta.BdID2Name[route.IprMeta.OutgoingIfIdx] != "vxlanBVI" {
					errString := fmt.Sprintf("vxlanBD outgoing interface for ipr index %d for route "+
						"with pod network ip %s is not vxlanBVI", route.IprMeta.OutgoingIfIdx, podNwIP)
					v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
					numErrs++
				}
			}
			for _, intf := range bd.Bd.Interfaces {
				if intf.Name == "vxlanBVI" {
					if !intf.BVI {
						errString := fmt.Sprintf("Bridge domain %s interface %s BVI is %+v, expected true",
							bd.Bd.Name, intf.Name, intf.BVI)
						v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
						numErrs++
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
		//
		if vrf0ToRemoteRoute.Ipr.DstAddr != othNode.ManIPAddr+"/32" {
			errString := fmt.Sprintf("vrf0 to remote route dst ip %s is different than node %s man ip %s",
				vrf0ToRemoteRoute.Ipr.DstAddr, node.Name, node.ManIPAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			//err wrong dest.
			numErrs++
		}
		if vrf0ToRemoteRoute.Ipr.ViaVRFID != 1 {
			//err expected id of via vrf to be 1
			numErrs++

		}
	}
	return numErrs
}

func (v *Validator) validateVrf0LocalHostRoute(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {

	//validate local route to host and that the interface is correct
	numErrs := 0
	localRoute, ok := vrfMap[0][node.ManIPAddr+"/32"]
	if !ok {
		errString := fmt.Sprintf("missing route with dst IP %s for node %s", node.ManIPAddr+"/32", node.Name)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}

	tapIntf := node.NodeInterfaces[int(localRoute.IprMeta.OutgoingIfIdx)]
	if tapIntf.IfMeta.Tag != "tap-vpp2" {
		errString := fmt.Sprintf("node %s interface with idx %d from route with ip %s does not "+
			"match tag tap-vpp2 instead is %s",
			node.Name, localRoute.IprMeta.OutgoingIfIdx, localRoute.Ipr.DstAddr, tapIntf.IfMeta.Tag)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++

	}
	if tapIntf.IfMeta.SwIfIndex != localRoute.IprMeta.OutgoingIfIdx {
		errString := fmt.Sprintf("tap interface index %d dot not match route outgoing index %d",
			tapIntf.IfMeta.SwIfIndex, localRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
		//err mismatch indexes
	}
	if localRoute.Ipr.NextHopAddr == "" {
		errString := fmt.Sprintf("local route with dst ip %s is missing a next hop ip", localRoute.Ipr.DstAddr)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
	}

	return numErrs
}

func (v *Validator) validateVrf1DefaultRoute(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {

	numErrs := 0
	defaultRoute, ok := vrfMap[1]["0.0.0.0/0"]
	if !ok {
		errString := fmt.Sprintf("default route 0.0.0.0/0 missing for node %s", node.Name)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
		//err default route is missing
	}

	if defaultRoute.IprMeta.OutgoingIfIdx != 0 {
		errString := fmt.Sprintf("expeceted default route 0.0.0.0/0 to have outgoing "+
			"interface index of 0, got %d", defaultRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		numErrs++
		//err index does not match vrf 0 index - mismatch
	}
	return numErrs
}

func (v *Validator) validateRouteToLocalLoopInterface(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[string]bool) int {

	numErrs := 0
	loopIf, err := datastore.GetNodeLoopIFInfo(node)
	if err != nil {
		v.Report.LogErrAndAppendToNodeReport(node.Name, err.Error())
	}

	//validateRouteToLocalNodeLoopInterface
	for _, ip := range loopIf.If.IPAddresses {
		route, ok := vrfMap[1][ip]
		if !ok {
			errString := fmt.Sprintf("Static route for node %s with ip %s not found", node.Name, ip)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
			routeMap[route.Ipr.DstAddr] = false
		}

		if route.Ipr.DstAddr != ip {
			errString := fmt.Sprintf("Node %s loop interface ip %s does not match static route ip %s",
				node.Name, ip, route.Ipr.DstAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
			routeMap[route.Ipr.DstAddr] = false
		}

		if loopIf.IfMeta.SwIfIndex != route.IprMeta.OutgoingIfIdx {
			errString := fmt.Sprintf("Node %s loop interface idx %d does not match static route idx %d",
				node.Name, loopIf.IfMeta.SwIfIndex, route.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
			routeMap[route.Ipr.DstAddr] = false
		}
		if loopIf.IfMeta.Tag != route.Ipr.OutIface {
			errString := fmt.Sprintf("Node %s loop interface tag %s does not match static route tag %s",
				node.Name, loopIf.IfMeta.Tag, route.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			numErrs++
			routeMap[route.Ipr.DstAddr] = false
		}
		_, ok = routeMap[route.Ipr.DstAddr]
		if !ok {
			routeMap[route.Ipr.DstAddr] = true
		}
	}
	return numErrs
}

func maskLength2Mask(ml int) uint32 {
	var mask uint32
	for i := 0; i < 32-ml; i++ {
		mask = mask << 1
		mask++
	}
	return mask
}

func ip2uint32(ipAddress string) uint32 {
	var ipu uint32
	parts := strings.Split(ipAddress, ".")
	for _, p := range parts {
		// num, _ := strconv.ParseUint(p, 10, 32)
		num, _ := strconv.Atoi(p)
		ipu = (ipu << 8) + uint32(num)
		//fmt.Printf("%d: num: 0x%x, ipu: 0x%x\n", i, num, ipu)
	}
	return ipu
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
