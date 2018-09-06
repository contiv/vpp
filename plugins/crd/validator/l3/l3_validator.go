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
	RouteMap map[string]bool
	vrfMap   map[uint32]Vrf
	numErrs int
}

//Vrf is a type declaration to help simplify a map of maps
type Vrf = map[string]telemetrymodel.NodeIPRoute

// Validate performes the validation of L3 telemetry data collected from a
// Contiv cluster.
func (v *Validator) Validate() {
	nodeList := v.VppCache.RetrieveAllNodes()
	v.RouteMap = make(map[string]bool)

	for _, node := range nodeList {
		v.createVrfMap(node)

		v.validateRoutesToLocalPods(node)
		v.validateRoutesToLocalAndRemoteGigEInterfaces(node, nodeList)
		v.validateRoutesToLocalHostStack(node)
		v.validateRoutesFromRemoteNodesToUs(node, nodeList)
	}
	for routeIP, bl := range v.RouteMap {
		if !bl {
			errString := fmt.Sprintf("Error validating L3 connectivity for route %s:", routeIP)
			v.Report.AppendToNodeReport(api.GlobalMsg, errString)
		}
	}
	
	if v.numErrs == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, "success validating l3 info.")
	} else {
		errString := fmt.Sprintf("%d Errors in L3 validation...", v.numErrs)
		v.Report.AppendToNodeReport(api.GlobalMsg, errString)
	}

}

// validateRoutesToLocalPods validates routes to local Pods
func (v *Validator) validateRoutesToLocalPods(node *telemetrymodel.Node) {
	for _, pod := range node.PodMap {

		// Skip over host network pods
		if pod.IPAddress == node.ManIPAddr {
			continue
		}

		// Validate routes to local Pods
		lookUpRoute, ok := v.vrfMap[1][pod.IPAddress+"/32"]
		if !ok {
			v.numErrs++
			errString := fmt.Sprintf("route for Pod %s with IP Address %s missing",
				pod.Name, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		if lookUpRoute.Ipr.NextHopAddr != pod.IPAddress {
			errString := fmt.Sprintf("Pod %s: next hop %s in route does not match the Pod IP Address %s",
				pod.Name, lookUpRoute.Ipr.NextHopAddr, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[lookUpRoute.Ipr.DstAddr] = false
		}

		if pod.VppSwIfIdx != lookUpRoute.IprMeta.OutgoingIfIdx {
			errString := fmt.Sprintf("Pod interface index %d does not match static route interface index %d",
				pod.VppSwIfIdx, lookUpRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[lookUpRoute.Ipr.DstAddr] = false
		}

		if pod.VppIfName != lookUpRoute.Ipr.OutIface {
			errString := fmt.Sprintf("Name of pod interface %s differs from route interface name %s", pod.VppIfInternalName, lookUpRoute.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[lookUpRoute.Ipr.DstAddr] = false
		}

		podIfIProute, ok := v.vrfMap[1][pod.VppIfIPAddr]
		if !ok {
			errString := fmt.Sprintf("route for Pod %s with vppIfIP Address %s does not exist ",
				pod.Name, pod.IPAddress)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		if podIfIProute.Ipr.NextHopAddr+"/32" != pod.VppIfIPAddr {
			errString := fmt.Sprintf("Pod %s IP %s does not match with route %+v next hop IP %s", pod.Name, pod.IPAddress, lookUpRoute, lookUpRoute.Ipr.NextHopAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[podIfIProute.Ipr.DstAddr] = false
		}
		if pod.VppSwIfIdx != podIfIProute.IprMeta.OutgoingIfIdx {
			errString := fmt.Sprintf("Pod interface index %d does not match static route interface index %d", pod.VppSwIfIdx, lookUpRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[podIfIProute.Ipr.DstAddr] = false
		}

		if pod.VppIfName != lookUpRoute.Ipr.OutIface {
			errString := fmt.Sprintf("Name of pod interface %s differs from route interface name %s",
				pod.VppIfInternalName, lookUpRoute.Ipr.OutIface)

			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			v.numErrs++
			v.RouteMap[podIfIProute.Ipr.DstAddr] = false
		}

		_, ok = v.RouteMap[lookUpRoute.Ipr.DstAddr]

		if !ok {
			v.RouteMap[lookUpRoute.Ipr.DstAddr] = true
		}

		_, ok = v.RouteMap[podIfIProute.Ipr.DstAddr]

		if !ok {
			v.RouteMap[podIfIProute.Ipr.DstAddr] = true
		}
	}
}

func (v *Validator) validateRoutesToLocalAndRemoteGigEInterfaces(localNode *telemetrymodel.Node,
	nodeList []*telemetrymodel.Node) {

	//begin validation of gigE routes, beginning with local one
	gigeRoute, ok := v.vrfMap[0][localNode.IPAddr]
	if !ok {
		errString := fmt.Sprintf("route with dst ip %s not found", localNode.IPAddr)
		v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
		v.numErrs++
	}

	if gigeRoute.Ipr.DstAddr != localNode.IPAddr {
		errString := fmt.Sprintf("route %s has different dst ip %s than localNode %s ip %s",
			gigeRoute.IprMeta.TableName, gigeRoute.Ipr.DstAddr, localNode.Name, localNode.IPAddr)
		v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
		v.numErrs++
	}

	if !strings.Contains(gigeRoute.Ipr.OutIface, "GigabitEthernet") {
		errString := fmt.Sprintf("route with dst IP %s had different out interface %s than expected GigabitEthernet0/8/0",
			gigeRoute.Ipr.DstAddr, gigeRoute.Ipr.OutIface)
		v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
		v.numErrs++
	}

	intf := localNode.NodeInterfaces[int(gigeRoute.IprMeta.OutgoingIfIdx)]

	if intf.IfMeta.SwIfIndex != gigeRoute.IprMeta.OutgoingIfIdx {
		errString := fmt.Sprintf("interface %s has different interface index %d than route with dst ip %s interface index %d",
			intf.IfMeta.Tag, intf.IfMeta.SwIfIndex, gigeRoute.Ipr.DstAddr, gigeRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
		v.numErrs++
	}

	gigEIPFound := false
	for _, ip := range intf.If.IPAddresses {
		if ip == localNode.IPAddr {
			gigEIPFound = true
		}
	}

	if !gigEIPFound {
		errString := fmt.Sprintf("interface %s with index %d does not have a matching ip for dst ip %s",
			intf.IfMeta.Tag, intf.IfMeta.SwIfIndex, gigeRoute.Ipr.DstAddr)
		v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
		v.numErrs++
	}

	//Validate local nodes gigabit ethernet routes to other nodes
	for _, otherNode := range nodeList {
		dstIP, _ := separateIPandMask(otherNode.IPAddr)
		route, ok := v.vrfMap[0][dstIP+"/32"]
		if !ok {
			errString := fmt.Sprintf("route with dst ip %s not found", dstIP+"/32")
			v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
			v.numErrs++
		}
		ip, _ := separateIPandMask(route.Ipr.DstAddr)
		if ip != route.Ipr.NextHopAddr {
			errString := fmt.Sprintf("Dst IP %s and next hop IP %s dont match for route %s",
				route.Ipr.NextHopAddr, route.Ipr.DstAddr, route.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
			v.numErrs++
		}

		if !strings.Contains(route.Ipr.OutIface, "GigabitEthernet") {
			errString := fmt.Sprintf("Route with dst IP %s has an out interface %s instead of GigabitEthernet0/8/0", otherNode.IPAddr, route.Ipr.OutIface)
			v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
			v.numErrs++
		}

		if route.IprMeta.OutgoingIfIdx != gigeRoute.IprMeta.OutgoingIfIdx {
			errString := fmt.Sprintf("Route %s has an outgoing interface index of %d instead of %d", route.IprMeta.TableName, route.IprMeta.OutgoingIfIdx, gigeRoute.IprMeta.OutgoingIfIdx)
			v.Report.LogErrAndAppendToNodeReport(localNode.Name, errString)
			v.numErrs++
		}
	}

}

func (v *Validator) validateRoutesToLocalHostStack(node *telemetrymodel.Node) {
	//validate local route to host
	localRoute, ok := v.vrfMap[0][node.ManIPAddr+"/32"]
	if !ok {
		errString := fmt.Sprintf("missing route with dst IP %s for node %s", node.ManIPAddr+"/32", node.Name)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++
	}

	tapIntf := node.NodeInterfaces[int(localRoute.IprMeta.OutgoingIfIdx)]
	if tapIntf.IfMeta.Tag != "tap-vpp2" {
		errString := fmt.Sprintf("node %s interface with idx %d from route with ip %s does not match tag tap-vpp2 instead is %s",
			node.Name, localRoute.IprMeta.OutgoingIfIdx, localRoute.Ipr.DstAddr, tapIntf.IfMeta.Tag)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++

	}
	if tapIntf.IfMeta.SwIfIndex != localRoute.IprMeta.OutgoingIfIdx {
		errString := fmt.Sprintf("tap interface index %d dot not match route outgoing index %d",
			tapIntf.IfMeta.SwIfIndex, localRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++
		//err mismatch indexes
	}
	if localRoute.Ipr.NextHopAddr == "" {
		errString := fmt.Sprintf("local route with dst ip %s is missing a next hop ip", localRoute.Ipr.DstAddr)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++
	}

	defaultRoute, ok := v.vrfMap[1]["0.0.0.0/0"]
	if !ok {
		errString := fmt.Sprintf("default route 0.0.0.0/0 missing for node %s", node.Name)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++
		//err default route is missing
	}

	if defaultRoute.IprMeta.OutgoingIfIdx != 0 {
		errString := fmt.Sprintf("expeceted default route 0.0.0.0/0 to have outgoing interface index of 0, got %d",
			defaultRoute.IprMeta.OutgoingIfIdx)
		v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		v.numErrs++
		//err index does not match vrf 0 index - mismatch
	}
}

func (v *Validator) validateRoutesFromRemoteNodesToUs(node *telemetrymodel.Node, nodeList []*telemetrymodel.Node) {
	//validate remote nodes connectivity to current node
	for _, othNode := range nodeList {
		if othNode.Name == node.Name {
			continue
		}

		podNwIP := othNode.NodeIPam.PodNetwork
		route, ok := v.vrfMap[1][podNwIP]
		if !ok {
			v.numErrs++
			//err
		}

		//look for vxlanBD, make sure the route outgoing interface idx points to vxlanBVI
		for _, bd := range node.NodeBridgeDomains {
			if bd.Bd.Name == "vxlanBD" {
				if bd.BdMeta.BdID2Name[route.IprMeta.OutgoingIfIdx] != "vxlanBVI" {
					v.numErrs++
					//err
				}
			}
			for _, intf := range bd.Bd.Interfaces {
				if intf.Name == "vxlanBVI" {
					if !intf.BVI {
						v.numErrs++
						//err
					}
				}
			}
		}

		// find remote node vxlanBD, find the interface which the idx points
		// to, make sure that one of the ip addresses is the same as the main
		// nodes routes next hop ip
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
						errString := fmt.Sprintf("no matching ip found in remote node %s interface %s to match current node %s route next hop %s", othNode.Name, intf.If.Name, node.Name, route.Ipr.NextHopAddr)
						v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
					}
				}
			}
		}

		//verify that the VRF0 to VRF1 connection exists
		vrf0ToRemoteRoute, ok := v.vrfMap[0][othNode.ManIPAddr+"/32"]
		if !ok {
			errString := fmt.Sprintf("could not find route to node %s with ip %s from vrf0",
				othNode.Name, othNode.ManIPAddr+"/32")
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			//err
			v.numErrs++
		}
		
		//
		if vrf0ToRemoteRoute.Ipr.DstAddr != othNode.ManIPAddr+"/32" {
			errString := fmt.Sprintf("vrf0 to remote route dst ip %s is different than node %s man ip %s",
				vrf0ToRemoteRoute.Ipr.DstAddr, node.Name, node.ManIPAddr)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
			//err wrong dest.
			v.numErrs++
		}
		
		if vrf0ToRemoteRoute.Ipr.ViaVRFID != 1 {
			//err expected id of via vrf to be 1
			v.numErrs++
		}
	}
}

func (v *Validator) createVrfMap(node *telemetrymodel.Node) {
	v.vrfMap = make(map[uint32]Vrf, 0)
	for _, route := range node.NodeStaticRoutes {
		vrf, ok := v.vrfMap[route.Ipr.VrfID]
		if !ok {
			v.vrfMap[route.Ipr.VrfID] = make(Vrf, 0)
			vrf = v.vrfMap[route.Ipr.VrfID]
		}

		if !strings.Contains(route.IprMeta.TableName, "-VRF:") {
			continue
		}
		vrf[route.Ipr.DstAddr] = route
	}
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
