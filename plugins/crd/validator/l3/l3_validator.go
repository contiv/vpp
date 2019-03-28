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
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/gogo/protobuf/sortkeys"
	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/api/models/vpp/l3"

	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/validator/utils"
	"github.com/contiv/vpp/plugins/ipnet"
)

const (
	// Route validation status
	routeNotValidated = iota
	routeInvalid      = iota
	routeValid        = iota

	// VPP interface names
	gigENameMatch = `GigabitEthernet[[:alnum:]]*/[[:alnum:]]*/[[:alnum:]]*`
	tap2HostName  = "tap-vpp2"

	hostToVppIfName = "vpp1"
	vppToHostIfName = "tap-vpp2"
)

var (
	v4CidrRe = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*`)
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

// LinuxIfMap defines the structure for quick ip addresses lookups on linux
// host stack.
type LinuxIfMap map[string]string

// Validate will validate each nodes and pods l3 connectivity for any errors
func (v *Validator) Validate() {
	nodeList := v.VppCache.RetrieveAllNodes()
	numErrs := 0

	v.Report.SetPrefix("L3-FIB")

	for _, node := range nodeList {

		if node.NodeIPam == nil {
			v.Log.Infof("No IPAM data for node %s", node.Name)
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no IPAM data available")
			continue
		}

		if node.NodeInterfaces == nil {
			v.Log.Infof("validation aborted - no interfaces data available")
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no interface data available")
			continue
		}

		if node.NodeStaticRoutes == nil {
			v.Log.Infof("validation aborted - no route data available")
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no route data available")
			continue
		}

		vrfMap, err := v.createVrfMap(node)
		if err != nil {
			v.Report.AppendToNodeReport(node.Name, err.Error())
		}
		routeMap := v.createValidationMap(vrfMap)

		// Validate routes to local pods (they are all on vrf 1).
		numErrs += v.validateVrf1PodRoutes(node, vrfMap, routeMap)

		// Validate the vrf1 route to the local loop interface
		numErrs += v.validateRouteToLocalVxlanBVI(node, vrfMap, routeMap)

		// Validate local nodes gigE routes
		numErrs += v.validateVrf0GigERoutes(node, vrfMap, routeMap)

		// Validate vrf 0 local routes
		numErrs += v.validateVrf0LocalHostRoute(node, vrfMap, routeMap)

		// Validate vrf0 an vrf1 default routes
		numErrs += v.validateDefaultRoutes(node, vrfMap, routeMap)

		// Validate routes to all remote nodes for vrf 1 and vrf 0
		numErrs += v.validateRemoteNodeRoutes(node, vrfMap, routeMap)

		// Validate podSubnetCIDR routes
		numErrs += v.validatePodSubnetCidrRoutes(node, vrfMap, routeMap)

		// Validate podSubnetCIDR routes
		numErrs += v.validateVppHostNetworkRoutes(node, vrfMap, routeMap)

		// Validate routes to host stack interfaces
		numErrs += v.validateRoutesToLinuxInterfaces(node, vrfMap, routeMap)

		// This routine must be last - check whatever has been left
		numErrs += v.checkUnvalidatedRoutes(routeMap, node.Name)
		// fmt.Println(node.Name + ":")
		// printValidationMap(routeMap, vrfMap)
	}

	if numErrs == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, "validation OK")
	} else {
		errString := fmt.Sprintf("%d error%s found", numErrs, printS(numErrs))
		v.Report.AppendToNodeReport(api.GlobalMsg, errString)
	}
}

// createVrfMap organizes routes in a two-dimensional map where they can be
// easily looked up by  VrfID and RouteID
func (v *Validator) createVrfMap(node *telemetrymodel.Node) (VrfMap, error) {
	vrfMap := make(VrfMap, 0)
	for _, route := range node.NodeStaticRoutes {
		vrf, ok := vrfMap[route.Value.VrfId]
		if !ok {
			vrfMap[route.Value.VrfId] = make(Vrf, 0)
			vrf = vrfMap[route.Value.VrfId]
		}
		vrf[route.Value.DstNetwork] = route
	}
	return vrfMap, nil
}

// createValidationMap sets up a mark-and-sweep database that keeps track of
// processed routes. It is used to detect dangling routes (i.e. routes that
// should not be present on a given node.
func (v *Validator) createValidationMap(vm map[uint32]Vrf) RouteMap {
	valMap := make(RouteMap, 0)

	for vIdx, vrf := range vm {
		vrfRoutes := make(map[string]int, 0)
		for _, rte := range vrf {
			vrfRoutes[rte.Value.DstNetwork] = routeNotValidated
		}
		valMap[vIdx] = vrfRoutes
	}

	return valMap
}

// validateVrf1PodRoutes validates routes from VRF1 to local Pods. There must
// be a route to the Pod's IP address.
func (v *Validator) validateVrf1PodRoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0
	for _, pod := range node.PodMap {

		// Skip over host network pods
		if pod.IPAddress == node.ManIPAddr {
			continue
		}

		// Validate routes to local Pods
		// Lookup the Pod route in VRF1; it must have mask length = 32

		if pod.IPAddress != "" {
			numErrs += v.validateRoute(pod.IPAddress+"/32", 1, vrfMap, routeMap, node.Name,
				pod.VppIfName, pod.IPAddress, 0, vpp_l3.Route_INTRA_VRF)
		} else {
			numErrs++
			errString := fmt.Sprintf("pod '%s': IP Address empty, pod route validation skipped", pod.Name)
			v.Report.AppendToNodeReport(node.Name, errString)
		}

	}

	return numErrs
}

// validateVrf0GigERoutes validates routes from VRF0 to VPP nodes connected
// to the GigE network
func (v *Validator) validateVrf0GigERoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0

	ifc, err := findInterface(gigENameMatch, node.NodeInterfaces)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("local GigE interface not found, error %s", err)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	// Validate the route to the GigE subnet
	numErrs += v.validateRoute(node.IPAddr, 0, vrfMap, routeMap, node.Name, ifc.Value.Name,
		"0.0.0.0", 0, vpp_l3.Route_INTRA_VRF)

	// Validate gigE interface drop routes
	for _, ipAddr := range ifc.Value.IpAddresses {
		if ipAddr == node.IPAddr {
			numErrs += v.validatePhyNextHopRoutes(ipAddr, 0, vrfMap, routeMap, node.Name,
				ifc, 0, vpp_l3.Route_DROP)
			break
		}
	}

	// Validate routes to individual VPP nodes (remote and local) that are connected
	// to the GigE network
	nodeList := v.VppCache.RetrieveAllNodes()
	for _, remoteNode := range nodeList {
		if remoteNode == node {
			continue
		}

		dstIP := strings.Split(remoteNode.IPAddr, "/")
		numErrs += v.validateRoute(dstIP[0]+"/32", 0, vrfMap, routeMap, node.Name, ifc.Value.Name,
			dstIP[0], 0, vpp_l3.Route_INTRA_VRF)
	}

	return numErrs
}

// validateRemoteNodeRoutes validates routes to Host subnets on both the local
// node and the remote nodes and toPod subnets on remote nodes.
func (v *Validator) validateRemoteNodeRoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0

	// Check for existence of local vxlanBVI - this will be the outgoing interface
	// for routes to Pod and host subnets on remote nodes
	_, err := findInterface(ipnet.VxlanBVIInterfaceName, node.NodeInterfaces)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("local vxlanBVI lookup failed, error %s; "+
			"unable to validate routes to remote nodes", err)
		v.Report.AppendToNodeReport(node.Name, errString)

		return numErrs
	}

	// Validate routes from VRF0 and VRF1 to local and remote Host IP addresses
	// (Management IP addresses).
	nodeList := v.VppCache.RetrieveAllNodes()
	for _, othNode := range nodeList {

		if othNode.NodeIPam == nil {
			numErrs++
			errString := fmt.Sprintf("missing IPAM for node %s - routes to the node not validated",
				othNode.Name)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		if othNode.Name == node.Name {
			// Validate route from VRF1 to the vppHostNetwork subnet on the
			// local node.
			numErrs += v.validateRoute(othNode.NodeIPam.VppHostNetwork, 1, vrfMap, routeMap, node.Name,
				"", "0.0.0.0", 0, vpp_l3.Route_INTER_VRF)
			continue
		}

		// Validate routes to remote nodes
		// Find the remote node's BVI interface
		ifc, err := findInterface(ipnet.VxlanBVIInterfaceName, othNode.NodeInterfaces)
		if err != nil {
			numErrs++
			errString := fmt.Sprintf("failed to validate route %s VRF%d - "+
				"failed lookup for vxlanBVI for node %s, error %s", othNode.ManIPAddr+"/32", 0, othNode.Name, err)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		// Check if the nextHop on the route to the vppHostNetwork subnet on
		// the remote node is one of the IP addresses configured on the remote
		// node's vxlanBVI interface
		bviAddr, err := checkIfRouteNextHopPointsToInterface(othNode.NodeIPam.VppHostNetwork, 1, vrfMap,
			ifc, othNode.Name)
		if err == nil {
			// Validate route from VRF1 to the vppHostNetwork subnet on the remote
			// node. The outgoing interface should be the local vxlanBVI interface
			// (i.e. the path to the remote node should be through the vxlan tunnel).
			numErrs += v.validateRoute(othNode.NodeIPam.VppHostNetwork, 1, vrfMap, routeMap, node.Name,
				ipnet.VxlanBVIInterfaceName, bviAddr, 0, vpp_l3.Route_INTRA_VRF)

			// Validate route from VRF0 to Host IP address (Management IP address)
			// on a remote node. It should point to VRF1.
			numErrs += v.validateRoute(othNode.ManIPAddr+"/32", 0, vrfMap, routeMap, node.Name,
				"", "0.0.0.0", 1, vpp_l3.Route_INTER_VRF)

			// Validate route from VRF1 to Host IP address (Management IP address)
			// on a remote node. Its next hop should be the IP address of the
			// vxlanBVI interface on the remote node and its outgoing interface
			// should be the local vxlanBVI interface.
			numErrs += v.validateRoute(othNode.ManIPAddr+"/32", 1, vrfMap, routeMap, node.Name,
				ipnet.VxlanBVIInterfaceName, bviAddr, 0, vpp_l3.Route_INTRA_VRF)
		} else {
			numErrs++
			v.Report.AppendToNodeReport(node.Name, err.Error())
		}

		// Check if the nextHop on the route to the PodSubnetThisNode subnet on
		// the remote node is one of the IP addresses configured on the remote
		// node's vxlanBVI interface
		bviAddr, err = checkIfRouteNextHopPointsToInterface(othNode.NodeIPam.PodSubnetThisNode, 1, vrfMap,
			ifc, othNode.Name)
		if err == nil {
			// Validate route from VRF1 to the PodSubnetThisNode subnet on the remote
			// node. The outgoing interface should be the local vxlanBVI
			// interface (i.e. the path to the remote node should be through
			// the vxlan tunnel).
			numErrs += v.validateRoute(othNode.NodeIPam.PodSubnetThisNode, 1, vrfMap, routeMap, node.Name,
				ipnet.VxlanBVIInterfaceName, bviAddr, 0, vpp_l3.Route_INTRA_VRF)
		} else {
			numErrs++
			v.Report.AppendToNodeReport(node.Name, err.Error())
		}
	}

	return numErrs
}

// validateVrf0LocalHostRoute validates the routes from VRF0 to the local
// Host network
func (v *Validator) validateVrf0LocalHostRoute(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {

	// validate local route to host and that the interface is correct
	numErrs := 0
	localRoute, ok := vrfMap[0][node.ManIPAddr+"/32"]
	if !ok {
		numErrs++
		errString := fmt.Sprintf("missing route with dst IP %s in VRF0 for node %s",
			node.ManIPAddr+"/32", node.Name)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}
	tapIntf, ok := node.NodeInterfaces.GetByName(localRoute.Value.OutgoingInterface)
	if !ok {
		numErrs++
		errString := fmt.Sprintf("missing interface %s for route with dst IP %s in VRF0 for node %s",
			localRoute.Value.OutgoingInterface, localRoute.Value.DstNetwork, node.Name)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	// If we see the next hop in the ARP table, validate it in the host route
	// and validate the route to the next hop; otherwise, just skip nextHop
	// validation
	var nextHop string
	for _, arpEntry := range node.NodeIPArp {
		if arpEntry.Value.Interface == tapIntf.Value.Name {
			nextHop = arpEntry.Value.IpAddress

			// Validate the nexthop found in the local host route
			numErrs += v.validateRoute(nextHop+"/32", 0, vrfMap, routeMap, node.Name,
				tap2HostName, nextHop, 0, vpp_l3.Route_INTRA_VRF)
			break
		}
	}

	// Validate the local host route itself
	numErrs += v.validateRoute(node.ManIPAddr+"/32", 0, vrfMap, routeMap, node.Name,
		tap2HostName, nextHop, 0, vpp_l3.Route_INTRA_VRF)

	return numErrs
}

// validateDefaultRoutes validates the default routes (most of them created
// automatically in VPP)
func (v *Validator) validateDefaultRoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {

	numErrs := 0

	// Validate the default route in VRF0:
	// - It must point to the GigE interface, so find its ifIndex
	// - If we know the next hop (from th ARP table), use it, otherwise do
	//   not validate the next hop
	ifc, err := findInterface(gigENameMatch, node.NodeInterfaces)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("failed to validate route %s VRF%d - "+
			"local GigE interface not found (error '%s')", "0.0.0.0/0", 0, err)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	// Validate the default Gateway route; if we can find the ARP entry for
	// the default Gateway, validate the route to it
	// numErrs += v.validateGigEDefaultRteNextHop("0.0.0.0/0", 0, vrfMap, routeMap, node, ifc)
	numErrs += v.validateRoute("0.0.0.0/0", 0, vrfMap, routeMap, node.Name,
		ifc.Value.Name, "", 0, vpp_l3.Route_INTRA_VRF)

	// Validate VRF0 boiler plate routes
	numErrs += v.validateRoute("0.0.0.0/32", 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("224.0.0.0/4", 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("240.0.0.0/4", 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("255.255.255.255/32", 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("::/0", 0, vrfMap, routeMap, node.Name,
		"", "::", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("fe80::/10", 0, vrfMap, routeMap, node.Name,
		"", "::", 0, vpp_l3.Route_INTRA_VRF)

	// Validate the default route in VRF1
	numErrs += v.validateRoute("0.0.0.0/0", 1, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_INTER_VRF)

	// Validate VRF1 boiler plate routes
	numErrs += v.validateRoute("0.0.0.0/32", 1, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("224.0.0.0/4", 1, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("240.0.0.0/4", 1, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)
	numErrs += v.validateRoute("255.255.255.255/32", 1, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 0, vpp_l3.Route_DROP)

	return numErrs
}

// validateRouteToLocalVxlanBVI validates the configured and automatically
// inserted routes to the local vxlanBVI interface
func (v *Validator) validateRouteToLocalVxlanBVI(node *telemetrymodel.Node, vrfMap map[uint32]Vrf,
	routeMap map[uint32]map[string]int) int {

	numErrs := 0
	loopIf, err := findInterface(ipnet.VxlanBVIInterfaceName, node.NodeInterfaces)
	if err != nil {
		numErrs++
		v.Report.AppendToNodeReport(node.Name, err.Error())
		return numErrs
	}

	// Validate the route to each of the vxlanBVI's IP addresses
	for _, ip := range loopIf.Value.IpAddresses {
		// Validate route to vxlanBVI subnet
		numErrs += v.validateRoute(ip, 1, vrfMap, routeMap, node.Name,
			loopIf.Value.Name, "0.0.0.0", 0, vpp_l3.Route_INTRA_VRF)

		numErrs += v.validatePhyNextHopRoutes(ip, 1, vrfMap, routeMap,
			node.Name, loopIf, 0, vpp_l3.Route_DROP)
	}

	return numErrs
}

// validatePodSubnetCidrRoutes to the subnet from which IP addresses are
// allocated for the vpp-side of tap interfaces that connect pods to vpp
func (v *Validator) validatePodSubnetCidrRoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0

	if node.NodeIPam == nil {
		numErrs++
		errString := fmt.Sprintf("missing IPAM for node %s - validatePodSubnetCidrRoutes not validated",
			node.Name)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	podSubnetCidrRte := node.NodeIPam.Config.PodSubnetCIDR

	numErrs += v.validateRoute(podSubnetCidrRte, 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 1, vpp_l3.Route_INTER_VRF)
	numErrs += v.validateRoute(podSubnetCidrRte, 1, vrfMap, routeMap, node.Name,
		"local0", "0.0.0.0", 0, vpp_l3.Route_DROP)

	return numErrs
}

// validateVppHostNetworkRoutes validates routes to the local host stack
// network
func (v *Validator) validateVppHostNetworkRoutes(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0

	if node.NodeIPam == nil {
		numErrs++
		errString := fmt.Sprintf("missing IPAM for node %s - routes to VppHostSubnetCIDR not validated",
			node.Name)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	numErrs += v.validateRoute(node.NodeIPam.Config.VPPHostSubnetCIDR, 0, vrfMap, routeMap, node.Name,
		"", "0.0.0.0", 1, vpp_l3.Route_INTER_VRF)
	numErrs += v.validateRoute(node.NodeIPam.Config.VPPHostSubnetCIDR, 1, vrfMap, routeMap, node.Name,
		"local0", "0.0.0.0", 0, vpp_l3.Route_DROP)

	numErrs += v.validateLocalVppHostNetworkRoute(node, vrfMap, routeMap)

	return numErrs
}

// validateLocalVppHostNetworkRoute validates the routes to IP addressed configured
// on the tap interfqace connecting the host stack to VPP.
func (v *Validator) validateLocalVppHostNetworkRoute(node *telemetrymodel.Node, vrfMap VrfMap, routeMap RouteMap) int {
	numErrs := 0

	ifc, err := findInterface(tap2HostName, node.NodeInterfaces)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("failed to validate route to tap-vpp2 - "+
			"failed lookup for tap-vpp2, err %s", err)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	if node.NodeIPam == nil {
		numErrs++
		errString := fmt.Sprintf("missing IPAM for node %s - route to VppHostNetwork not validated",
			node.Name)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	ipamHostNetAddr, ipamHostNetMask, err := utils.Ipv4CidrToAddressAndMask(node.NodeIPam.VppHostNetwork)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("ipam vppHostNetwork %s bad format; err %s",
			node.NodeIPam.VppHostNetwork, err)
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}
	ipamHostNetPrefix := ipamHostNetAddr &^ ipamHostNetMask

	for _, ipAddr := range ifc.Value.IpAddresses {
		// Validate host subnet route
		numErrs += v.validateRoute(ipAddr, 0, vrfMap, routeMap, node.Name,
			ifc.Value.Name, "0.0.0.0", 0, vpp_l3.Route_INTRA_VRF)

		// Validate tap-vpp2's drop routes (.0/32, .1/32 and .255/32)
		numErrs += v.validatePhyNextHopRoutes(ipAddr, 0, vrfMap, routeMap,
			node.Name, ifc, 0, vpp_l3.Route_DROP)

		// Make sure that the tap-vpp2 ip address is within the vppHostNetwork subnet
		ifHostNetAddr, ifHostNetMask, err := utils.Ipv4CidrToAddressAndMask(ipAddr)
		if err != nil {
			numErrs++
			errString := fmt.Sprintf("tap-vpp2 IP address %s bad format; err %s",
				ifc.Value.IpAddresses[0], err)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}
		ifHostNetPrefix := ifHostNetAddr &^ ifHostNetMask

		if (ifHostNetMask != ipamHostNetMask) || (ifHostNetPrefix != ipamHostNetPrefix) {
			numErrs++
			errString := fmt.Sprintf("inconsistent ipam vppHostNetwork %s vs tap-vpp2 IP address %s",
				node.NodeIPam.VppHostNetwork, ifc.Value.IpAddresses[0])
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}
	}

	return numErrs
}

// validateRoute performs all validations checks on a given route
func (v *Validator) validateRoute(rteID string, vrfID uint32, vrfMap VrfMap, rtMap RouteMap, nodeName string,
	eOutIface string, eNextHopAddr string, eViaVrf uint32, eType vpp_l3.Route_RouteType) int {

	numErrs := 0

	route, ok := vrfMap[vrfID][rteID]
	if !ok {
		numErrs++
		errString := fmt.Sprintf("missing route %s in VRF%d", rteID, vrfID)
		v.Report.AppendToNodeReport(nodeName, errString)

		return numErrs
	}

	// Assume at first that the route is valid. Any error found below will
	// flip the route status to false
	rtMap[vrfID][route.Value.DstNetwork] = routeValid

	// If Outgoing interface name is empty, skip outgoing interface validation
	if (route.Value.OutgoingInterface != "") && (eOutIface != route.Value.OutgoingInterface) {
		numErrs++
		rtMap[vrfID][route.Value.DstNetwork] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad outgoing if - "+
			"have '%s', expecting '%s'", route.Value.DstNetwork, vrfID, route.Value.OutgoingInterface, eOutIface)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	if route.Value.ViaVrfId != eViaVrf {
		numErrs++
		rtMap[vrfID][route.Value.DstNetwork] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad viaVrfID - "+
			"have '%d', expecting '%d'", route.Value.DstNetwork, vrfID, route.Value.ViaVrfId, eViaVrf)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	if route.Value.Type != eType {
		numErrs++
		rtMap[vrfID][route.Value.DstNetwork] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad Type - "+
			"have '%d', expecting '%d'", route.Value.DstNetwork, vrfID, route.Value.Type, eType)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	// eNextHopAddr is empty if the next hop should not be validated
	if (eNextHopAddr != "") && (route.Value.NextHopAddr != eNextHopAddr) {
		numErrs++
		rtMap[vrfID][route.Value.DstNetwork] = routeInvalid
		errString := fmt.Sprintf("invalid route %s in VRF%d; bad nextHop -"+
			"have '%s', expecting '%s", route.Value.DstNetwork, vrfID, route.Value.NextHopAddr, eNextHopAddr)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	return numErrs
}

// validatePhyNextHopRoutes validates routes tp physical next hop nodes and
// automatically inserted drop routes.
func (v *Validator) validatePhyNextHopRoutes(rteID string, vrfID uint32, vrfMap VrfMap, rtMap RouteMap, nodeName string,
	outIfc *telemetrymodel.NodeInterface, eViaVrf uint32, eType vpp_l3.Route_RouteType) int {
	numErrs := 0

	rteAddr, rteMask, _ := utils.Ipv4CidrToAddressAndMask(rteID)

	// Validate route to the physical nextHop
	phyNextHopCidr := utils.AddressAndMaskToIPv4(rteAddr, ^uint32(0))
	phyNextHopAddr := fmt.Sprintf("%d.%d.%d.%d",
		rteAddr>>24, (rteAddr>>16)&0xFF, (rteAddr>>8)&0xff, rteAddr&0xFF)
	numErrs += v.validateRoute(phyNextHopCidr, vrfID, vrfMap, rtMap, nodeName,
		outIfc.Value.Name, phyNextHopAddr, 0, vpp_l3.Route_INTRA_VRF)

	// Validate local vxlanBVI drop routes
	drop1Addr := utils.AddressAndMaskToIPv4(rteAddr&^rteMask, ^uint32(0))
	numErrs += v.validateRoute(drop1Addr, vrfID, vrfMap, rtMap, nodeName,
		"", "0.0.0.0", 0, eType)

	drop2Addr := utils.AddressAndMaskToIPv4(rteAddr|rteMask, ^uint32(0))
	numErrs += v.validateRoute(drop2Addr, vrfID, vrfMap, rtMap, nodeName,
		"", "0.0.0.0", 0, eType)

	return numErrs
}

// validateGigEDefaultRteNextHop validates the next hop in the VRF0 default
// route (if it's set). Two rules must be satisfied: the route to the next
// hop must exist, and there must be an entry for the next hop in the ARP
// table.
func (v *Validator) validateGigEDefaultRteNextHop(rteID string, vrfID uint32, vrfMap VrfMap, rtMap RouteMap,
	node *telemetrymodel.Node, outIfc *telemetrymodel.NodeInterface) int {
	if defaultRte, ok := vrfMap[0]["0.0.0.0/0"]; ok {
		defaultRteID := defaultRte.Value.NextHopAddr + "/32"

		if defaultRte, ok := vrfMap[0][defaultRteID]; ok {
			numErrs := v.validateRoute(defaultRteID, 0, vrfMap, rtMap, node.Name, outIfc.Value.Name,
				defaultRte.Value.NextHopAddr, 0, vpp_l3.Route_DROP)

			// Check that the next hop also has an ARP table entry
			//for _, arpEntry := range node.NodeIPArp {
			//	if arpEntry.Ae.IPAddress == defaultRte.Ipr.NextHopAddr {
			//		return numErrs
			//	}
			//}
			//
			//numErrs++
			//errString := fmt.Sprintf("invalid nextHop %s in default route 0.0.0.0/0 in VRF0 -"+
			//	"no corresponding ARP entry", defaultRte.Ipr.NextHopAddr)
			//v.Report.AppendToNodeReport(node.Name, errString)
			return numErrs
		}
	}

	// Default route not found; do not increment error count, default route
	// is validated at a later point in the workflow.
	return 0
}

// validateRoutesToLinuxInterfaces validates routes to interfaces/subnets
// attached to the host stack
func (v *Validator) validateRoutesToLinuxInterfaces(node *telemetrymodel.Node, vrfMap VrfMap, rtMap RouteMap) int {
	numErrs := 0

	nhIP, linuxRtes := getLinuxNextHopAndIfIP(node.LinuxInterfaces)
	linuxRteIfName, _, err := getToHostIfNameAndIdx(node.NodeInterfaces)
	if err != nil {
		numErrs++
		errString := fmt.Sprintf("can not validate routes to host; vpp interface to host stack not found")
		v.Report.AppendToNodeReport(node.Name, errString)
		return numErrs
	}

	for _, ifRteID := range linuxRtes {
		if _, ok := vrfMap[0][ifRteID]; ok {
			numErrs += v.validateRoute(ifRteID, 0, vrfMap, rtMap, node.Name, linuxRteIfName,
				nhIP, 0, vpp_l3.Route_INTRA_VRF)
		}
	}

	return numErrs
}

// getLinuxNextHopAndIfIP divides the host stack interfaces into tow sets: one
// set containing just the interface to vpp, the other set containing all other
// interfaces. The IP address of the interface to vpp is used as the next hop
// for routes to all subnets connected all other interfaces.
func getLinuxNextHopAndIfIP(lifcs telemetrymodel.LinuxInterfaces) (string, []string) {
	vppIfIP := ""
	nonVppIfIPRte := make([]string, 0)

	for _, ifc := range lifcs {
		for _, ifCidr := range ifc.Value.IpAddresses {
			if v4CidrRe.Match([]byte(ifCidr)) {
				ifSubnet := strings.Split(ifCidr, " ")[0]
				ipAddr := strings.Split(ifSubnet, "/")[0]

				if ifc.Value.HostIfName == hostToVppIfName {
					vppIfIP = ipAddr
				} else {
					nonVppIfIPRte = append(nonVppIfIPRte, fmt.Sprintf("%s/32", ipAddr))
				}
			}
		}
	}

	return vppIfIP, nonVppIfIPRte
}

// getToHostIfNameAndIdx finds the name and ifIndex of the vpp <-> host stack
// interface.
func getToHostIfNameAndIdx(ifcs map[uint32]telemetrymodel.NodeInterface) (string, uint32, error) {

	for _, v := range ifcs {
		if v.Value.Name == vppToHostIfName {
			return v.Value.Name, v.Metadata.SwIfIndex, nil
		}
	}

	return "", 0, fmt.Errorf("vpp host name not found")
}

// checkUnvalidatedRoutes walks through the mark-and-sweep database and reports
// all routes that have not been validated. An unvalidated route is likely
// dangling and a symptom of misconfiguration.
func (v *Validator) checkUnvalidatedRoutes(routeMap RouteMap, nodeName string) int {
	numErrs := 0
	vrfIDs := make([]uint32, 0)
	for vrfID := range routeMap {
		vrfIDs = append(vrfIDs, vrfID)
	}
	sortkeys.Uint32s(vrfIDs)

	reports := make([]string, 0)
	for _, vrfID := range vrfIDs {
		vrf := routeMap[vrfID]

		notValidated := 0
		invalid := 0
		valid := 0

		for rteID, rteStatus := range vrf {
			switch rteStatus {
			case routeNotValidated:
				notValidated++
				if strings.HasSuffix(rteID, "/32") {
					v.Log.Warnf("skipping validation of route %s in VRF%d; route ends with /32", rteID, vrfID)
					continue
				}

				numErrs++
				v.Report.AppendToNodeReport(nodeName, fmt.Sprintf("unexpected route %s in VRF%d; "+
					"route not validated", rteID, vrfID))
			case routeInvalid:
				invalid++
			case routeValid:
				valid++
			}
		}

		// Stash the summary, we will print it after all unexpected routes in
		// all VRFs have been printed
		report := fmt.Sprintf("Rte report VRF%d: total %d, notValidated %d, invalid: %d, valid:%d",
			vrfID, len(vrf), notValidated, invalid, valid)
		reports = append(reports, report)
	}

	for _, r := range reports {
		v.Report.AppendToNodeReport(nodeName, r)
	}

	return numErrs
}

// findInterface find the interface whose name matches the 'name' pattern.
// 'name' is specified as a regexp string
func findInterface(name string, ifcs map[uint32]telemetrymodel.NodeInterface) (*telemetrymodel.NodeInterface, error) {
	for _, ifc := range ifcs {
		match, err := regexp.Match(name, []byte(ifc.Value.Name))
		if err != nil {
			return nil, err
		}
		if match {
			return &ifc, nil
		}
	}

	return nil, fmt.Errorf("interface pattern %s not found", name)
}

// checkIfRouteNextHopPointsToInterface checks if the nextHop of the route
// identified by rteIDvpoints to one of the IP Addresses configured on the
// interface ifc.
func checkIfRouteNextHopPointsToInterface(rteID string, vrfID uint32, vrfMap VrfMap,
	ifc *telemetrymodel.NodeInterface, nodeName string) (string, error) {

	route, ok := vrfMap[vrfID][rteID]
	if !ok {
		return "", fmt.Errorf("missing route %s VRF%d", rteID, vrfID)
	}

	for _, ip := range ifc.Value.IpAddresses {
		bviAddr := strings.Split(ip, "/")[0]
		if bviAddr == route.Value.NextHopAddr {
			return bviAddr, nil
		}
	}

	return "", fmt.Errorf("invalid route %s; nextHop Address %s not configured on node %s, if %s",
		rteID, route.Value.NextHopAddr, nodeName, ifc.Value.Name)
}

func printS(errCnt int) string {
	if errCnt > 0 {
		return "s"
	}
	return ""
}

func printValidationMap(routeMap RouteMap, vrfMap VrfMap) {
	vrfIDs := make([]uint32, 0)
	for idx := range routeMap {
		vrfIDs = append(vrfIDs, idx)
	}
	sortkeys.Uint32s(vrfIDs)

	for _, key := range vrfIDs {
		fmt.Printf("VRF%d: routes %d\n", key, len(routeMap[key]))
		vrf := routeMap[key]

		routeIDs := make([]string, 0)
		for id := range vrf {
			routeIDs = append(routeIDs, id)
		}
		sortkeys.Strings(routeIDs)

		w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintf(w, "\tROUTE\tNEXT_HOP\tOUT_INTERFACE\tVIA-VRF\tTYPE\n")
		for _, rteID := range routeIDs {
			sts := routeMap[key][rteID]

			tag := ""
			if sts == routeNotValidated {
				tag = "x"
			}

			rte := vrfMap[key][rteID]
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\n", tag, rteID,
				rte.Value.NextHopAddr, rte.Value.OutgoingInterface, rte.Value.ViaVrfId, rte.Value.Type)
		}
		w.Flush()
		fmt.Println("")
	}
	fmt.Println("")
}
