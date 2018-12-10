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

package ipv4net

import (
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/idxmap"

	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/nodesync"
)

/* Main VPP interface */
const (
	loopbackNICLogicalName = "loopbackNIC" // logical name of the loopback interface configured instead of physical NICs
)

/* VXLANs */
const (
	// VXLAN Network Identifier (or VXLAN Segment ID)
	vxlanVNI = 10

	// as VXLAN tunnels are added to a BD, they must be configured with the same
	// and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may
	// loop among servers with the same VXLAN segment because VXLAN tunnels are fully
	// meshed among servers.
	vxlanSplitHorizonGroup = 1

	// name of the VXLAN BVI interface.
	vxlanBVIInterfaceName = "vxlanBVI" // name of the VXLAN BVI interface.

	// name of the VXLAN bridge domain
	vxlanBDName = "vxlanBD"
)

// prefix for the hardware address of VXLAN interfaces
var vxlanBVIHwAddrPrefix = []byte{0x12, 0x2b}

/********************** Node Connectivity Configuration ***********************/

// nodeConnectivityConfig return configuration used to connect this node with the given other node.
func (n *IPv4Net) nodeConnectivityConfig(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	// configuration for VXLAN tunnel
	l2Interconnect := n.ContivConf.GetRoutingConfig().UseL2Interconnect
	if !l2Interconnect && len(n.nodeIP) > 0 {
		// VXLAN interface
		var nodeIP net.IP
		if len(node.VppIPAddresses) > 0 {
			nodeIP = node.VppIPAddresses[0].Address
		} else {
			var err error
			nodeIP, err = n.otherNodeIP(node.ID)
			if err != nil {
				n.Log.Error(err)
				return config, err
			}
		}
		key, vxlanIf := n.vxlanIfToOtherNode(node.ID, nodeIP)
		config[key] = vxlanIf

		// ARP entry for the IP address on the opposite side
		vxlanIP, _, err := n.IPAM.VxlanIPAddress(node.ID)
		if err != nil {
			n.Log.Error(err)
			return config, err
		}
		key, vxlanArp := n.vxlanArpEntry(node.ID, vxlanIP)
		config[key] = vxlanArp

		// L2 FIB for the hardware address on the opposite side
		key, vxlanFib := n.vxlanFibEntry(node.ID)
		config[key] = vxlanFib
	}

	// collect configuration for L3 routes
	routes, err := n.routesToNode(node)
	if err != nil {
		return config, err
	}
	for key, route := range routes {
		config[key] = route
	}

	return config, nil
}

// nodeHasIPAddress returns true if the given node has at least one IP address assigned.
func nodeHasIPAddress(node *nodesync.Node) bool {
	return node != nil && (len(node.VppIPAddresses) > 0 || len(node.MgmtIPAddresses) > 0)
}

// routesToNode returns configuration of routes used for routing traffic destined to the given other node.
func (n *IPv4Net) routesToNode(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	var nextHop net.IP
	l2Interconnect := n.ContivConf.GetRoutingConfig().UseL2Interconnect
	if l2Interconnect {
		// route traffic destined to the other node directly
		if len(node.VppIPAddresses) > 0 {
			nextHop = node.VppIPAddresses[0].Address
		} else {
			var err error
			nextHop, err = n.otherNodeIP(node.ID)
			if err != nil {
				n.Log.Error(err)
				return config, err
			}
		}
	} else {
		// route traffic destined to the other node via VXLANs
		vxlanNextHop, _, err := n.IPAM.VxlanIPAddress(node.ID)
		if err != nil {
			n.Log.Error(err)
			return config, err
		}
		nextHop = vxlanNextHop
	}

	// route to pods of the other node
	key, routeToPods, err := n.routeToOtherNodePods(node.ID, nextHop)
	if err != nil {
		n.Log.Error(err)
		return config, err
	}
	config[key] = routeToPods

	// route to the host stack of the other node
	key, routeToHostStack, err := n.routeToOtherNodeHostStack(node.ID, nextHop)
	if err != nil {
		n.Log.Error(err)
		return config, err
	}
	config[key] = routeToHostStack

	// route to management IPs of the other node
	for _, mgmtIP := range node.MgmtIPAddresses {
		// route management IP address towards the destination node
		key, mgmtRoute1 := n.routeToOtherNodeManagementIP(mgmtIP, nextHop)
		config[key] = mgmtRoute1

		// inter-VRF route for the management IP address
		if !n.ContivConf.InSTNMode() {
			key, mgmtRoute2 := n.routeToOtherNodeManagementIPViaPodVRF(mgmtIP)
			config[key] = mgmtRoute2
		}
	}
	return config, nil
}

/*********************************** DHCP *************************************/

var (
	// variable used only in the context of go routines running handleDHCPNotification
	lastDHCPLease *interfaces.DHCPLease
)

// handleDHCPNotifications handles DHCP state change notifications
func (n *IPv4Net) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	n.Log.Info("DHCP notification received")

	// check for validity of the DHCP event
	if notif.Del {
		lastDHCPLease = nil
		n.Log.Info("Ignoring event of removed DHCP lease")
		return
	}
	if !n.useDHCP {
		n.Log.Info("Ignoring DHCP event, dynamic IP address assignment is disabled")
		return
	}
	if notif.Value == nil {
		n.Log.Warn("DHCP notification metadata is empty")
		return
	}
	dhcpLease, isDHCPLease := notif.Value.(*interfaces.DHCPLease)
	if !isDHCPLease {
		n.Log.Warn("Received invalid DHCP notification")
		return
	}
	if dhcpLease.InterfaceName != n.ContivConf.GetMainInterfaceName() {
		n.Log.Debugf("DHCP notification for a non-main interface (%s)",
			dhcpLease.InterfaceName)
		return
	}
	if proto.Equal(dhcpLease, lastDHCPLease) {
		// nothing has really changed, ignore
		n.Log.Info("Ignoring DHCP event - this lease was already processed")
		return
	}
	lastDHCPLease = dhcpLease

	// parse DHCP lease fields
	hostAddr, hostNet, defaultGw, err := n.parseDHCPLease(dhcpLease)
	if err != nil {
		return
	}

	// push event into the event loop
	n.EventLoop.PushEvent(&NodeIPv4Change{
		NodeIP:    hostAddr,
		NodeIPNet: hostNet,
		DefaultGw: defaultGw,
	})
	n.Log.Infof("Sent NodeIPv4Change event to the event loop for DHCP lease: %+v", *dhcpLease)
}

// parseDHCPLease parses fields of a DHCP lease.
func (n *IPv4Net) parseDHCPLease(lease *interfaces.DHCPLease) (hostAddr net.IP, hostNet *net.IPNet, defaultGw net.IP, err error) {
	// parse IP address of the default gateway
	if lease.RouterIpAddress != "" {
		defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
		if err != nil {
			n.Log.Errorf("Failed to parse DHCP route IP address: %v", err)
			return
		}
	}

	// parse host IP address and network
	if lease.HostIpAddress != "" {
		hostAddr, hostNet, err = net.ParseCIDR(lease.HostIpAddress)
		if err != nil {
			n.Log.Errorf("Failed to parse DHCP host IP address: %v", err)
			return
		}
	}
	return
}

/*********************** Global vswitch configuration *************************/

// enabledIPNeighborScan returns configuration for enabled IP neighbor scanning
// (used to clean up old ARP entries).
func (n *IPv4Net) enabledIPNeighborScan() (key string, config *l3.IPScanNeighbor) {
	ipScanConfig := n.ContivConf.GetIPNeighborScanConfig()
	config = &l3.IPScanNeighbor{
		Mode:           l3.IPScanNeighbor_IPv4,
		ScanInterval:   uint32(ipScanConfig.IPNeighborScanInterval),
		StaleThreshold: uint32(ipScanConfig.IPNeighborStaleThreshold),
	}
	key = l3.IPScanNeighborKey
	return key, config
}

/************************************ NICs ************************************/

// physicalInterface returns configuration for physical interface - either the main interface
// connecting node with the rest of the cluster or an extra physical interface requested
// in the config file.
func (n *IPv4Net) physicalInterface(name string, ips contivconf.IPsWithNetworks) (key string, config *interfaces.Interface) {
	ifConfig := n.ContivConf.GetInterfaceConfig()
	iface := &interfaces.Interface{
		Name:    name,
		Type:    interfaces.Interface_DPDK,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	if n.ContivConf.UseVmxnet3() {
		iface.Type = interfaces.Interface_VMXNET3_INTERFACE
		if ifConfig.Vmxnet3RxRingSize != 0 && ifConfig.Vmxnet3TxRingSize != 0 {
			iface.GetVmxNet3().RxqSize = uint32(ifConfig.Vmxnet3RxRingSize)
			iface.GetVmxNet3().TxqSize = uint32(ifConfig.Vmxnet3TxRingSize)
		}
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = interfaces.InterfaceKey(name)
	return key, iface
}

// loopbackInterface returns configuration for loopback created when no physical interfaces
// are configured.
func (n *IPv4Net) loopbackInterface(ips contivconf.IPsWithNetworks) (key string, config *interfaces.Interface) {
	iface := &interfaces.Interface{
		Name:    loopbackNICLogicalName,
		Type:    interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = interfaces.InterfaceKey(loopbackNICLogicalName)
	return key, iface
}

// defaultRoute return configuration for default route connecting the node with the outside world.
func (n *IPv4Net) defaultRoute(gwIP net.IP, outIfName string) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:        ipv4NetAny,
		NextHopAddr:       gwIP.String(),
		OutgoingInterface: outIfName,
		VrfId:             n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/************************************ VRFs ************************************/

// routesPodToMainVRF returns non-drop routes from Pod VRF to Main VRF.
func (n *IPv4Net) routesPodToMainVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// by default to go from Pod VRF via Main VRF
	r1 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: ipv4NetAny,
		VrfId:      routingCfg.PodVRFID,
		ViaVrfId:   routingCfg.MainVRFID,
	}
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Pod VRF via Main VRF
	r2 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: n.IPAM.HostInterconnectSubnetThisNode().String(),
		VrfId:      routingCfg.PodVRFID,
		ViaVrfId:   routingCfg.MainVRFID,
	}
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// routesMainToPodVRF returns non-drop routes from Main VRF to Pod VRF.
func (n *IPv4Net) routesMainToPodVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// pod subnet (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r1 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: n.IPAM.PodSubnetAllNodes().String(),
		VrfId:      routingCfg.MainVRFID,
		ViaVrfId:   routingCfg.PodVRFID,
	}
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r2 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: n.IPAM.HostInterconnectSubnetAllNodes().String(),
		VrfId:      routingCfg.MainVRFID,
		ViaVrfId:   routingCfg.PodVRFID,
	}
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// dropRoutesIntoPodVRF returns drop routes for Pod VRF.
func (n *IPv4Net) dropRoutesIntoPodVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// drop packets destined to pods no longer deployed
	r1 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.PodSubnetAllNodes())
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// drop packets destined to nodes no longer deployed
	r2 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.HostInterconnectSubnetAllNodes())
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2

	return routes
}

// dropRoute is a helper method to construct drop route.
func (n *IPv4Net) dropRoute(vrfID uint32, dstAddr *net.IPNet) *l3.StaticRoute {
	return &l3.StaticRoute{
		Type:       l3.StaticRoute_DROP,
		DstNetwork: dstAddr.String(),
		VrfId:      vrfID,
	}
}

/************************** Bridge Domain with VXLANs **************************/

// vxlanBVILoopback returns configuration of the loopback interfaces acting as BVI
// for the bridge domain with VXLAN interfaces.
func (n *IPv4Net) vxlanBVILoopback() (key string, config *interfaces.Interface, err error) {
	vxlanIP, vxlanIPNet, err := n.IPAM.VxlanIPAddress(n.NodeSync.GetNodeID())
	if err != nil {
		return "", nil, err
	}
	vxlan := &interfaces.Interface{
		Name:        vxlanBVIInterfaceName,
		Type:        interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(vxlanIP, vxlanIPNet))},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), vxlanBVIHwAddrPrefix),
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
	}
	key = interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan, nil
}

// vxlanBridgeDomain returns configuration for the bridge domain with VXLAN interfaces.
func (n *IPv4Net) vxlanBridgeDomain() (key string, config *l2.BridgeDomain) {
	bd := &l2.BridgeDomain{
		Name:                vxlanBDName,
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*l2.BridgeDomain_Interface{
			{
				Name: vxlanBVIInterfaceName,
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
	if len(n.nodeIP) > 0 {
		for _, node := range n.NodeSync.GetAllNodes() {
			if node.Name == n.ServiceLabel.GetAgentLabel() {
				// skip this node
				continue
			}
			if !nodeHasIPAddress(node) {
				// skip node without IP address
			}
			bd.Interfaces = append(bd.Interfaces, &l2.BridgeDomain_Interface{
				Name:              n.nameForVxlanToOtherNode(node.ID),
				SplitHorizonGroup: vxlanSplitHorizonGroup,
			})
		}
	}
	key = l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// nameForVxlanToOtherNode returns logical name to use for VXLAN interface
// connecting this node with the given other node.
func (n *IPv4Net) nameForVxlanToOtherNode(otherNodeID uint32) string {
	return fmt.Sprintf("vxlan%d", otherNodeID)
}

// vxlanIfToOtherNode returns configuration for VXLAN interface connecting this node
// with the given other node.
func (n *IPv4Net) vxlanIfToOtherNode(otherNodeID uint32, otherNodeIP net.IP) (key string, config *interfaces.Interface) {
	vxlan := &interfaces.Interface{
		Name: n.nameForVxlanToOtherNode(otherNodeID),
		Type: interfaces.Interface_VXLAN_TUNNEL,
		Link: &interfaces.Interface_Vxlan{
			Vxlan: &interfaces.VxlanLink{
				SrcAddress: n.nodeIP.String(),
				DstAddress: otherNodeIP.String(),
				Vni:        vxlanVNI,
			},
		},
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan
}

// vxlanArpEntry returns configuration for ARP entry resolving hardware address
// of the VXLAN BVI interface of another node.
func (n *IPv4Net) vxlanArpEntry(otherNodeID uint32, vxlanIP net.IP) (key string, config *l3.ARPEntry) {
	arp := &l3.ARPEntry{
		Interface:   vxlanBVIInterfaceName,
		IpAddress:   vxlanIP.String(),
		PhysAddress: hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		Static:      true,
	}
	key = l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vxlanFibEntry returns configuration for L2 FIB used inside the bridge domain with VXLANs
// to route traffic destinated to the given other node through the right VXLAN interface.
func (n *IPv4Net) vxlanFibEntry(otherNodeID uint32) (key string, config *l2.FIBEntry) {
	fib := &l2.FIBEntry{
		BridgeDomain:            vxlanBDName,
		PhysAddress:             hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		OutgoingInterface:       n.nameForVxlanToOtherNode(otherNodeID),
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  l2.FIBEntry_FORWARD,
	}
	key = l2.FIBKey(fib.BridgeDomain, fib.PhysAddress)
	return key, fib
}

// otherNodeIP calculates the (statically selected) IP address of the given other node
func (n *IPv4Net) otherNodeIP(otherNodeID uint32) (net.IP, error) {
	nodeIP, _, err := n.IPAM.NodeIPAddress(otherNodeID)
	if err != nil {
		err := fmt.Errorf("Failed to get Node IP address for node ID %v, error: %v ",
			otherNodeID, err)
		n.Log.Error(err)
		return nodeIP, err
	}
	return nodeIP, nil
}

// routeToOtherNodePods returns configuration for route applied to traffic destined
// to pods of another node.
func (n *IPv4Net) routeToOtherNodePods(otherNodeID uint32, nextHopIP net.IP) (key string, config *l3.StaticRoute, err error) {
	podNetwork, err := n.IPAM.PodSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to compute pod network for node ID %v, error: %v ", otherNodeID, err)
	}
	key, config = n.routeToOtherNodeNetworks(podNetwork, nextHopIP)
	return
}

// routeToOtherNodeHostStack returns configuration for route applied to traffic destined
// to the host stack of another node.
func (n *IPv4Net) routeToOtherNodeHostStack(otherNodeID uint32, nextHopIP net.IP) (key string, config *l3.StaticRoute, err error) {
	hostNetwork, err := n.IPAM.HostInterconnectSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", otherNodeID, err)
	}
	key, config = n.routeToOtherNodeNetworks(hostNetwork, nextHopIP)
	return
}

// routeToOtherNodeNetworks is a helper function to build route for traffic destined to another node.
func (n *IPv4Net) routeToOtherNodeNetworks(destNetwork *net.IPNet, nextHopIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP.String(),
	}
	if n.ContivConf.GetRoutingConfig().UseL2Interconnect {
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = n.ContivConf.GetRoutingConfig().PodVRFID
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIP returns configuration for route applied to traffic destined
// to a management IP of another node.
func (n *IPv4Net) routeToOtherNodeManagementIP(managementIP, nextHopIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:  managementIP.String() + "/32",
		NextHopAddr: nextHopIP.String(),
	}
	if n.ContivConf.GetRoutingConfig().UseL2Interconnect {
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = n.ContivConf.GetRoutingConfig().PodVRFID
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIPViaPodVRF returns configuration for route used
// in Main VRF to direct traffic destined to management IP of another node
// to go via Pod VRF (and then further via VXLANs).
func (n *IPv4Net) routeToOtherNodeManagementIPViaPodVRF(managementIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: managementIP.String() + "/32",
		VrfId:      n.ContivConf.GetRoutingConfig().MainVRFID,
		ViaVrfId:   n.ContivConf.GetRoutingConfig().PodVRFID,
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}
