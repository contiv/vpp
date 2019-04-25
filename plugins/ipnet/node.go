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

package ipnet

import (
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/idxmap"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/nodesync"

	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
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

	// VxlanBVIInterfaceName is the name of the VXLAN BVI interface.
	VxlanBVIInterfaceName = "vxlanBVI"

	// podGwLoopbackInterfaceName is the name of the POD gateway loopback interface.
	podGwLoopbackInterfaceName = "podGwLoop"

	// name of the VXLAN bridge domain
	vxlanBDName = "vxlanBD"
)

// prefix for the hardware address of VXLAN interfaces
var vxlanBVIHwAddrPrefix = []byte{0x12, 0x2b}

/********************** Node Connectivity Configuration ***********************/

// nodeConnectivityConfig return configuration used to connect this node with the given other node.
func (n *IPNet) nodeConnectivityConfig(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	// configuration for VXLAN tunnel
	noOverlay := n.ContivConf.GetRoutingConfig().UseNoOverlay
	if !noOverlay && len(n.nodeIP) > 0 {
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

// nodeHasIPAddress returns true if the given node has at least one VPP and one management IP address assigned.
func nodeHasIPAddress(node *nodesync.Node) bool {
	return node != nil && (len(node.VppIPAddresses) > 0 && len(node.MgmtIPAddresses) > 0)
}

// routesToNode returns configuration of routes used for routing traffic destined to the given other node.
func (n *IPNet) routesToNode(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	var nextHop net.IP
	noOverlay := n.ContivConf.GetRoutingConfig().UseNoOverlay
	if noOverlay {
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
	if !n.ContivConf.GetIPAMConfig().UseExternalIPAM { // skip in case that external IPAM is in use
		key, routeToPods, err := n.routeToOtherNodePods(node.ID, nextHop)
		if err != nil {
			n.Log.Error(err)
			return config, err
		}
		config[key] = routeToPods
	}

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
		if mgmtRoute1 != nil {
			config[key] = mgmtRoute1
		}

		// inter-VRF route for the management IP address
		if !n.ContivConf.InSTNMode() && !noOverlay {
			key, mgmtRoute2 := n.routeToOtherNodeManagementIPViaPodVRF(mgmtIP)
			config[key] = mgmtRoute2
		}
	}
	return config, nil
}

/*********************************** DHCP *************************************/

var (
	// variable used only in the context of go routines running handleDHCPNotification
	lastDHCPLease *vpp_interfaces.DHCPLease
)

// handleDHCPNotifications handles DHCP state change notifications
func (n *IPNet) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
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
	dhcpLease, isDHCPLease := notif.Value.(*vpp_interfaces.DHCPLease)
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
func (n *IPNet) parseDHCPLease(lease *vpp_interfaces.DHCPLease) (hostAddr net.IP, hostNet *net.IPNet, defaultGw net.IP, err error) {
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
func (n *IPNet) enabledIPNeighborScan() (key string, config *vpp_l3.IPScanNeighbor) {
	ipScanConfig := n.ContivConf.GetIPNeighborScanConfig()
	config = &vpp_l3.IPScanNeighbor{
		Mode:           vpp_l3.IPScanNeighbor_IPv4,
		ScanInterval:   uint32(ipScanConfig.IPNeighborScanInterval),
		StaleThreshold: uint32(ipScanConfig.IPNeighborStaleThreshold),
	}
	key = vpp_l3.IPScanNeighborKey()
	return key, config
}

/************************************ NICs ************************************/

// physicalInterface returns configuration for physical interface - either the main interface
// connecting node with the rest of the cluster or an extra physical interface requested
// in the config file.
func (n *IPNet) physicalInterface(name string, ips contivconf.IPsWithNetworks) (key string, config *vpp_interfaces.Interface) {
	ifConfig := n.ContivConf.GetInterfaceConfig()
	iface := &vpp_interfaces.Interface{
		Name:    name,
		Type:    vpp_interfaces.Interface_DPDK,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	if n.ContivConf.UseVmxnet3() {
		iface.Type = vpp_interfaces.Interface_VMXNET3_INTERFACE
		if ifConfig.Vmxnet3RxRingSize != 0 && ifConfig.Vmxnet3TxRingSize != 0 {
			iface.GetVmxNet3().RxqSize = uint32(ifConfig.Vmxnet3RxRingSize)
			iface.GetVmxNet3().TxqSize = uint32(ifConfig.Vmxnet3TxRingSize)
		}
	}
	if interfaceRxModeType(ifConfig.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		iface.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(ifConfig.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(name)
	return key, iface
}

// loopbackInterface returns configuration for loopback created when no physical interfaces
// are configured.
func (n *IPNet) loopbackInterface(ips contivconf.IPsWithNetworks) (key string, config *vpp_interfaces.Interface) {
	iface := &vpp_interfaces.Interface{
		Name:    loopbackNICLogicalName,
		Type:    vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = vpp_interfaces.InterfaceKey(loopbackNICLogicalName)
	return key, iface
}

// defaultRoute return configuration for default route connecting the node with the outside world.
func (n *IPNet) defaultRoute(gwIP net.IP, outIfName string) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		DstNetwork:        anyNetAddrForAF(gwIP),
		NextHopAddr:       gwIP.String(),
		OutgoingInterface: outIfName,
		VrfId:             n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/************************************ VRFs ************************************/

// vrfTablesForPods returns VRF tables for networking between pods.
func (n *IPNet) vrfTablesForPods() map[string]*vpp_l3.VrfTable {
	tables := make(map[string]*vpp_l3.VrfTable)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		v6 := &vpp_l3.VrfTable{
			Id:       routingCfg.PodVRFID,
			Protocol: vpp_l3.VrfTable_IPV6,
			Label:    "VRF-pods-ipv6",
		}
		v6Key := vpp_l3.VrfTableKey(v6.Id, v6.Protocol)
		tables[v6Key] = v6
	} else {
		v4 := &vpp_l3.VrfTable{
			Id:       routingCfg.PodVRFID,
			Protocol: vpp_l3.VrfTable_IPV4,
			Label:    "VRF-pods-ipv4",
		}
		v4Key := vpp_l3.VrfTableKey(v4.Id, v4.Protocol)
		tables[v4Key] = v4
	}

	return tables
}

// routesPodToMainVRF returns non-drop routes from Pod VRF to Main VRF.
func (n *IPNet) routesPodToMainVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// by default to go from Pod VRF via Main VRF
	r1 := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  anyNetAddrForAF(n.IPAM.PodGatewayIP()),
		VrfId:       routingCfg.PodVRFID,
		ViaVrfId:    routingCfg.MainVRFID,
		NextHopAddr: anyAddrForAF(n.IPAM.PodGatewayIP()),
	}
	r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	if !routingCfg.UseNoOverlay {
		// host network (this node) routed from Pod VRF via Main VRF
		// (only needed for overly mode (VXLAN), to have better prefix match so that the drop route is not in effect)
		r2 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.HostInterconnectSubnetThisNode().String(),
			VrfId:       routingCfg.PodVRFID,
			ViaVrfId:    routingCfg.MainVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.HostInterconnectSubnetThisNode().IP),
		}
		r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
		routes[r2Key] = r2
	}

	return routes
}

// routesMainToPodVRF returns non-drop routes from Main VRF to Pod VRF.
func (n *IPNet) routesMainToPodVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if !routingCfg.UseNoOverlay {
		// pod subnet (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.PodSubnetAllNodes().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.PodSubnetAllNodes().IP),
		}
		r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
		routes[r1Key] = r1

		// host network (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
		r2 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.HostInterconnectSubnetAllNodes().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.HostInterconnectSubnetAllNodes().IP),
		}
		r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
		routes[r2Key] = r2
	} else {
		// pod subnet (this node only) routed from Main VRF to Pod VRF
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.PodSubnetThisNode().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.PodSubnetThisNode().IP),
		}
		r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
		routes[r1Key] = r1
	}

	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		// service subnet routed from Main VRF to Pod VRF
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.ServiceNetwork().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.ServiceNetwork().IP),
		}
		r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
		routes[r1Key] = r1
	}

	return routes
}

// dropRoutesIntoPodVRF returns drop routes for Pod VRF.
func (n *IPNet) dropRoutesIntoPodVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		// drop packets destined to service subnet with no more specific routes
		r1 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.ServiceNetwork())
		r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
		routes[r1Key] = r1
	}

	if !routingCfg.UseNoOverlay {
		// drop packets destined to pods no longer deployed
		r1 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.PodSubnetAllNodes())
		r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
		routes[r1Key] = r1

		// drop packets destined to nodes no longer deployed
		r2 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.HostInterconnectSubnetAllNodes())
		r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
		routes[r2Key] = r2
	}

	return routes
}

// dropRoute is a helper method to construct drop route.
func (n *IPNet) dropRoute(vrfID uint32, dstAddr *net.IPNet) *vpp_l3.Route {
	return &vpp_l3.Route{
		Type:        vpp_l3.Route_DROP,
		DstNetwork:  dstAddr.String(),
		VrfId:       vrfID,
		NextHopAddr: anyAddrForAF(dstAddr.IP),
	}
}

// podGwLoopback returns configuration of the loopback interface used in the POD VRF
// to respond on POD gateway IP address.
func (n *IPNet) podGwLoopback() (key string, config *vpp_interfaces.Interface) {
	lo := &vpp_interfaces.Interface{
		Name:        podGwLoopbackInterfaceName,
		Type:        vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(n.IPAM.PodGatewayIP(), n.IPAM.PodSubnetThisNode()))},
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
	}
	key = vpp_interfaces.InterfaceKey(lo.Name)
	return key, lo
}

/************************** Bridge Domain with VXLANs **************************/

// vxlanBVILoopback returns configuration of the loopback interfaces acting as BVI
// for the bridge domain with VXLAN interfaces.
func (n *IPNet) vxlanBVILoopback() (key string, config *vpp_interfaces.Interface, err error) {
	vxlanIP, vxlanIPNet, err := n.IPAM.VxlanIPAddress(n.NodeSync.GetNodeID())
	if err != nil {
		return "", nil, err
	}
	vxlan := &vpp_interfaces.Interface{
		Name:        VxlanBVIInterfaceName,
		Type:        vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(vxlanIP, vxlanIPNet))},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), vxlanBVIHwAddrPrefix),
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
	}
	key = vpp_interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan, nil
}

// vxlanBridgeDomain returns configuration for the bridge domain with VXLAN interfaces.
func (n *IPNet) vxlanBridgeDomain() (key string, config *vpp_l2.BridgeDomain) {
	bd := &vpp_l2.BridgeDomain{
		Name:                vxlanBDName,
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*vpp_l2.BridgeDomain_Interface{
			{
				Name:                    VxlanBVIInterfaceName,
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
			bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
				Name:              n.nameForVxlanToOtherNode(node.ID),
				SplitHorizonGroup: vxlanSplitHorizonGroup,
			})
		}
	}
	key = vpp_l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// nameForVxlanToOtherNode returns logical name to use for VXLAN interface
// connecting this node with the given other node.
func (n *IPNet) nameForVxlanToOtherNode(otherNodeID uint32) string {
	return fmt.Sprintf("vxlan%d", otherNodeID)
}

// vxlanIfToOtherNode returns configuration for VXLAN interface connecting this node
// with the given other node.
func (n *IPNet) vxlanIfToOtherNode(otherNodeID uint32, otherNodeIP net.IP) (key string, config *vpp_interfaces.Interface) {
	vxlan := &vpp_interfaces.Interface{
		Name: n.nameForVxlanToOtherNode(otherNodeID),
		Type: vpp_interfaces.Interface_VXLAN_TUNNEL,
		Link: &vpp_interfaces.Interface_Vxlan{
			Vxlan: &vpp_interfaces.VxlanLink{
				SrcAddress: n.nodeIP.String(),
				DstAddress: otherNodeIP.String(),
				Vni:        vxlanVNI,
			},
		},
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = vpp_interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan
}

// vxlanArpEntry returns configuration for ARP entry resolving hardware address
// of the VXLAN BVI interface of another node.
func (n *IPNet) vxlanArpEntry(otherNodeID uint32, vxlanIP net.IP) (key string, config *vpp_l3.ARPEntry) {
	arp := &vpp_l3.ARPEntry{
		Interface:   VxlanBVIInterfaceName,
		IpAddress:   vxlanIP.String(),
		PhysAddress: hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vxlanFibEntry returns configuration for L2 FIB used inside the bridge domain with VXLANs
// to route traffic destinated to the given other node through the right VXLAN interface.
func (n *IPNet) vxlanFibEntry(otherNodeID uint32) (key string, config *vpp_l2.FIBEntry) {
	fib := &vpp_l2.FIBEntry{
		BridgeDomain:            vxlanBDName,
		PhysAddress:             hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		OutgoingInterface:       n.nameForVxlanToOtherNode(otherNodeID),
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  vpp_l2.FIBEntry_FORWARD,
	}
	key = vpp_l2.FIBKey(fib.BridgeDomain, fib.PhysAddress)
	return key, fib
}

// otherNodeIP calculates the (statically selected) IP address of the given other node
func (n *IPNet) otherNodeIP(otherNodeID uint32) (net.IP, error) {
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
func (n *IPNet) routeToOtherNodePods(otherNodeID uint32, nextHopIP net.IP) (key string, config *vpp_l3.Route, err error) {
	podNetwork, err := n.IPAM.PodSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to compute pod network for node ID %v, error: %v ", otherNodeID, err)
	}
	key, config = n.routeToOtherNodeNetworks(podNetwork, nextHopIP)
	return
}

// routeToOtherNodeHostStack returns configuration for route applied to traffic destined
// to the host stack of another node.
func (n *IPNet) routeToOtherNodeHostStack(otherNodeID uint32, nextHopIP net.IP) (key string, config *vpp_l3.Route, err error) {
	hostNetwork, err := n.IPAM.HostInterconnectSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", otherNodeID, err)
	}
	key, config = n.routeToOtherNodeNetworks(hostNetwork, nextHopIP)
	return
}

// routeToOtherNodeNetworks is a helper function to build route for traffic destined to another node.
func (n *IPNet) routeToOtherNodeNetworks(destNetwork *net.IPNet, nextHopIP net.IP) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP.String(),
	}
	if n.ContivConf.GetRoutingConfig().UseNoOverlay {
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		route.OutgoingInterface = VxlanBVIInterfaceName
		route.VrfId = n.ContivConf.GetRoutingConfig().PodVRFID
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIP returns configuration for route applied to traffic destined
// to a management IP of another node.
func (n *IPNet) routeToOtherNodeManagementIP(managementIP, nextHopIP net.IP) (key string, config *vpp_l3.Route) {
	if managementIP.Equal(nextHopIP) {
		return "", nil
	}
	route := &vpp_l3.Route{
		DstNetwork:  managementIP.String() + hostPrefixForAF(managementIP),
		NextHopAddr: nextHopIP.String(),
	}
	if n.ContivConf.GetRoutingConfig().UseNoOverlay {
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		route.OutgoingInterface = VxlanBVIInterfaceName
		route.VrfId = n.ContivConf.GetRoutingConfig().PodVRFID
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIPViaPodVRF returns configuration for route used
// in Main VRF to direct traffic destined to management IP of another node
// to go via Pod VRF (and then further via VXLANs).
func (n *IPNet) routeToOtherNodeManagementIPViaPodVRF(managementIP net.IP) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  managementIP.String() + hostPrefixForAF(managementIP),
		VrfId:       n.ContivConf.GetRoutingConfig().MainVRFID,
		ViaVrfId:    n.ContivConf.GetRoutingConfig().PodVRFID,
		NextHopAddr: anyAddrForAF(managementIP),
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}
