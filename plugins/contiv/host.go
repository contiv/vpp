// Copyright (c) 2017 Cisco and/or its affiliates.
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

package contiv

import (
	"fmt"
	"net"
	"strconv"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/stn"
)

/*********************** Global vswitch configuration *************************/

// enabledIPNeighborScan returns configuration for enabled IP neighbor scanning
// (used to clean up old ARP entries).
func (s *remoteCNIserver) enabledIPNeighborScan() (key string, config *l3.IPScanNeighbor) {
	config = &l3.IPScanNeighbor{
		Mode:           l3.IPScanNeighbor_IPv4,
		ScanInterval:   uint32(s.config.IPNeighborScanInterval),
		StaleThreshold: uint32(s.config.IPNeighborStaleThreshold),
	}
	key = l3.IPScanNeighborKey
	return key, config
}

/************************************ NICs ************************************/

// physicalInterface returns configuration for physical interface - either the main interface
// connecting node with the rest of the cluster or an extra physical interface requested
// in the config file.
func (s *remoteCNIserver) physicalInterface(name string, ips []*nodesync.IPWithNetwork) (key string, config *interfaces.Interface) {
	iface := &interfaces.Interface{
		Name:    name,
		Type:    interfaces.Interface_DPDK,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = interfaces.InterfaceKey(name)
	return key, iface
}

// loopbackInterface returns configuration for loopback created when no physical interfaces
// are configured.
func (s *remoteCNIserver) loopbackInterface(ips []*nodesync.IPWithNetwork) (key string, config *interfaces.Interface) {
	iface := &interfaces.Interface{
		Name:    loopbackNICLogicalName,
		Type:    interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = interfaces.InterfaceKey(loopbackNICLogicalName)
	return key, iface
}

// defaultRoute return configuration for default route connecting the node with the outside world.
func (s *remoteCNIserver) defaultRoute(gwIP net.IP, outIfName string) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:        ipv4NetAny,
		NextHopAddr:       gwIP.String(),
		OutgoingInterface: outIfName,
		VrfId:             s.GetMainVrfID(),
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/************************** VPP <-> Host connectivity **************************/

// hostInterconnectVPPIfName returns the logical name of the VPP-host interconnect
// interface on the VPP side.
func (s *remoteCNIserver) hostInterconnectVPPIfName() string {
	if s.config.UseTAPInterfaces {
		return HostInterconnectTAPinVPPLogicalName
	}
	return hostInterconnectAFPacketLogicalName
}

// hostInterconnectLinuxIfName returns the logical name of the VPP-host interconnect
// interface on the Linux side.
func (s *remoteCNIserver) hostInterconnectLinuxIfName() string {
	if s.config.UseTAPInterfaces {
		return HostInterconnectTAPinLinuxLogicalName
	}
	return hostInterconnectVETH1LogicalName
}

// interconnectTapVPP returns configuration for the VPP-side of the TAP interface
// connecting VPP with the host stack.
func (s *remoteCNIserver) interconnectTapVPP() (key string, config *interfaces.Interface) {
	size, _ := s.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &interfaces.Interface{
		Name:    HostInterconnectTAPinVPPLogicalName,
		Type:    interfaces.Interface_TAP,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{},
		},
		PhysAddress: hwAddrForNodeInterface(s.nodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	if s.UseSTN() {
		tap.Unnumbered = &interfaces.Interface_Unnumbered{
			InterfaceWithIp: s.mainPhysicalIf,
		}
	} else {
		tap.IpAddresses = []string{s.ipam.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)}

	}
	if s.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(s.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(s.config.TAPv2TxRingSize)
	}
	key = interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectTapHost returns configuration for the Host-side of the TAP interface
// connecting VPP with the host stack.
func (s *remoteCNIserver) interconnectTapHost() (key string, config *linux_interfaces.Interface) {
	size, _ := s.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &linux_interfaces.Interface{
		Name: HostInterconnectTAPinLinuxLogicalName,
		Type: linux_interfaces.Interface_TAP_TO_VPP,
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: HostInterconnectTAPinVPPLogicalName,
			},
		},
		Mtu:        s.config.MTUSize,
		HostIfName: HostInterconnectTAPinLinuxHostName,
		Enabled:    true,
	}
	if s.UseSTN() {
		if len(s.nodeIP) > 0 {
			tap.IpAddresses = []string{combineAddrWithNet(s.nodeIP, s.nodeIPNet).String()}
		}
	} else {
		tap.IpAddresses = []string{s.ipam.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)}
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectAfpacket returns configuration for the AF-Packet interface attached
// to interconnectVethVpp (see below)
func (s *remoteCNIserver) interconnectAfpacket() (key string, config *interfaces.Interface) {
	size, _ := s.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	afpacket := &interfaces.Interface{
		Name: hostInterconnectAFPacketLogicalName,
		Type: interfaces.Interface_AF_PACKET,
		Link: &interfaces.Interface_Afpacket{
			Afpacket: &interfaces.AfpacketLink{
				HostIfName: hostInterconnectVETH2HostName,
			},
		},
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetMainVrfID(),
		IpAddresses: []string{s.ipam.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)},
		PhysAddress: hwAddrForNodeInterface(s.nodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	key = interfaces.InterfaceKey(afpacket.Name)
	return key, afpacket
}

// interconnectVethVpp returns configuration for VPP-side of the VETH pipe connecting
// vswitch with the host stack.
func (s *remoteCNIserver) interconnectVethVpp() (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name: hostInterconnectVETH2LogicalName,
		Type: linux_interfaces.Interface_VETH,
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: hostInterconnectVETH1LogicalName},
		},
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH2HostName,
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// interconnectVethHost returns configuration for host-side of the VETH pipe connecting
// vswitch with the host stack.
func (s *remoteCNIserver) interconnectVethHost() (key string, config *linux_interfaces.Interface) {
	size, _ := s.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	veth := &linux_interfaces.Interface{
		Name: hostInterconnectVETH1LogicalName,
		Type: linux_interfaces.Interface_VETH,
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: hostInterconnectVETH2LogicalName},
		},
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  hostInterconnectVETH1HostName,
		IpAddresses: []string{s.ipam.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)},
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// routesToHost return one route to configure on VPP for every host interface.
func (s *remoteCNIserver) routesToHost(nextHopIP net.IP) map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	// generate a /32 static route from VPP for each of the host's IPs
	for _, ip := range s.hostIPs {
		route := &l3.StaticRoute{
			DstNetwork:        fmt.Sprintf("%s/32", ip.String()),
			NextHopAddr:       nextHopIP.String(),
			OutgoingInterface: s.hostInterconnectVPPIfName(),
			VrfId:             s.GetMainVrfID(),
		}
		key := l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// routePODsFromHost returns configuration for route for the host stack to direct
// traffic destined to pods via VPP.
func (s *remoteCNIserver) routePODsFromHost(nextHopIP net.IP) (key string, config *linux_l3.StaticRoute) {
	route := &linux_l3.StaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		DstNetwork:        s.ipam.PodSubnetAllNodes().String(),
		GwAddr:            nextHopIP.String(),
	}
	if s.config.UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// routeServicesFromHost returns configuration for route for the host stack to direct
// traffic destined to services via VPP.
func (s *remoteCNIserver) routeServicesFromHost(nextHopIP net.IP) (key string, config *linux_l3.StaticRoute) {
	route := &linux_l3.StaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		DstNetwork:        s.ipam.ServiceNetwork().String(),
		GwAddr:            nextHopIP.String(),
	}
	if s.config.UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/************************************ STN *************************************/

// stnRule returns configuration for STN rule, used to forward all traffic not matched
// in VPP to host via interconnect interface.
// The method assumes that node has IP address allocated!
func (s *remoteCNIserver) stnRule() (key string, config *stn.Rule) {
	rule := &stn.Rule{
		IpAddress: s.nodeIP.String(),
		Interface: s.hostInterconnectVPPIfName(),
	}
	key = stn.Key(rule.Interface, rule.IpAddress)
	return key, rule
}

// proxyArpForSTNGateway configures proxy ARP used in the STN case to let VPP to answer
// to ARP requests coming from the host stack.
func (s *remoteCNIserver) proxyArpForSTNGateway() (key string, config *l3.ProxyARP) {
	firstIP, lastIP := cidr.AddressRange(s.nodeIPNet)

	// If larger than a /31, remove network and broadcast addresses
	// from address range.
	if cidr.AddressCount(s.nodeIPNet) > 2 {
		firstIP = cidr.Inc(firstIP)
		lastIP = cidr.Dec(lastIP)
	}

	proxyarp := &l3.ProxyARP{
		Interfaces: []*l3.ProxyARP_Interface{
			{Name: s.hostInterconnectVPPIfName()},
		},
		Ranges: []*l3.ProxyARP_Range{
			{
				FirstIpAddr: firstIP.String(),
				LastIpAddr:  lastIP.String(),
			},
		},
	}
	key = l3.ProxyARPKey
	return key, proxyarp
}

// stnRoutesForVPP returns VPP routes mirroring Host routes that were associated
// with the stolen interface.
func (s *remoteCNIserver) stnRoutesForVPP() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	for _, stnRoute := range s.stnRoutes {
		route := &l3.StaticRoute{
			DstNetwork:        stnRoute.DestinationSubnet,
			NextHopAddr:       stnRoute.NextHopIp,
			OutgoingInterface: s.mainPhysicalIf,
			VrfId:             s.GetMainVrfID(),
		}
		key := l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// stnRoutesForHost returns configuration of routes that were associated
// with the stolen interface, now updated to route via host-interconnect.
func (s *remoteCNIserver) stnRoutesForHost() map[string]*linux_l3.StaticRoute {
	routes := make(map[string]*linux_l3.StaticRoute)

	for _, stnRoute := range s.stnRoutes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &linux_l3.StaticRoute{
			DstNetwork:        stnRoute.DestinationSubnet,
			GwAddr:            stnRoute.NextHopIp,
			Scope:             linux_l3.StaticRoute_GLOBAL,
			OutgoingInterface: s.hostInterconnectLinuxIfName(),
		}
		if route.DstNetwork == "" {
			route.DstNetwork = ipv4NetAny
		}
		key := linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
		routes[key] = route
	}

	return routes
}

/************************************ VRFs ************************************/

// routesPodToMainVRF returns non-drop routes from Pod VRF to Main VRF.
func (s *remoteCNIserver) routesPodToMainVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	// by default to go from Pod VRF via Main VRF
	r1 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: ipv4NetAny,
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Pod VRF via Main VRF
	r2 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.HostInterconnectSubnetThisNode().String(),
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// routesMainToPodVRF returns non-drop routes from Main VRF to Pod VRF.
func (s *remoteCNIserver) routesMainToPodVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	// pod subnet (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r1 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.PodSubnetAllNodes().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r2 := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.HostInterconnectSubnetAllNodes().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// dropRoutesIntoPodVRF returns drop routes for Pod VRF.
func (s *remoteCNIserver) dropRoutesIntoPodVRF() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	// drop packets destined to pods no longer deployed
	r1 := s.dropRoute(s.GetPodVrfID(), s.ipam.PodSubnetAllNodes())
	r1Key := l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// drop packets destined to nodes no longer deployed
	r2 := s.dropRoute(s.GetPodVrfID(), s.ipam.HostInterconnectSubnetAllNodes())
	r2Key := l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2

	return routes
}

// dropRoute is a helper method to construct drop route.
func (s *remoteCNIserver) dropRoute(vrfID uint32, dstAddr *net.IPNet) *l3.StaticRoute {
	return &l3.StaticRoute{
		Type:       l3.StaticRoute_DROP,
		DstNetwork: dstAddr.String(),
		VrfId:      vrfID,
	}
}

/************************** Bridge Domain with VXLANs **************************/

// vxlanBVILoopback returns configuration of the loopback interfaces acting as BVI
// for the bridge domain with VXLAN interfaces.
func (s *remoteCNIserver) vxlanBVILoopback() (key string, config *interfaces.Interface, err error) {
	vxlanIP, vxlanIPNet, err := s.ipam.VxlanIPAddress(s.nodeSync.GetNodeID())
	if err != nil {
		return "", nil, err
	}
	vxlan := &interfaces.Interface{
		Name:        vxlanBVIInterfaceName,
		Type:        interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(vxlanIP, vxlanIPNet))},
		PhysAddress: hwAddrForNodeInterface(s.nodeSync.GetNodeID(), vxlanBVIHwAddrPrefix),
		Vrf:         s.GetPodVrfID(),
	}
	key = interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan, nil
}

// vxlanBridgeDomain returns configuration for the bridge domain with VXLAN interfaces.
func (s *remoteCNIserver) vxlanBridgeDomain() (key string, config *l2.BridgeDomain) {
	bd := &l2.BridgeDomain{
		Name:                vxlanBDName,
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*l2.BridgeDomain_Interface{
			{
				Name:                    vxlanBVIInterfaceName,
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
	if len(s.nodeIP) > 0 {
		for _, node := range s.nodeSync.GetAllNodes() {
			if node.Name == s.agentLabel {
				// skip this node
				continue
			}
			if !nodeHasIPAddress(node) {
				// skip node without IP address
			}
			bd.Interfaces = append(bd.Interfaces, &l2.BridgeDomain_Interface{
				Name:              s.nameForVxlanToOtherNode(node.ID),
				SplitHorizonGroup: vxlanSplitHorizonGroup,
			})
		}
	}
	key = l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// nameForVxlanToOtherNode returns logical name to use for VXLAN interface
// connecting this node with the given other node.
func (s *remoteCNIserver) nameForVxlanToOtherNode(otherNodeID uint32) string {
	return fmt.Sprintf("vxlan%d", otherNodeID)
}

// vxlanIfToOtherNode returns configuration for VXLAN interface connecting this node
// with the given other node.
func (s *remoteCNIserver) vxlanIfToOtherNode(otherNodeID uint32, otherNodeIP net.IP) (key string, config *interfaces.Interface) {
	vxlan := &interfaces.Interface{
		Name: s.nameForVxlanToOtherNode(otherNodeID),
		Type: interfaces.Interface_VXLAN_TUNNEL,
		Link: &interfaces.Interface_Vxlan{
			Vxlan: &interfaces.VxlanLink{
				SrcAddress: s.nodeIP.String(),
				DstAddress: otherNodeIP.String(),
				Vni:        vxlanVNI,
			},
		},
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
	}
	key = interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan
}

// vxlanArpEntry returns configuration for ARP entry resolving hardware address
// of the VXLAN BVI interface of another node.
func (s *remoteCNIserver) vxlanArpEntry(otherNodeID uint32, vxlanIP net.IP) (key string, config *l3.ARPEntry) {
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
func (s *remoteCNIserver) vxlanFibEntry(otherNodeID uint32) (key string, config *l2.FIBEntry) {
	fib := &l2.FIBEntry{
		BridgeDomain:            vxlanBDName,
		PhysAddress:             hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		OutgoingInterface:       s.nameForVxlanToOtherNode(otherNodeID),
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  l2.FIBEntry_FORWARD,
	}
	key = l2.FIBKey(fib.BridgeDomain, fib.PhysAddress)
	return key, fib
}

// otherNodeIP calculates the (statically selected) IP address of the given other node
func (s *remoteCNIserver) otherNodeIP(otherNodeID uint32) (net.IP, error) {
	nodeIP, _, err := s.ipam.NodeIPAddress(otherNodeID)
	if err != nil {
		err := fmt.Errorf("Failed to get Node IP address for node ID %v, error: %v ",
			otherNodeID, err)
		s.Logger.Error(err)
		return nodeIP, err
	}
	return nodeIP, nil
}

// routeToOtherNodePods returns configuration for route applied to traffic destined
// to pods of another node.
func (s *remoteCNIserver) routeToOtherNodePods(otherNodeID uint32, nextHopIP net.IP) (key string, config *l3.StaticRoute, err error) {
	podNetwork, err := s.ipam.PodSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to compute pod network for node ID %v, error: %v ", otherNodeID, err)
	}
	key, config = s.routeToOtherNodeNetworks(podNetwork, nextHopIP)
	return
}

// routeToOtherNodeHostStack returns configuration for route applied to traffic destined
// to the host stack of another node.
func (s *remoteCNIserver) routeToOtherNodeHostStack(otherNodeID uint32, nextHopIP net.IP) (key string, config *l3.StaticRoute, err error) {
	hostNetwork, err := s.ipam.HostInterconnectSubnetOtherNode(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", otherNodeID, err)
	}
	key, config = s.routeToOtherNodeNetworks(hostNetwork, nextHopIP)
	return
}

// routeToOtherNodeNetworks is a helper function to build route for traffic destined to another node.
func (s *remoteCNIserver) routeToOtherNodeNetworks(destNetwork *net.IPNet, nextHopIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP.String(),
	}
	if s.config.UseL2Interconnect {
		route.VrfId = s.GetMainVrfID()
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = s.GetPodVrfID()
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIP returns configuration for route applied to traffic destined
// to a management IP of another node.
func (s *remoteCNIserver) routeToOtherNodeManagementIP(managementIP, nextHopIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		DstNetwork:  managementIP.String() + "/32",
		NextHopAddr: nextHopIP.String(),
	}
	if s.config.UseL2Interconnect {
		route.VrfId = s.GetMainVrfID()
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = s.GetPodVrfID()
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIPViaPodVRF returns configuration for route used
// in Main VRF to direct traffic destined to management IP of another node
// to go via Pod VRF (and then further via VXLANs).
func (s *remoteCNIserver) routeToOtherNodeManagementIPViaPodVRF(managementIP net.IP) (key string, config *l3.StaticRoute) {
	route := &l3.StaticRoute{
		Type:       l3.StaticRoute_INTER_VRF,
		DstNetwork: managementIP.String() + "/32",
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}
