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
	"strings"

	"github.com/vishvananda/netlink"

	linux_intf "github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
)

/********** Global vswitch configuration **********/

// enabledIPNeighborScan returns configuration for enabled IP neighbor scanning
// (used to clean up old ARP entries).
func (s *remoteCNIserver) enabledIPNeighborScan() (key string, config *vpp_l3.IPScanNeighbor){
	return vpp_l3.IPScanNeighborKey,
		&vpp_l3.IPScanNeighbor{
			Mode:           vpp_l3.IPScanNeighbor_IPv4,
			ScanInterval:   uint32(s.config.IPNeighborScanInterval),
			StaleThreshold: uint32(s.config.IPNeighborStaleThreshold),
		}
}

/********** NICs **********/

// physicalInterface returns configuration for physical interface - either the main interface
// connecting node with the rest of the cluster or an extra physical interface requested
// in the config file.
func (s *remoteCNIserver) physicalInterface(name string, ipAddress *net.IPNet) (key string, config *vpp_intf.Interface) {
	return vpp_intf.InterfaceKey(name),
		&vpp_intf.Interface{
			Name:        name,
			Type:        vpp_intf.Interface_ETHERNET_CSMACD,
			Enabled:     true,
			Vrf:         s.GetMainVrfID(),
			IpAddresses: []string{ipAddress.String()},
		}
}

// loopbackInterface returns configuration for loopback created when no physical interfaces
// are configured.
func (s *remoteCNIserver) loopbackInterface(ipAddress *net.IPNet) (key string, config *vpp_intf.Interface) {
	return vpp_intf.InterfaceKey(loopbackNICLogicalName),
		&vpp_intf.Interface{
			Name:        loopbackNICLogicalName,
			Type:        vpp_intf.Interface_SOFTWARE_LOOPBACK,
			Enabled:     true,
			Vrf:         s.GetMainVrfID(),
			IpAddresses: []string{ipAddress.String()},
		}
}

// defaultRoute return configuration for default route connecting the node with the outside world.
func (s *remoteCNIserver) defaultRoute(gwIP net.IP, outIfName string) (key string, config *vpp_l3.StaticRoute) {
	route := &vpp_l3.StaticRoute{
		DstNetwork:        ipv4NetAny,
		NextHopAddr:       gwIP.String(),
		OutgoingInterface: outIfName,
		VrfId:             s.GetMainVrfID(),
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/********** VPP <-> Host connectivity **********/

// hostInterconnectVPPIfName returns the logical name of the VPP-host interconnect
// interface on the VPP side.
func (s *remoteCNIserver) hostInterconnectVPPIfName() string {
	if s.config.UseTAPInterfaces {
		return HostInterconnectTAPinVPPLogicalName
	}
	return hostInterconnectAFPacketLogicalName
}

// interconnectTapVPP returns configuration for the VPP-side of the TAP interface
// connecting VPP with the host stack.
func (s *remoteCNIserver) interconnectTapVPP() (key string, config *vpp_intf.Interface) {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	tap := &vpp_intf.Interface{
		Name:    HostInterconnectTAPinVPPLogicalName,
		Type:    vpp_intf.Interface_TAP_INTERFACE,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
		Link: &vpp_intf.Interface_Tap{
			Tap: &vpp_intf.Interface_TapLink{},
		},
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
		PhysAddress: hwAddrForNodeInterface(s.ipam.NodeID(), hostInterconnectHwAddrPrefix),
	}
	if s.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(s.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(s.config.TAPv2TxRingSize)
	}
	key = vpp_intf.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectTapHost returns configuration for the Host-side of the TAP interface
// connecting VPP with the host stack.
func (s *remoteCNIserver) interconnectTapHost() (key string, config *linux_intf.LinuxInterface) {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	tap := &linux_intf.LinuxInterface{
		Name: HostInterconnectTAPinLinuxLogicalName,
		Type: linux_intf.LinuxInterface_TAP_TO_VPP,
		Link: &linux_intf.LinuxInterface_Tap{
			Tap: &linux_intf.LinuxInterface_TapLink{
				VppTapIfName: HostInterconnectTAPinVPPLogicalName,
			},
		},
		Mtu:         s.config.MTUSize,
		HostIfName:  HostInterconnectTAPinLinuxHostName,
		Enabled:     true,
		IpAddresses: []string{s.ipam.VEthHostEndIP().String() + "/" + strconv.Itoa(size)},
	}
	key = linux_intf.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectAfpacket returns configuration for the AF-Packet interface attached
// to interconnectVethVpp (see below)
func (s *remoteCNIserver) interconnectAfpacket() (key string, config *vpp_intf.Interface) {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	afpacket := &vpp_intf.Interface{
		Name: hostInterconnectAFPacketLogicalName,
		Type: vpp_intf.Interface_AF_PACKET_INTERFACE,
		Link: &vpp_intf.Interface_Afpacket{
			Afpacket: &vpp_intf.Interface_AfpacketLink{
				HostIfName: hostInterconnectVETH2HostName,
			},
		},
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetMainVrfID(),
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
		PhysAddress: hwAddrForNodeInterface(s.ipam.NodeID(), hostInterconnectHwAddrPrefix),
	}
	key = vpp_intf.InterfaceKey(afpacket.Name)
	return key, config
}

// interconnectVethVpp returns configuration for VPP-side of the VETH pipe connecting
// vswitch with the host stack.
func (s *remoteCNIserver) interconnectVethVpp() (key string, config *linux_intf.LinuxInterface) {
	veth := &linux_intf.LinuxInterface{
		Name: hostInterconnectVETH2LogicalName,
		Type: linux_intf.LinuxInterface_VETH,
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: hostInterconnectVETH1LogicalName},
		},
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH2HostName,
	}
	key = linux_intf.InterfaceKey(veth.Name)
	return key, veth
}

// interconnectVethHost returns configuration for host-side of the VETH pipe connecting
// vswitch with the host stack.
func (s *remoteCNIserver) interconnectVethHost() (key string, config *linux_intf.LinuxInterface) {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	veth := &linux_intf.LinuxInterface{
		Name: hostInterconnectVETH1LogicalName,
		Type: linux_intf.LinuxInterface_VETH,
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: hostInterconnectVETH2LogicalName},
		},
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  hostInterconnectVETH1HostName,
		IpAddresses: []string{s.ipam.VEthHostEndIP().String() + "/" + strconv.Itoa(size)},
	}
	key = linux_intf.InterfaceKey(veth.Name)
	return key, veth
}

// routesToHost return one route to configure on VPP for every host interface.
func (s *remoteCNIserver) routesToHost(nextHopIP net.IP) map[string]*vpp_l3.StaticRoute {
	routes := make(map[string]*vpp_l3.StaticRoute)
	// list all IPs assigned to host interfaces
	ips, err := s.getHostLinkIPs()
	if err != nil {
		s.Logger.Errorf("Error by listing host IPs: %v", err)
		return nil
	}

	// generate a /32 static route from VPP for each of the host's IPs
	for _, ip := range ips {
		route := &vpp_l3.StaticRoute{
			DstNetwork:        fmt.Sprintf("%s/32", ip.String()),
			NextHopAddr:       nextHopIP.String(),
			OutgoingInterface: s.hostInterconnectVPPIfName(),
			VrfId:             s.GetMainVrfID(),
		}
		key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// routePODsFromHost returns configuration for route for the host stack to direct
// traffic destined to pods via VPP.
func (s *remoteCNIserver) routePODsFromHost(nextHopIP net.IP) (key string, config *linux_l3.LinuxStaticRoute) {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.LinuxStaticRoute_GLOBAL,
		DstNetwork:        s.ipam.PodSubnet().String(),
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
func (s *remoteCNIserver) routeServicesFromHost(nextHopIP net.IP) (key string, config *linux_l3.LinuxStaticRoute) {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.LinuxStaticRoute_GLOBAL,
		DstNetwork:        s.ipam.ServiceNetwork().String(),
		GwAddr:            nextHopIP.String(),
	}
	if s.config.UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/********** VRFs **********/

// routesPodToMainVRF returns non-drop routes from Pod VRF to Main VRF.
func (s *remoteCNIserver) routesPodToMainVRF() map[string]*vpp_l3.StaticRoute {
	routes := make(map[string]*vpp_l3.StaticRoute)

	// by default to go from Pod VRF via Main VRF
	r1 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: ipv4NetAny,
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Pod VRF via Main VRF
	r2 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.VPPHostNetwork().String(),
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// routesMainToPodVRF returns non-drop routes from Main VRF to Pod VRF.
func (s *remoteCNIserver) routesMainToPodVRF() map[string]*vpp_l3.StaticRoute {
	routes := make(map[string]*vpp_l3.StaticRoute)

	// pod subnet (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r1 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.PodSubnet().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// host network (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
	r2 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.VPPHostSubnet().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2
	return routes
}

// dropRoutesIntoPodVRF returns drop routes for Pod VRF.
func (s *remoteCNIserver) dropRoutesIntoPodVRF() map[string]*vpp_l3.StaticRoute {
	routes := make(map[string]*vpp_l3.StaticRoute)

	// drop packets destined to pods no longer deployed
	r1 := s.dropRoute(s.GetPodVrfID(), s.ipam.PodSubnet())
	r1Key := vpp_l3.RouteKey(r1.VrfId, r1.DstNetwork, r1.NextHopAddr)
	routes[r1Key] = r1

	// drop packets destined to nodes no longer deployed
	r2 := s.dropRoute(s.GetPodVrfID(), s.ipam.VPPHostSubnet())
	r2Key := vpp_l3.RouteKey(r2.VrfId, r2.DstNetwork, r2.NextHopAddr)
	routes[r2Key] = r2

	return routes
}

// dropRoute is a helper method to construct drop route.
func (s *remoteCNIserver) dropRoute(vrfID uint32, dstAddr *net.IPNet) *vpp_l3.StaticRoute {
	return &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_DROP,
		DstNetwork: dstAddr.String(),
		VrfId:      vrfID,
	}
}

/********** Bridge Domain with VXLANs **********/

// vxlanBVILoopback returns configuration of the loopback interfaces acting as BVI
// for the bridge domain with VXLAN interfaces.
func (s *remoteCNIserver) vxlanBVILoopback() (key string, config *vpp_intf.Interface, err error) {
	vxlanIP, err := s.ipam.VxlanIPWithPrefix(s.ipam.NodeID())
	if err != nil {
		return "", nil, err
	}
	vxlan := &vpp_intf.Interface{
		Name:        vxlanBVIInterfaceName,
		Type:        vpp_intf.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{vxlanIP.String()},
		PhysAddress: hwAddrForNodeInterface(s.ipam.NodeID(), vxlanBVIHwAddrPrefix),
		Vrf:         s.GetPodVrfID(),
	}
	key = vpp_intf.InterfaceKey(vxlan.Name)
	return key, vxlan, nil
}

// vxlanBridgeDomain returns configuration for the bridge domain with VXLAN interfaces.
func (s *remoteCNIserver) vxlanBridgeDomain() (key string, config *vpp_l2.BridgeDomain) {
	bd := &vpp_l2.BridgeDomain{
		Name:                vxlanBDName,
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*vpp_l2.BridgeDomain_Interface{
			{
				Name:                    vxlanBVIInterfaceName,
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
	for otherNodeID := range s.otherNodes {
		bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
			Name:              s.nameForVxlanToOtherNode(otherNodeID),
			SplitHorizonGroup: vxlanSplitHorizonGroup,
		})
	}
	key = vpp_l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// nameForVxlanToOtherNode returns logical name to use for VXLAN interface
// connecting this node with the given other node.
func (s *remoteCNIserver) nameForVxlanToOtherNode(otherNodeID uint32) string {
	return fmt.Sprintf("vxlan%d", otherNodeID)
}

// vxlanIfToOtherNode returns configuration for VXLAN interface connecting this node
// with the given other node.
func (s *remoteCNIserver) vxlanIfToOtherNode(otherNodeID uint32, otherNodeIP net.IP) (key string, config *vpp_intf.Interface) {
	vxlan := &vpp_intf.Interface{
		Name: s.nameForVxlanToOtherNode(otherNodeID),
		Type: vpp_intf.Interface_VXLAN_TUNNEL,
		Link: &vpp_intf.Interface_Vxlan{
			Vxlan: &vpp_intf.Interface_VxlanLink{
				SrcAddress: s.nodeIP.String(),
				DstAddress: otherNodeIP.String(),
				Vni:        vxlanVNI,
			},
		},
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
	}
	key = vpp_intf.InterfaceKey(vxlan.Name)
	return key, vxlan
}

// vxlanArpEntry returns configuration for ARP entry resolving hardware address
// of the VXLAN BVI interface of another node.
func (s *remoteCNIserver) vxlanArpEntry(otherNodeID uint32, vxlanIP net.IP) (key string, config *vpp_l3.ARPEntry) {
	arp := &vpp_l3.ARPEntry{
		Interface:   vxlanBVIInterfaceName,
		IpAddress:   vxlanIP.String(),
		PhysAddress: hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vxlanFibEntry returns configuration for L2 FIB used inside the bridge domain with VXLANs
// to route traffic destinated to the given other node through the right VXLAN interface.
func (s *remoteCNIserver) vxlanFibEntry(otherNodeID uint32) (key string, config *vpp_l2.FIBEntry) {
	fib := &vpp_l2.FIBEntry{
		BridgeDomain:            vxlanBDName,
		PhysAddress:             hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		OutgoingInterface:       s.nameForVxlanToOtherNode(otherNodeID),
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  vpp_l2.FIBEntry_FORWARD,
	}
	key = vpp_l2.FIBKey(fib.BridgeDomain, fib.PhysAddress)
	return key, fib
}

// otherNodeIP calculates the IP address of the given other node or just trims the mask
// from the provided one.
func (s *remoteCNIserver) otherNodeIP(otherNodeID uint32, otherNodeIPNet string) (net.IP, error) {
	if otherNodeIPNet != "" {
		// otherNodeIPNet defined, just remove the mask
		nodeIP, _, err := net.ParseCIDR(otherNodeIPNet)
		if err != nil {
			err := fmt.Errorf("Failed to parse Node IP address for node ID %v: %v",
				otherNodeID, err)
			s.Logger.Error(err)
			return nodeIP, err
		}
		return nodeIP, nil
	}

	// otherNodeIPNet not defined, determine based on otherNodeID
	nodeIP, err := s.ipam.NodeIPAddress(otherNodeID)
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
func (s *remoteCNIserver) routeToOtherNodePods(otherNodeID uint32, nextHopIP net.IP) (key string, config *vpp_l3.StaticRoute, err error) {
	podNetwork, err := s.ipam.OtherNodePodNetwork(otherNodeID)
	if err != nil {
		return "",nil, fmt.Errorf("Failed to compute pod network for node ID %v, error: %v ", otherNodeID, err)
	}
	key, config = s.routeToOtherNodeNetworks(podNetwork, nextHopIP)
	return
}

// routeToOtherNodeHostStack returns configuration for route applied to traffic destined
// to the host stack of another node.
func (s *remoteCNIserver) routeToOtherNodeHostStack(otherNodeID uint32, nextHopIP net.IP) (key string, config *vpp_l3.StaticRoute, err error) {
	hostNetwork, err := s.ipam.OtherNodeVPPHostNetwork(otherNodeID)
	if err != nil {
		return "", nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", otherNodeID, err)
	}
	key, config = s.routeToOtherNodeNetworks(hostNetwork, nextHopIP)
	return
}

// routeToOtherNodeNetworks is a helper function to build route for traffic destined to another node.
func (s *remoteCNIserver) routeToOtherNodeNetworks(destNetwork *net.IPNet, nextHopIP net.IP) (key string, config *vpp_l3.StaticRoute) {
	route := &vpp_l3.StaticRoute{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP.String(),
	}
	if s.config.UseL2Interconnect {
		route.VrfId = s.GetMainVrfID()
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = s.GetPodVrfID()
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, config
}

// routeToOtherNodeManagementIP returns configuration for route applied to traffic destined
// to a management IP of another node.
func (s *remoteCNIserver) routeToOtherNodeManagementIP(managementIP, nextHopIP net.IP) (key string, config *vpp_l3.StaticRoute) {
	route := &vpp_l3.StaticRoute{
		DstNetwork:  managementIP.String() + "/32",
		NextHopAddr: nextHopIP.String(),
	}
	if s.config.UseL2Interconnect {
		route.VrfId = s.GetMainVrfID()
	} else {
		route.OutgoingInterface = vxlanBVIInterfaceName
		route.VrfId = s.GetPodVrfID()
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// routeToOtherNodeManagementIPViaPodVRF returns configuration for route used
// in Main VRF to direct traffic destined to management IP of another node
// to go via Pod VRF (and then further via VXLANs).
func (s *remoteCNIserver) routeToOtherNodeManagementIPViaPodVRF(managementIP net.IP) (key string, config *vpp_l3.StaticRoute) {
	route := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: managementIP.String() + "/32",
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/********** Host IP addresses **********/

func (s *remoteCNIserver) getHostLinkIPs() ([]net.IP, error) {
	if s.hostIPs != nil {
		return s.hostIPs, nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		s.Logger.Error("Unable to list host links:", err)
		return nil, err
	}

	s.hostIPs = make([]net.IP, 0)
	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") && !strings.HasPrefix(l.Attrs().Name, "docker") &&
			!strings.HasPrefix(l.Attrs().Name, "virbr") && !strings.HasPrefix(l.Attrs().Name, "vpp") {
			// not a virtual interface, list its IP addresses
			addrList, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				s.Logger.Error("Unable to list link IPs:", err)
				return nil, err
			}
			// return all IPs
			for _, addr := range addrList {
				s.hostIPs = append(s.hostIPs, addr.IP)
			}
		}
	}
	return s.hostIPs, nil
}