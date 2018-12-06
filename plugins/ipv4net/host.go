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

package ipv4net

import (
	"fmt"
	"net"
	"strconv"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/stn"
)

/* VPP - Host interconnect */
const (
	/* AF-PACKET + VETH */

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the host stack side of the pipe
	hostInterconnectVETH1LogicalName = "veth-vpp1"
	hostInterconnectVETH1HostName    = "vpp1"

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the VPP side of the pipe
	hostInterconnectVETH2LogicalName = "veth-vpp2"
	hostInterconnectVETH2HostName    = "vpp2"

	// logical name of the AF-packet interface attached to VETH2.
	hostInterconnectAFPacketLogicalName = "afpacket-vpp2"

	/* TAP */

	// HostInterconnectTAPinVPPLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - VPP side
	HostInterconnectTAPinVPPLogicalName = "tap-vpp2"

	// HostInterconnectTAPinLinuxLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - Linux side
	HostInterconnectTAPinLinuxLogicalName = "tap-vpp1"

	// HostInterconnectTAPinLinuxHostName is the physical name of the TAP interface
	// connecting host stack with VPP
	//  - the Linux side
	HostInterconnectTAPinLinuxHostName = "vpp1"

	/* STN */

	// MAC address of the TAP/veth interface connecting host stack with VPP - Linux side
	// VPP STN plugin can only send packets to this destination MAC
	hostInterconnectMACinLinuxSTN = "00:00:00:00:00:02"
)

// prefix for the hardware address of host interconnects
var hostInterconnectHwAddrPrefix = []byte{0x34, 0x3c}

/************************** VPP <-> Host connectivity **************************/

// hostInterconnectVPPIfName returns the logical name of the VPP-host interconnect
// interface on the VPP side.
func (n *IPv4Net) hostInterconnectVPPIfName() string {
	if n.config.UseTAPInterfaces {
		return HostInterconnectTAPinVPPLogicalName
	}
	return hostInterconnectAFPacketLogicalName
}

// hostInterconnectLinuxIfName returns the logical name of the VPP-host interconnect
// interface on the Linux side.
func (n *IPv4Net) hostInterconnectLinuxIfName() string {
	if n.config.UseTAPInterfaces {
		return HostInterconnectTAPinLinuxLogicalName
	}
	return hostInterconnectVETH1LogicalName
}

// interconnectTapVPP returns configuration for the VPP-side of the TAP interface
// connecting VPP with the host stack.
func (n *IPv4Net) interconnectTapVPP() (key string, config *interfaces.Interface) {
	size, _ := n.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &interfaces.Interface{
		Name:    HostInterconnectTAPinVPPLogicalName,
		Type:    interfaces.Interface_TAP,
		Mtu:     n.config.MTUSize,
		Enabled: true,
		Vrf:     n.GetMainVrfID(),
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{},
		},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	if n.InSTNMode() {
		tap.Unnumbered = &interfaces.Interface_Unnumbered{
			InterfaceWithIp: n.mainPhysicalIf,
		}
	} else {
		tap.IpAddresses = []string{n.ipam.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)}

	}
	if n.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(n.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(n.config.TAPv2TxRingSize)
	}
	key = interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectTapHost returns configuration for the Host-side of the TAP interface
// connecting VPP with the host stack.
func (n *IPv4Net) interconnectTapHost() (key string, config *linux_interfaces.Interface) {
	size, _ := n.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &linux_interfaces.Interface{
		Name: HostInterconnectTAPinLinuxLogicalName,
		Type: linux_interfaces.Interface_TAP_TO_VPP,
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: HostInterconnectTAPinVPPLogicalName,
			},
		},
		Mtu:        n.config.MTUSize,
		HostIfName: HostInterconnectTAPinLinuxHostName,
		Enabled:    true,
	}
	if n.InSTNMode() {
		// TODO: this specific MAC address can be removed after moving to the IP punt redirect instead of the STN plugin
		tap.PhysAddress = hostInterconnectMACinLinuxSTN

		if len(n.nodeIP) > 0 {
			tap.IpAddresses = []string{combineAddrWithNet(n.nodeIP, n.nodeIPNet).String()}
		}
	} else {
		tap.IpAddresses = []string{n.ipam.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)}
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectAfpacket returns configuration for the AF-Packet interface attached
// to interconnectVethVpp (see below)
func (n *IPv4Net) interconnectAfpacket() (key string, config *interfaces.Interface) {
	size, _ := n.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	afpacket := &interfaces.Interface{
		Name: hostInterconnectAFPacketLogicalName,
		Type: interfaces.Interface_AF_PACKET,
		Link: &interfaces.Interface_Afpacket{
			Afpacket: &interfaces.AfpacketLink{
				HostIfName: hostInterconnectVETH2HostName,
			},
		},
		Mtu:         n.config.MTUSize,
		Enabled:     true,
		Vrf:         n.GetMainVrfID(),
		IpAddresses: []string{n.ipam.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	key = interfaces.InterfaceKey(afpacket.Name)
	return key, afpacket
}

// interconnectVethVpp returns configuration for VPP-side of the VETH pipe connecting
// vswitch with the host stack.
func (n *IPv4Net) interconnectVethVpp() (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name: hostInterconnectVETH2LogicalName,
		Type: linux_interfaces.Interface_VETH,
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: hostInterconnectVETH1LogicalName},
		},
		Mtu:        n.config.MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH2HostName,
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// interconnectVethHost returns configuration for host-side of the VETH pipe connecting
// vswitch with the host stack.
func (n *IPv4Net) interconnectVethHost() (key string, config *linux_interfaces.Interface) {
	size, _ := n.ipam.HostInterconnectSubnetThisNode().Mask.Size()
	veth := &linux_interfaces.Interface{
		Name: hostInterconnectVETH1LogicalName,
		Type: linux_interfaces.Interface_VETH,
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: hostInterconnectVETH2LogicalName},
		},
		Mtu:        n.config.MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH1HostName,
	}
	if n.InSTNMode() {
		// TODO: this specific MAC address can be removed after moving to the IP punt redirect instead of the STN plugin
		veth.PhysAddress = hostInterconnectMACinLinuxSTN

		if len(n.nodeIP) > 0 {
			veth.IpAddresses = []string{combineAddrWithNet(n.nodeIP, n.nodeIPNet).String()}
		}
	} else {
		veth.IpAddresses = []string{n.ipam.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)}
	}
	if n.config.TCPChecksumOffloadDisabled {
		veth.GetVeth().RxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
		veth.GetVeth().TxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// routesToHost return one route to configure on VPP for every host interface.
func (n *IPv4Net) routesToHost(nextHopIP net.IP) map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	// generate a /32 static route from VPP for each of the host's IPs
	for _, ip := range n.hostIPs {
		route := &l3.StaticRoute{
			DstNetwork:        fmt.Sprintf("%s/32", ip.String()),
			NextHopAddr:       nextHopIP.String(),
			OutgoingInterface: n.hostInterconnectVPPIfName(),
			VrfId:             n.GetMainVrfID(),
		}
		key := l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// routePODsFromHost returns configuration for route for the host stack to direct
// traffic destined to pods via VPP.
func (n *IPv4Net) routePODsFromHost(nextHopIP net.IP) (key string, config *linux_l3.StaticRoute) {
	route := &linux_l3.StaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		DstNetwork:        n.ipam.PodSubnetAllNodes().String(),
		GwAddr:            nextHopIP.String(),
	}
	if n.config.UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// routeServicesFromHost returns configuration for route for the host stack to direct
// traffic destined to services via VPP.
func (n *IPv4Net) routeServicesFromHost(nextHopIP net.IP) (key string, config *linux_l3.StaticRoute) {
	route := &linux_l3.StaticRoute{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		DstNetwork:        n.ipam.ServiceNetwork().String(),
		GwAddr:            nextHopIP.String(),
	}
	if n.config.UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/************************************ STN *************************************/

// stnRule returns configuration for STN rule, used to forward all traffic not matched
// in VPP to host via interconnect interface.
// The method assumes that node has IP address allocated!
func (n *IPv4Net) stnRule() (key string, config *stn.Rule) {
	rule := &stn.Rule{
		IpAddress: n.nodeIP.String(),
		Interface: n.hostInterconnectVPPIfName(),
	}
	key = stn.Key(rule.Interface, rule.IpAddress)
	return key, rule
}

// proxyArpForSTNGateway configures proxy ARP used in the STN case to let VPP to answer
// to ARP requests coming from the host stack.
func (n *IPv4Net) proxyArpForSTNGateway() (key string, config *l3.ProxyARP) {
	firstIP, lastIP := cidr.AddressRange(n.nodeIPNet)

	// If larger than a /31, remove network and broadcast addresses
	// from address range.
	if cidr.AddressCount(n.nodeIPNet) > 2 {
		firstIP = cidr.Inc(firstIP)
		lastIP = cidr.Dec(lastIP)
	}

	proxyarp := &l3.ProxyARP{
		Interfaces: []*l3.ProxyARP_Interface{
			{Name: n.hostInterconnectVPPIfName()},
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
func (n *IPv4Net) stnRoutesForVPP() map[string]*l3.StaticRoute {
	routes := make(map[string]*l3.StaticRoute)

	for _, stnRoute := range n.stnRoutes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &l3.StaticRoute{
			DstNetwork:        stnRoute.DestinationSubnet,
			NextHopAddr:       stnRoute.NextHopIp,
			OutgoingInterface: n.mainPhysicalIf,
			VrfId:             n.GetMainVrfID(),
		}
		if route.DstNetwork == "" {
			route.DstNetwork = ipv4NetAny
		}
		key := l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// stnRoutesForHost returns configuration of routes that were associated
// with the stolen interface, now updated to route via host-interconnect.
func (n *IPv4Net) stnRoutesForHost() map[string]*linux_l3.StaticRoute {
	routes := make(map[string]*linux_l3.StaticRoute)

	for _, stnRoute := range n.stnRoutes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &linux_l3.StaticRoute{
			DstNetwork:        stnRoute.DestinationSubnet,
			GwAddr:            stnRoute.NextHopIp,
			Scope:             linux_l3.StaticRoute_GLOBAL,
			OutgoingInterface: n.hostInterconnectLinuxIfName(),
		}
		if route.DstNetwork == "" {
			route.DstNetwork = ipv4NetAny
		}
		key := linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
		routes[key] = route
	}

	return routes
}
