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
	"net"
	"strconv"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/punt"
	"github.com/ligato/vpp-agent/api/models/vpp/stn"
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
	// -required to be able to configure the static ARP towards linux on VPP in STN case
	// (dynamic ARP for an IP that is also assigned on VPP does not work)
	hostInterconnectMACinLinuxSTN = "00:00:00:00:00:02"
)

// prefix for the hardware address of host interconnects
var hostInterconnectHwAddrPrefix = []byte{0x34, 0x3c}

/************************** VPP <-> Host connectivity **************************/

// hostInterconnectVPPIfName returns the logical name of the VPP-host interconnect
// interface on the VPP side.
func (n *IPv4Net) hostInterconnectVPPIfName() string {
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		return HostInterconnectTAPinVPPLogicalName
	}
	return hostInterconnectAFPacketLogicalName
}

// hostInterconnectLinuxIfName returns the logical name of the VPP-host interconnect
// interface on the Linux side.
func (n *IPv4Net) hostInterconnectLinuxIfName() string {
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		return HostInterconnectTAPinLinuxLogicalName
	}
	return hostInterconnectVETH1LogicalName
}

// interconnectTapVPP returns configuration for the VPP-side of the TAP interface
// connecting VPP with the host stack.
func (n *IPv4Net) interconnectTapVPP() (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	size, _ := n.IPAM.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &vpp_interfaces.Interface{
		Name:    HostInterconnectTAPinVPPLogicalName,
		Type:    vpp_interfaces.Interface_TAP,
		Mtu:     interfaceCfg.MTUSize,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{},
		},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	if n.ContivConf.InSTNMode() {
		tap.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: n.ContivConf.GetMainInterfaceName(),
		}
	} else {
		tap.IpAddresses = []string{n.IPAM.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)}
	}
	if interfaceCfg.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(interfaceCfg.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(interfaceCfg.TAPv2TxRingSize)
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		tap.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectTapHost returns configuration for the Host-side of the TAP interface
// connecting VPP with the host stack.
func (n *IPv4Net) interconnectTapHost() (key string, config *linux_interfaces.Interface) {
	size, _ := n.IPAM.HostInterconnectSubnetThisNode().Mask.Size()
	tap := &linux_interfaces.Interface{
		Name: HostInterconnectTAPinLinuxLogicalName,
		Type: linux_interfaces.Interface_TAP_TO_VPP,
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: HostInterconnectTAPinVPPLogicalName,
			},
		},
		Mtu:        n.ContivConf.GetInterfaceConfig().MTUSize,
		HostIfName: HostInterconnectTAPinLinuxHostName,
		Enabled:    true,
	}
	if n.ContivConf.InSTNMode() {
		// static MAC for STN case - we need a static ARP entry towards Linux from VPP
		tap.PhysAddress = hostInterconnectMACinLinuxSTN

		if len(n.nodeIP) > 0 {
			if n.ContivConf.GetIPAMConfig().UseIPv6 {
				// For IPv6, we assign /127 subnet to the stolen interface
				// and set the other IP from that subnet as the gateway IP.
				// The original subnet is routed towards VPP in routeToOriginalSTNSubnet()
				tap.IpAddresses = []string{n.nodeIP.String() + "/127"}
			} else {
				tap.IpAddresses = []string{combineAddrWithNet(n.nodeIP, n.nodeIPNet).String()}
			}
		}
	} else {
		tap.IpAddresses = []string{n.IPAM.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)}
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// interconnectAfpacket returns configuration for the AF-Packet interface attached
// to interconnectVethVpp (see below)
func (n *IPv4Net) interconnectAfpacket() (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	size, _ := n.IPAM.HostInterconnectSubnetThisNode().Mask.Size()
	afpacket := &vpp_interfaces.Interface{
		Name: hostInterconnectAFPacketLogicalName,
		Type: vpp_interfaces.Interface_AF_PACKET,
		Link: &vpp_interfaces.Interface_Afpacket{
			Afpacket: &vpp_interfaces.AfpacketLink{
				HostIfName: hostInterconnectVETH2HostName,
			},
		},
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().MainVRFID,
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	if n.ContivConf.InSTNMode() {
		afpacket.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: n.ContivConf.GetMainInterfaceName(),
		}
	} else {
		afpacket.IpAddresses = []string{n.IPAM.HostInterconnectIPInVPP().String() + "/" + strconv.Itoa(size)}
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		afpacket.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(afpacket.Name)
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
		Mtu:        n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH2HostName,
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// interconnectVethHost returns configuration for host-side of the VETH pipe connecting
// vswitch with the host stack.
func (n *IPv4Net) interconnectVethHost() (key string, config *linux_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	size, _ := n.IPAM.HostInterconnectSubnetThisNode().Mask.Size()
	veth := &linux_interfaces.Interface{
		Name: hostInterconnectVETH1LogicalName,
		Type: linux_interfaces.Interface_VETH,
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: hostInterconnectVETH2LogicalName},
		},
		Mtu:        interfaceCfg.MTUSize,
		Enabled:    true,
		HostIfName: hostInterconnectVETH1HostName,
	}
	if n.ContivConf.InSTNMode() {
		// static MAC for STN case - we need a static ARP entry towards Linux from VPP
		veth.PhysAddress = hostInterconnectMACinLinuxSTN

		if len(n.nodeIP) > 0 {
			if n.ContivConf.GetIPAMConfig().UseIPv6 {
				// For IPv6, we assign /127 subnet to the stolen interface
				// and set the other IP from that subnet as the gateway IP.
				// The original subnet is routed towards VPP in routeToOriginalSTNSubnet()
				veth.IpAddresses = []string{n.nodeIP.String() + "/127"}
			} else {
				veth.IpAddresses = []string{combineAddrWithNet(n.nodeIP, n.nodeIPNet).String()}
			}
		}
	} else {
		veth.IpAddresses = []string{n.IPAM.HostInterconnectIPInLinux().String() + "/" + strconv.Itoa(size)}
	}
	if interfaceCfg.TCPChecksumOffloadDisabled {
		veth.GetVeth().RxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
		veth.GetVeth().TxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// routesToHost return one route to configure on VPP for every host interface.
func (n *IPv4Net) routesToHost(nextHopIP net.IP) map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)

	// generate a /32 (or /128 for ipv6) static route from VPP for each of the host's IPs
	for _, ip := range n.hostIPs {
		route := &vpp_l3.Route{
			DstNetwork:        ip.String() + hostPrefixForAF(ip),
			NextHopAddr:       nextHopIP.String(),
			OutgoingInterface: n.hostInterconnectVPPIfName(),
			VrfId:             n.ContivConf.GetRoutingConfig().MainVRFID,
		}
		key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// routePODsFromHost returns configuration for route for the host stack to direct
// traffic destined to pods via VPP.
func (n *IPv4Net) routePODsFromHost(nextHopIP net.IP) (key string, config *linux_l3.Route) {
	route := &linux_l3.Route{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.Route_GLOBAL,
		DstNetwork:        n.IPAM.PodSubnetAllNodes().String(),
		GwAddr:            nextHopIP.String(),
	}
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// routeServicesFromHost returns configuration for route for the host stack to direct
// traffic destined to services via VPP.
func (n *IPv4Net) routeServicesFromHost(nextHopIP net.IP) (key string, config *linux_l3.Route) {
	route := &linux_l3.Route{
		OutgoingInterface: hostInterconnectVETH1LogicalName,
		Scope:             linux_l3.Route_GLOBAL,
		DstNetwork:        n.IPAM.ServiceNetwork().String(),
		GwAddr:            nextHopIP.String(),
	}
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/************************************ STN *************************************/

// stnRule returns configuration for STN rule, used to forward all traffic not matched
// in VPP to host via interconnect interface.
// The method assumes that node has IP address allocated!
func (n *IPv4Net) stnRule() (key string, config *vpp_stn.Rule) {
	rule := &vpp_stn.Rule{
		IpAddress: n.nodeIP.String(),
		Interface: n.hostInterconnectVPPIfName(),
	}
	key = vpp_stn.Key(rule.Interface, rule.IpAddress)
	return key, rule
}

// ipRedirectRule returns configuration for ip_redirect flavor of STN rule, used to forward all traffic not matched
// in VPP to host via interconnect interface. in is another alternative of the stnRule() functionality.
// The method assumes that node has IP address allocated!
func (n *IPv4Net) ipRedirectRule() (key string, config *vpp_punt.IPRedirect) {
	rule := &vpp_punt.IPRedirect{
		L3Protocol:  vpp_punt.L3Protocol_ALL,
		TxInterface: n.hostInterconnectVPPIfName(),
		NextHop:     n.nodeIP.String(),
	}
	key = vpp_punt.IPRedirectKey(rule.L3Protocol, rule.TxInterface)
	return key, rule
}

// proxyArpForSTNGateway configures proxy ARP used in the STN case to let VPP to answer
// to ARP requests coming from the host stack.
func (n *IPv4Net) proxyArpForSTNGateway() (key string, config *vpp_l3.ProxyARP) {
	firstIP, lastIP := cidr.AddressRange(n.nodeIPNet)

	// If larger than a /31, remove network and broadcast addresses
	// from address range.
	if cidr.AddressCount(n.nodeIPNet) > 2 {
		firstIP = cidr.Inc(firstIP)
		lastIP = cidr.Dec(lastIP)
	}

	proxyarp := &vpp_l3.ProxyARP{
		Interfaces: []*vpp_l3.ProxyARP_Interface{
			{Name: n.hostInterconnectVPPIfName()},
		},
		Ranges: []*vpp_l3.ProxyARP_Range{
			{
				FirstIpAddr: firstIP.String(),
				LastIpAddr:  lastIP.String(),
			},
		},
	}
	key = vpp_l3.ProxyARPKey()
	return key, proxyarp
}

// staticArpForSTNGateway returns configuration of a static ARP entry for the host mapping
// the STN gateway IP to VPP MAC address.
func (n *IPv4Net) staticArpForSTNGateway() (key string, arp *linux_l3.ARPEntry) {
	arp = &linux_l3.ARPEntry{
		Interface: HostInterconnectTAPinLinuxLogicalName,
		IpAddress: n.stnGwIPForHost().String(),
		HwAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), hostInterconnectHwAddrPrefix),
	}
	key = linux_l3.ArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// staticArpForSTNHostInterface creates a static ARP entry for for the host stack interface on VPP.
func (n *IPv4Net) staticArpForSTNHostInterface() (key string, arp *vpp_l3.ARPEntry) {
	arp = &vpp_l3.ARPEntry{
		Interface:   n.hostInterconnectVPPIfName(),
		IpAddress:   n.nodeIP.String(),
		PhysAddress: hostInterconnectMACinLinuxSTN,
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// routeToOriginalSTNSubnet creates a linux route pointing the original subnet of the stolen interface towards VPP.
func (n *IPv4Net) routeToOriginalSTNSubnet() (key string, route *linux_l3.Route) {
	route = &linux_l3.Route{
		DstNetwork:        n.nodeIPNet.String(),
		GwAddr:            n.stnGwIPForHost().String(),
		Scope:             linux_l3.Route_GLOBAL,
		OutgoingInterface: n.hostInterconnectLinuxIfName(),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// stnGwIPForHost returns gateway IP address used in the host stack for routes pointing towards VPP
// (in the STN scenario).
func (n *IPv4Net) stnGwIPForHost() net.IP {
	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		// for IPv6, we assign /127 subnet to the stolen interface
		// and return the other IP from that subnet as the gateway IP
		ipNet := &net.IPNet{IP: n.nodeIP, Mask: net.CIDRMask(127, 128)}
		firstIP, lastIP := cidr.AddressRange(ipNet)
		if !cidr.Inc(firstIP).Equal(n.nodeIP) {
			return cidr.Inc(firstIP)
		}
		return cidr.Dec(lastIP)
	}

	nh := n.ContivConf.GetStaticDefaultGW()
	if nh == nil || nh.IsUnspecified() {
		// no default gateway, calculate fake gateway address for routes pointing to VPP
		firstIP, lastIP := cidr.AddressRange(n.nodeIPNet)
		if !cidr.Inc(firstIP).Equal(n.nodeIP) {
			nh = cidr.Inc(firstIP)
		} else {
			nh = cidr.Dec(lastIP)
		}
	}
	return nh
}

// stnRoutesForVPP returns VPP routes mirroring Host routes that were associated
// with the stolen interface.
func (n *IPv4Net) stnRoutesForVPP() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)

	for _, stnRoute := range n.ContivConf.GetSTNConfig().STNRoutes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &vpp_l3.Route{
			DstNetwork:        stnRoute.DestinationSubnet,
			NextHopAddr:       stnRoute.NextHopIp,
			OutgoingInterface: n.ContivConf.GetMainInterfaceName(),
			VrfId:             n.ContivConf.GetRoutingConfig().MainVRFID,
		}
		if route.DstNetwork == "" {
			route.DstNetwork = anyNetAddrForAF(net.ParseIP(stnRoute.NextHopIp))
		}
		key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		routes[key] = route
	}

	return routes
}

// stnRoutesForHost returns configuration of routes that were associated
// with the stolen interface, now updated to route via host-interconnect.
func (n *IPv4Net) stnRoutesForHost() map[string]*linux_l3.Route {
	routes := make(map[string]*linux_l3.Route)

	for _, stnRoute := range n.ContivConf.GetSTNConfig().STNRoutes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &linux_l3.Route{
			DstNetwork:        stnRoute.DestinationSubnet,
			GwAddr:            stnRoute.NextHopIp,
			Scope:             linux_l3.Route_GLOBAL,
			OutgoingInterface: n.hostInterconnectLinuxIfName(),
		}
		if route.DstNetwork == "" {
			route.DstNetwork = anyNetAddrForAF(net.ParseIP(stnRoute.NextHopIp))
		}
		key := linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
		routes[key] = route
	}

	return routes
}
