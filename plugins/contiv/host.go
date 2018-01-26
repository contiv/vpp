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

	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l4"
	"github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/linuxcalls"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/model/l3"
)

const (
	vxlanVNI               = 10 // VXLAN Network Identifier (or VXLAN Segment ID)
	vxlanSplitHorizonGroup = 1  // As VXLAN tunnels are added to a BD, they must be configured with the same and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may loop among servers with the same VXLAN segment because VXLAN tunnels are fully meshed among servers.
)

func (s *remoteCNIserver) l4Features(enable bool) *vpp_l4.L4Features {
	return &vpp_l4.L4Features{
		Enabled: enable,
	}
}

func (s *remoteCNIserver) routeFromHost() *linux_l3.LinuxStaticRoutes_Route {
	route := &linux_l3.LinuxStaticRoutes_Route{
		Name:        "host-to-vpp",
		Default:     false,
		Namespace:   nil,
		Interface:   vethHostEndLogicalName,
		Description: "Route from host to VPP for this K8s node.",
		Scope: &linux_l3.LinuxStaticRoutes_Route_Scope{
			Type: linux_l3.LinuxStaticRoutes_Route_Scope_GLOBAL,
		},
		DstIpAddr: s.ipam.PodSubnet().String(),
		GwAddr:    s.ipam.VEthVPPEndIP().String(),
	}
	if s.useTAPInterfaces {
		route.Interface = tapHostEndName
	}
	return route
}

func (s *remoteCNIserver) defaultRoute(gwIP string, outIfName string) *vpp_l3.StaticRoutes_Route {
	route := &vpp_l3.StaticRoutes_Route{
		DstIpAddr:         "0.0.0.0/0",
		NextHopAddr:       gwIP,
		OutgoingInterface: outIfName,
	}
	return route
}

func (s *remoteCNIserver) interconnectTap() *vpp_intf.Interfaces_Interface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	tap := &vpp_intf.Interfaces_Interface{
		Name:    tapVPPEndLogicalName,
		Type:    vpp_intf.InterfaceType_TAP_INTERFACE,
		Enabled: true,
		Tap: &vpp_intf.Interfaces_Interface_Tap{
			HostIfName: tapHostEndName,
		},
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
	}
	if s.tapVersion == 2 {
		tap.Tap.Version = 2
		tap.Tap.RxRingSize = uint32(s.tapV2RxRingSize)
		tap.Tap.TxRingSize = uint32(s.tapV2TxRingSize)
	}

	return tap
}

func (s *remoteCNIserver) configureInterfconnectHostTap() error {
	// Set TAP interface IP to that of the Pod.
	return linuxcalls.AddInterfaceIP(tapHostEndName, &net.IPNet{IP: s.ipam.VEthHostEndIP(), Mask: s.ipam.VPPHostNetwork().Mask}, nil)
}

func (s *remoteCNIserver) interconnectVethHost() *linux_intf.LinuxInterfaces_Interface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       vethHostEndLogicalName,
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: vethHostEndName,
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: vethVPPEndLogicalName,
		},
		IpAddresses: []string{s.ipam.VEthHostEndIP().String() + "/" + strconv.Itoa(size)},
	}
}

func (s *remoteCNIserver) interconnectVethVpp() *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       vethVPPEndLogicalName,
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: vethVPPEndName,
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: vethHostEndLogicalName,
		},
	}
}

func (s *remoteCNIserver) interconnectAfpacketName() string {
	return afPacketNamePrefix + "-" + vethVPPEndName
}

func (s *remoteCNIserver) interconnectAfpacket() *vpp_intf.Interfaces_Interface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	return &vpp_intf.Interfaces_Interface{
		Name:    s.interconnectAfpacketName(),
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: vethVPPEndName,
		},
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
	}
}

func (s *remoteCNIserver) physicalInterface(name string, ipAddress string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:    name,
		Type:    vpp_intf.InterfaceType_ETHERNET_CSMACD,
		Enabled: true,

		IpAddresses: []string{ipAddress},
	}
}

func (s *remoteCNIserver) physicalInterfaceLoopback(ipAddress string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        "loopbackNIC",
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipAddress},
	}
}

func (s *remoteCNIserver) vxlanBVILoopback() (*vpp_intf.Interfaces_Interface, error) {
	vxlanIP, err := s.ipam.VxlanIPWithPrefix(s.ipam.NodeID())
	if err != nil {
		return nil, err
	}
	return &vpp_intf.Interfaces_Interface{
		Name:        "vxlanBVI",
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{vxlanIP.String()},
		PhysAddress: s.hwAddrForVXLAN(),
	}, nil
}

func (s *remoteCNIserver) hwAddrForVXLAN() string {
	return fmt.Sprintf("1a:2b:3c:4d:5e:%02x", s.ipam.NodeID())
}

func (s *remoteCNIserver) vxlanBridgeDomain(bviInterface string) *vpp_l2.BridgeDomains_BridgeDomain {
	return &vpp_l2.BridgeDomains_BridgeDomain{
		Name:                "vxlanBD",
		Learn:               true,
		Forward:             true,
		Flood:               true,
		UnknownUnicastFlood: true,
		Interfaces: []*vpp_l2.BridgeDomains_BridgeDomain_Interfaces{
			{
				Name: bviInterface,
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
}

func (s *remoteCNIserver) computeRoutesToHost(hostID uint8, nextHopIP string) (podsRoute *vpp_l3.StaticRoutes_Route, hostRoute *vpp_l3.StaticRoutes_Route, err error) {
	podsRoute, err = s.routeToOtherHostPods(hostID, nextHopIP)
	if err != nil {
		err = fmt.Errorf("Can't construct route to pods of host %v: %v ", hostID, err)
		return
	}
	hostRoute, err = s.routeToOtherHostStack(hostID, nextHopIP)
	if err != nil {
		err = fmt.Errorf("Can't construct route to host %v: %v ", hostID, err)
		return
	}
	return
}

func (s *remoteCNIserver) routeToOtherHostPods(hostID uint8, nextHopIP string) (*vpp_l3.StaticRoutes_Route, error) {
	podNetwork, err := s.ipam.OtherNodePodNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute pod network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(podNetwork, nextHopIP)
}

func (s *remoteCNIserver) routeToOtherHostStack(hostID uint8, nextHopIP string) (*vpp_l3.StaticRoutes_Route, error) {
	hostNw, err := s.ipam.OtherNodeVPPHostNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(hostNw, nextHopIP)
}

func (s *remoteCNIserver) routeToOtherHostNetworks(destNetwork *net.IPNet, nextHopIP string) (*vpp_l3.StaticRoutes_Route, error) {
	return &vpp_l3.StaticRoutes_Route{
		DstIpAddr:   destNetwork.String(),
		NextHopAddr: nextHopIP,
	}, nil
}

func (s *remoteCNIserver) computeVxlanToHost(hostID uint8, hostIP string) (*vpp_intf.Interfaces_Interface, error) {
	return &vpp_intf.Interfaces_Interface{
		Name:    fmt.Sprintf("vxlan%d", hostID),
		Type:    vpp_intf.InterfaceType_VXLAN_TUNNEL,
		Enabled: true,
		Vxlan: &vpp_intf.Interfaces_Interface_Vxlan{
			SrcAddress: s.ipPrefixToAddress(s.nodeIP),
			DstAddress: hostIP,
			Vni:        vxlanVNI,
		},
	}, nil
}

func (s *remoteCNIserver) addInterfaceToVxlanBD(bd *vpp_l2.BridgeDomains_BridgeDomain, ifName string) {
	bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomains_BridgeDomain_Interfaces{
		Name:              ifName,
		SplitHorizonGroup: vxlanSplitHorizonGroup,
	})
}

func (s *remoteCNIserver) otherHostIP(hostID uint8, hostIPPrefix string) string {
	// determine next hop IP - either use provided one, or calculate based on hostIPPrefix
	if hostIPPrefix != "" {
		// hostIPPrefix defined, just trim prefix length
		return s.ipPrefixToAddress(hostIPPrefix)
	}

	// hostIPPrefix not defined, determine based on hostID
	nodeIP, err := s.ipam.NodeIPAddress(hostID)
	if err != nil {
		s.Logger.Errorf("Can't get Host IP address for host ID %v, error: %v ", hostID, err)
		return ""
	}
	return nodeIP.String()
}

func (s *remoteCNIserver) ipPrefixToAddress(ip string) string {
	if strings.Contains(ip, "/") {
		return ip[:strings.Index(ip, "/")]
	}
	return ip
}
