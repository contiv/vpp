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
	"net"

	"fmt"

	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"
	"github.com/vishvananda/netlink"
)

func (s *remoteCNIserver) configureRouteOnHost() error {
	dev, err := s.LinkByName(vethHostEndName)
	if err != nil {
		s.Logger.Error(err)
		return err
	}
	_, network, err := net.ParseCIDR(s.ipam.getPodSubnetCIDR())
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return s.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Dst:       network,
		Gw:        net.ParseIP(vethVPPEndIP),
	})
}

func (s *remoteCNIserver) defaultRouteToHost() *l3.StaticRoutes_Route {
	return &l3.StaticRoutes_Route{
		DstIpAddr:         "0.0.0.0/0",
		NextHopAddr:       vethHostEndIP,
		OutgoingInterface: vethVPPEndName,
	}
}

func (s *remoteCNIserver) interconnectVethHost() *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       "vppv1",
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: vethHostEndName,
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: "v2",
		},
		IpAddresses: []string{vethHostEndIP + "/24"},
	}
}

func (s *remoteCNIserver) interconnectVethVpp() *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       "v2",
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: vethVPPEndName,
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: "vppv1",
		},
	}
}

func (s *remoteCNIserver) interconnectAfpacket() *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:    vethVPPEndName,
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: vethVPPEndName,
		},
		IpAddresses: []string{vethVPPEndIP + "/24"},
	}
}

func (s *remoteCNIserver) physicalInterface(name string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        name,
		Type:        vpp_intf.InterfaceType_ETHERNET_CSMACD,
		Enabled:     true,
		IpAddresses: []string{fmt.Sprintf("%s.%d/24", nicNetworkPerfix, s.ipam.getPodNetworkSubnetID())},
	}
}

func (s *remoteCNIserver) physicalInterfaceLoopback() *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        "loopbackNIC",
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{fmt.Sprintf("%s.%d/24", nicNetworkPerfix, s.ipam.getPodNetworkSubnetID())},
	}
}

func (s *remoteCNIserver) routeToOtherHost(hostID uint8) *l3.StaticRoutes_Route {
	return &l3.StaticRoutes_Route{
		DstIpAddr:   fmt.Sprintf("%s.%d.0/24", podSubnetPrefix, hostID),
		NextHopAddr: fmt.Sprintf("%s.%d", nicNetworkPerfix, hostID),
	}
}
