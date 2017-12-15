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

	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/model/l3"
)

func (s *remoteCNIserver) l4Features(enable bool) *vpp_l4.L4Features {
	return &vpp_l4.L4Features{
		Enabled: enable,
	}
}

func (s *remoteCNIserver) routeFromHost() *linux_l3.LinuxStaticRoutes_Route {
	return &linux_l3.LinuxStaticRoutes_Route{
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
}

func (s *remoteCNIserver) defaultRouteToHost() *l3.StaticRoutes_Route {
	return &l3.StaticRoutes_Route{
		DstIpAddr:         "0.0.0.0/0",
		NextHopAddr:       s.ipam.VEthHostEndIP().String(),
		OutgoingInterface: s.interconnectAfpacketName(),
	}
}

func (s *remoteCNIserver) interconnectVethHost() *linux_intf.LinuxInterfaces_Interface {
	size, _ := s.ipam.VSwitchNetwork().Mask.Size()
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
	size, _ := s.ipam.VSwitchNetwork().Mask.Size()
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

func (s *remoteCNIserver) physicalInterface(name string) (*vpp_intf.Interfaces_Interface, error) {
	hostNetwork, err := s.ipam.HostIPNetwork(s.ipam.HostID())
	if err != nil {
		return nil, err
	}
	return &vpp_intf.Interfaces_Interface{
		Name:        name,
		Type:        vpp_intf.InterfaceType_ETHERNET_CSMACD,
		Enabled:     true,
		IpAddresses: []string{hostNetwork.String()},
	}, nil
}

func (s *remoteCNIserver) physicalInterfaceWithCustomIPAddress(name string, ipAddress string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        name,
		Type:        vpp_intf.InterfaceType_ETHERNET_CSMACD,
		Enabled:     true,
		IpAddresses: []string{ipAddress},
	}
}

func (s *remoteCNIserver) physicalInterfaceLoopback() (*vpp_intf.Interfaces_Interface, error) {
	hostNetwork, err := s.ipam.HostIPNetwork(s.ipam.HostID())
	if err != nil {
		return nil, err
	}
	return &vpp_intf.Interfaces_Interface{
		Name:        "loopbackNIC",
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{hostNetwork.String()},
	}, nil
}

func (s *remoteCNIserver) routeToOtherHostPods(hostID uint8) (*l3.StaticRoutes_Route, error) {
	podNetwork, err := s.ipam.OtherHostPodNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute pod network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(hostID, podNetwork)
}

func (s *remoteCNIserver) routeToOtherHostStack(hostID uint8) (*l3.StaticRoutes_Route, error) {
	vswitchNetwork, err := s.ipam.OtherHostVSwitchNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(hostID, vswitchNetwork)
}

func (s *remoteCNIserver) routeToOtherHostNetworks(hostID uint8, destNetwork *net.IPNet) (*l3.StaticRoutes_Route, error) {
	hostIP, err := s.ipam.HostIPAddress(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't get Host IP address for host ID %v, error: %v ", hostID, err)
	}
	return &l3.StaticRoutes_Route{
		DstIpAddr:   destNetwork.String(),
		NextHopAddr: hostIP.String(),
	}, nil
}
