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
	"hash/fnv"
	"net"
	"os/exec"
	"strings"

	linux_intf "github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	linux_ns "github.com/ligato/vpp-agent/plugins/linuxv2/model/namespace"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
	txn_api "github.com/contiv/vpp/plugins/controller/txn"
)

/********** Pod Configuration **********/

// Pod contains all attributes of a k8s Pod that are needed to configure connectivity.
type Pod struct {
	ID               pod.ID
	ContainerID      string
	NetworkNamespace string
	VPPIfName        string
	LinuxIfName      string
	IPAddress        net.IP
}

// podConnectivityConfig returns configuration for VPP<->Pod connectivity.
func (s *remoteCNIserver) podConnectivityConfig(pod *Pod) (config txn_api.KeyValuePairs) {
	config = make(txn_api.KeyValuePairs)
	pod.VPPIfName, pod.LinuxIfName = s.podInterfaceName(pod)

	// create VPP to POD interconnect interface
	if s.config.UseTAPInterfaces {
		// TAP
		key, vppTap := s.podVPPTap(pod)
		config[key] = vppTap
		key, linuxTap := s.podLinuxTAP(pod)
		config[key] = linuxTap
	} else {
		// VETH pair + AF_PACKET
		key, veth1 := s.podVeth1(pod)
		config[key] = veth1
		key, veth2 := s.podVeth2(pod)
		config[key] = veth2
		key, afpacket := s.podAfPacket(pod)
		config[key] = afpacket
	}

	// ARP to VPP
	key, podArp := s.podToVPPArpEntry(pod)
	config[key] = podArp

	// link scope route
	key, route := s.podToVPPLinkRoute(pod)
	config[key] = route

	// Add default route for the container
	key, route = s.podToVPPDefaultRoute(pod)
	config[key] = route

	// ARP entry for POD IP
	key, vppArp := s.vppToPodArpEntry(pod)
	config[key] = vppArp

	// route to PodIP via AF_PACKET / TAP
	key, vppRoute := s.vppToPodRoute(pod)
	config[key] = vppRoute
	return config
}

// podInterfaceName returns logical names of interfaces on both sides
// of the interconnection between VPP and the given Pod.
func (s *remoteCNIserver) podInterfaceName(pod *Pod) (vppIfName, linuxIfName string) {
	if s.config.UseTAPInterfaces {
		return s.podVPPSideTAPName(pod), s.podLinuxSideTAPName(pod)
	} else {
		return s.podAFPacketName(pod), s.podVeth1Name(pod)
	}
}

/********** TAP interface **********/

// podVPPSideTAPName returns logical name of the TAP interface on VPP connected to a given pod.
func (s *remoteCNIserver) podVPPSideTAPName(pod *Pod) string {
	return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (s *remoteCNIserver) podLinuxSideTAPName(pod *Pod) string {
	return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPTap returns the configuration for TAP interface on the VPP side
// connecting a given Pod.
func (s *remoteCNIserver) podVPPTap(pod *Pod) (key string, config *vpp_intf.Interface) {
	tap := &vpp_intf.Interface{
		Name:        s.podVPPSideTAPName(pod),
		Type:        vpp_intf.Interface_TAP_INTERFACE,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetPodVrfID(),
		IpAddresses: []string{s.ipAddrForPodVPPIf(pod)},
		PhysAddress: s.hwAddrForPod(pod, true),
		Link: &vpp_intf.Interface_Tap{
			Tap: &vpp_intf.Interface_TapLink{},
		},
	}
	if s.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(s.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(s.config.TAPv2TxRingSize)
	}
	key = vpp_intf.InterfaceKey(tap.Name)
	return key, tap
}

// podLinuxTAP returns the configuration for TAP interface on the Linux side
// connecting a given Pod to VPP.
func (s *remoteCNIserver) podLinuxTAP(pod *Pod) (key string, config *linux_intf.LinuxInterface) {
	podIPNet := &net.IPNet{
		IP:   pod.IPAddress,
		Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
	}
	tap := &linux_intf.LinuxInterface{
		Name:        s.podLinuxSideTAPName(pod),
		Type:        linux_intf.LinuxInterface_TAP_TO_VPP,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: s.hwAddrForPod(pod, false),
		IpAddresses: []string{podIPNet.String()},
		Link: &linux_intf.LinuxInterface_Tap{
			Tap: &linux_intf.LinuxInterface_TapLink{
				VppTapIfName: s.podVPPSideTAPName(pod),
			},
		},
		Namespace: &linux_ns.LinuxNetNamespace{
			Type:      linux_ns.LinuxNetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	key = linux_intf.InterfaceKey(tap.Name)
	return key, tap
}


/********** AF-Packet + VETH interfaces **********/

// podAFPacketName returns logical name of AF-Packet interface connecting VPP with a given Pod.
func (s *remoteCNIserver) podAFPacketName(pod *Pod) string {
	return trimInterfaceName(podAFPacketLogicalNamePrefix+s.podVeth2Name(pod), logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the namespace of the given pod.
func (s *remoteCNIserver) podVeth1Name(pod *Pod) string {
	return trimInterfaceName(podInterfaceHostName+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the default namespace
// connecting the given pod.
func (s *remoteCNIserver) podVeth2Name(pod *Pod) string {
	return trimInterfaceName(pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth2HostIfName returns host name of the VETH interface in the default namespace
// connecting the given pod.
func (s *remoteCNIserver) podVeth2HostIfName(pod *Pod) string {
	return trimInterfaceName(pod.ContainerID, linuxIfNameMaxLen)
}

// podVeth1 returns the configuration for pod-side of the VETH interface
// connecting the given pod with VPP.
func (s *remoteCNIserver) podVeth1(pod *Pod) (key string, config *linux_intf.LinuxInterface) {
	podIPNet := &net.IPNet{
		IP:   pod.IPAddress,
		Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
	}
	veth := &linux_intf.LinuxInterface{
		Name:        s.podVeth1Name(pod),
		Type:        linux_intf.LinuxInterface_VETH,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: s.hwAddrForPod(pod, false),
		IpAddresses: []string{podIPNet.String()},
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: s.podVeth2Name(pod)},
		},
		Namespace: &linux_ns.LinuxNetNamespace{
			Type:      linux_ns.LinuxNetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	key =  linux_intf.InterfaceKey(veth.Name)
	return key, veth
}

// podVeth2 returns the configuration for vswitch-side of the VETH interface
// connecting the given pod with VPP.
func (s *remoteCNIserver) podVeth2(pod *Pod) (key string, config *linux_intf.LinuxInterface) {
	veth := &linux_intf.LinuxInterface{
		Name:       s.podVeth2Name(pod),
		Type:       linux_intf.LinuxInterface_VETH,
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: s.podVeth2HostIfName(pod),
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: s.podVeth1Name(pod)},
		},
	}
	key =  linux_intf.InterfaceKey(veth.Name)
	return key, veth
}

func (s *remoteCNIserver) podAfPacket(pod *Pod) (key string, config *vpp_intf.Interface) {
	afpacket := &vpp_intf.Interface{
		Name:        s.podAFPacketName(pod),
		Type:        vpp_intf.Interface_AF_PACKET_INTERFACE,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetPodVrfID(),
		IpAddresses: []string{s.ipAddrForPodVPPIf(pod)},
		PhysAddress: s.hwAddrForPod(pod, true),
		Link: &vpp_intf.Interface_Afpacket{
			Afpacket: &vpp_intf.Interface_AfpacketLink{
				HostIfName: s.podVeth2HostIfName(pod),
			},
		},
	}
	key = vpp_intf.InterfaceKey(afpacket.Name)
	return key, afpacket
}

/********** Pod ARPs and routes **********/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (s *remoteCNIserver) podToVPPArpEntry(pod *Pod) (key string, config *linux_l3.LinuxStaticARPEntry) {
	arp := &linux_l3.LinuxStaticARPEntry{
		Interface: pod.LinuxIfName,
		IpAddress: s.ipam.PodGatewayIP().String(),
		HwAddress: s.hwAddrForPod(pod, true),
	}
	key = linux_l3.StaticArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podToVPPLinkRoute returns configuration for route that puts pod's default GW behind
// the interface connecting pod with VPP (even though the GW IP does not fall into
// the pod IP address network).
func (s *remoteCNIserver) podToVPPLinkRoute(pod *Pod) (key string, config *linux_l3.LinuxStaticRoute) {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: pod.LinuxIfName,
		Scope:             linux_l3.LinuxStaticRoute_LINK,
		DstNetwork:        s.ipam.PodGatewayIP().String() + "/32",
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPLinkRoute returns configuration for the default route of the given pod.
func (s *remoteCNIserver) podToVPPDefaultRoute(pod *Pod) (key string, config *linux_l3.LinuxStaticRoute) {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: pod.LinuxIfName,
		DstNetwork:        ipv4NetAny,
		Scope:             linux_l3.LinuxStaticRoute_GLOBAL,
		GwAddr:            s.ipam.PodGatewayIP().String(),
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}


/********** VSwitch ARPs and routes **********/

// vppToPodArpEntry return configuration for ARP entry used in VPP to resolve
// hardware address from the IP address of the given pod.
func (s *remoteCNIserver) vppToPodArpEntry(pod *Pod) (key string, config *vpp_l3.ARPEntry) {
	arp := &vpp_l3.ARPEntry{
		Interface:   pod.VPPIfName,
		IpAddress:   pod.IPAddress.String(),
		PhysAddress: s.hwAddrForPod(pod, false),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vppToPodRoute return configuration for route used in VPP to direct traffic destinated
// to the IP address of the given pod.
func (s *remoteCNIserver) vppToPodRoute(pod *Pod) (key string, config *vpp_l3.StaticRoute) {
	podVPPIfName, _ := s.podInterfaceName(pod)
	route := &vpp_l3.StaticRoute{
		OutgoingInterface: podVPPIfName,
		DstNetwork:        pod.IPAddress.String() + "/32",
		NextHopAddr:       pod.IPAddress.String(),
		VrfId:             s.GetPodVrfID(),
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/********** Address generators **********/

// ipAddrForPodVPPIf returns the IP address of the interface connecting pod on the VPP side.
func (s *remoteCNIserver) ipAddrForPodVPPIf(pod *Pod) string {
	tapPrefix, _ := ipv4ToUint32(*s.ipam.VPPIfIPPrefix())

	podAddr, _ := ipv4ToUint32(pod.IPAddress)
	podMask, _ := ipv4ToUint32(net.IP(s.ipam.PodNetwork().Mask))
	podSuffix := podAddr &^ podMask

	tapAddress := uint32ToIpv4(tapPrefix + podSuffix)

	return net.IP.String(tapAddress) + "/32"
}

// generateHwAddrForPod generates hardware address for Pod interface on the VPP
// side or on the host (Linux) side.
// TODO: Safer may be to use node ID + pod IP address index
func (s *remoteCNIserver) hwAddrForPod(pod *Pod, vppSide bool) string {
	hwAddr := make(net.HardwareAddr, 6)
	h := fnv.New32a()
	h.Write([]byte(pod.ContainerID))
	hash := h.Sum32()
	if vppSide {
		hash = ^hash
	}
	hwAddr[0] = 2
	hwAddr[1] = 0xfe
	for i := 0; i < 4; i++ {
		hwAddr[i+2] = byte(hash & 0xff)
		hash >>= 8
	}
	return hwAddr.String()
}

/********** IPv6 **********/

// enableIPv6 enables IPv6 in the destination pod.
func (s *remoteCNIserver) enableIPv6(pod *Pod) error {
	// parse PID from the network namespace
	pid, err := getPIDFromNwNsPath(pod.NetworkNamespace)
	if err != nil {
		return err
	}

	// execute the sysctl in the namespace of given PID
	cmdStr := fmt.Sprintf("nsenter -t %d -n sysctl net.ipv6.conf.all.disable_ipv6=0", pid)
	s.Logger.Infof("Executing CMD: %s", cmdStr)

	cmdArr := strings.Split(cmdStr, " ")
	cmd := exec.Command("nsenter", cmdArr[1:]...)

	// check the output of the exec
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Logger.Errorf("CMD exec returned error: %v", err)
		return err
	}
	s.Logger.Infof("CMD output: %s", output)

	return nil
}