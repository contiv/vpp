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

	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/namespace"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/podmanager"
)

/****************************** Pod Configuration ******************************/

// podConnectivityConfig returns configuration for VPP<->Pod connectivity.
func (s *remoteCNIserver) podConnectivityConfig(pod *podmanager.LocalPod) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

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
func (s *remoteCNIserver) podInterfaceName(pod *podmanager.LocalPod) (vppIfName, linuxIfName string) {
	if s.config.UseTAPInterfaces {
		return s.podVPPSideTAPName(pod), s.podLinuxSideTAPName(pod)
	}
	return s.podAFPacketName(pod), s.podVeth1Name(pod)
}

/******************************** TAP interface ********************************/

// podVPPSideTAPName returns logical name of the TAP interface on VPP connected to a given pod.
func (s *remoteCNIserver) podVPPSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (s *remoteCNIserver) podLinuxSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPTap returns the configuration for TAP interface on the VPP side
// connecting a given Pod.
func (s *remoteCNIserver) podVPPTap(pod *podmanager.LocalPod) (key string, config *interfaces.Interface) {
	tap := &interfaces.Interface{
		Name:        s.podVPPSideTAPName(pod),
		Type:        interfaces.Interface_TAP,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetPodVrfID(),
		IpAddresses: []string{s.ipAddrForPodVPPIf(pod)},
		PhysAddress: s.hwAddrForPod(pod, true),
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{},
		},
	}
	if s.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(s.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(s.config.TAPv2TxRingSize)
	}
	key = interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// podLinuxTAP returns the configuration for TAP interface on the Linux side
// connecting a given Pod to VPP.
func (s *remoteCNIserver) podLinuxTAP(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	tap := &linux_interfaces.Interface{
		Name:        s.podLinuxSideTAPName(pod),
		Type:        linux_interfaces.Interface_TAP_TO_VPP,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: s.hwAddrForPod(pod, false),
		IpAddresses: []string{s.ipam.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: s.podVPPSideTAPName(pod),
			},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if s.config.TCPChecksumOffloadDisabled {
		tap.RxChecksumOffloading = linux_interfaces.Interface_CHKSM_OFFLOAD_DISABLED
		tap.TxChecksumOffloading = linux_interfaces.Interface_CHKSM_OFFLOAD_DISABLED
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

/************************* AF-Packet + VETH interfaces *************************/

// podAFPacketName returns logical name of AF-Packet interface connecting VPP with a given Pod.
func (s *remoteCNIserver) podAFPacketName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podAFPacketLogicalNamePrefix+s.podVeth2Name(pod), logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the namespace of the given pod.
func (s *remoteCNIserver) podVeth1Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH1LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the default namespace
// connecting the given pod.
func (s *remoteCNIserver) podVeth2Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH2LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth2HostIfName returns host name of the VETH interface in the default namespace
// connecting the given pod.
func (s *remoteCNIserver) podVeth2HostIfName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(pod.ContainerID, linuxIfNameMaxLen)
}

// podVeth1 returns the configuration for pod-side of the VETH interface
// connecting the given pod with VPP.
func (s *remoteCNIserver) podVeth1(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:        s.podVeth1Name(pod),
		Type:        linux_interfaces.Interface_VETH,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: s.hwAddrForPod(pod, false),
		IpAddresses: []string{s.ipam.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: s.podVeth2Name(pod)},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	// AF-PACKET + VETHs do not work properly with checksum offloading
	// - disabling regardless of the configuration
	// if s.config.TCPChecksumOffloadDisabled {
	veth.RxChecksumOffloading = linux_interfaces.Interface_CHKSM_OFFLOAD_DISABLED
	veth.TxChecksumOffloading = linux_interfaces.Interface_CHKSM_OFFLOAD_DISABLED
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// podVeth2 returns the configuration for vswitch-side of the VETH interface
// connecting the given pod with VPP.
func (s *remoteCNIserver) podVeth2(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:       s.podVeth2Name(pod),
		Type:       linux_interfaces.Interface_VETH,
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: s.podVeth2HostIfName(pod),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: s.podVeth1Name(pod)},
		},
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

func (s *remoteCNIserver) podAfPacket(pod *podmanager.LocalPod) (key string, config *interfaces.Interface) {
	afpacket := &interfaces.Interface{
		Name:        s.podAFPacketName(pod),
		Type:        interfaces.Interface_AF_PACKET,
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		Vrf:         s.GetPodVrfID(),
		IpAddresses: []string{s.ipAddrForPodVPPIf(pod)},
		PhysAddress: s.hwAddrForPod(pod, true),
		Link: &interfaces.Interface_Afpacket{
			Afpacket: &interfaces.AfpacketLink{
				HostIfName: s.podVeth2HostIfName(pod),
			},
		},
	}
	key = interfaces.InterfaceKey(afpacket.Name)
	return key, afpacket
}

/***************************** Pod ARPs and routes *****************************/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (s *remoteCNIserver) podToVPPArpEntry(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticARPEntry) {
	_, linuxIfName := s.podInterfaceName(pod)
	arp := &linux_l3.StaticARPEntry{
		Interface: linuxIfName,
		IpAddress: s.ipam.PodGatewayIP().String(),
		HwAddress: s.hwAddrForPod(pod, true),
	}
	key = linux_l3.StaticArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podToVPPLinkRoute returns configuration for route that puts pod's default GW behind
// the interface connecting pod with VPP (even though the GW IP does not fall into
// the pod IP address network).
func (s *remoteCNIserver) podToVPPLinkRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticRoute) {
	_, linuxIfName := s.podInterfaceName(pod)
	route := &linux_l3.StaticRoute{
		OutgoingInterface: linuxIfName,
		Scope:             linux_l3.StaticRoute_LINK,
		DstNetwork:        s.ipam.PodGatewayIP().String() + "/32",
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPLinkRoute returns configuration for the default route of the given pod.
func (s *remoteCNIserver) podToVPPDefaultRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticRoute) {
	_, linuxIfName := s.podInterfaceName(pod)
	route := &linux_l3.StaticRoute{
		OutgoingInterface: linuxIfName,
		DstNetwork:        ipv4NetAny,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		GwAddr:            s.ipam.PodGatewayIP().String(),
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/*************************** VSwitch ARPs and routes ***************************/

// vppToPodArpEntry return configuration for ARP entry used in VPP to resolve
// hardware address from the IP address of the given pod.
func (s *remoteCNIserver) vppToPodArpEntry(pod *podmanager.LocalPod) (key string, config *l3.ARPEntry) {
	vppIfName, _ := s.podInterfaceName(pod)
	arp := &l3.ARPEntry{
		Interface:   vppIfName,
		IpAddress:   s.ipam.GetPodIP(pod.ID).IP.String(),
		PhysAddress: s.hwAddrForPod(pod, false),
		Static:      true,
	}
	key = l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vppToPodRoute return configuration for route used in VPP to direct traffic destinated
// to the IP address of the given pod.
func (s *remoteCNIserver) vppToPodRoute(pod *podmanager.LocalPod) (key string, config *l3.StaticRoute) {
	podVPPIfName, _ := s.podInterfaceName(pod)
	podIP := s.ipam.GetPodIP(pod.ID)
	route := &l3.StaticRoute{
		OutgoingInterface: podVPPIfName,
		DstNetwork:        podIP.String(),
		NextHopAddr:       podIP.IP.String(),
		VrfId:             s.GetPodVrfID(),
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/**************************** Address generators ******************************/

// ipAddrForPodVPPIf returns the IP address of the interface connecting pod on the VPP side.
func (s *remoteCNIserver) ipAddrForPodVPPIf(pod *podmanager.LocalPod) string {
	prefix, _ := ipv4ToUint32(*s.ipam.PodVPPSubnet())

	podAddr, _ := ipv4ToUint32(s.ipam.GetPodIP(pod.ID).IP)
	podMask, _ := ipv4ToUint32(net.IP(s.ipam.PodSubnetThisNode().Mask))
	podSuffix := podAddr &^ podMask

	address := uint32ToIpv4(prefix + podSuffix)

	return net.IP.String(address) + "/32"
}

// generateHwAddrForPod generates hardware address for Pod interface on the VPP
// side or on the host (Linux) side.
// TODO: Safer may be to use node ID + pod IP address index
func (s *remoteCNIserver) hwAddrForPod(pod *podmanager.LocalPod, vppSide bool) string {
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

/************************************ IPv6 ************************************/

// enableIPv6 enables IPv6 in the destination pod.
func (s *remoteCNIserver) enableIPv6(pod *podmanager.LocalPod) error {
	var pid int
	fmt.Sscanf(pod.NetworkNamespace, "/proc/%d/ns/net", &pid)
	if pid == 0 {
		return fmt.Errorf("failed to parse PID from network namespace path '%v'",
			pod.NetworkNamespace)
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
