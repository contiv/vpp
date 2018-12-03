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

const (
	// interface host name as required by Kubernetes for every pod
	podInterfaceHostName = "eth0" // required by Kubernetes

	// prefix for logical name of AF-Packet interface (VPP) connecting a pod
	podAFPacketLogicalNamePrefix = "afpacket"

	// prefix for logical name of VETH1 interface (pod namespace) connecting a pod
	podVETH1LogicalNamePrefix = "veth1-"

	// prefix for logical name of VETH2 interface (vswitch namespace) connecting a pod
	podVETH2LogicalNamePrefix = "veth2-"

	// prefix for logical name of the VPP-TAP interface connecting a pod
	podVPPSideTAPLogicalNamePrefix = "vpp-tap-"

	// prefix for logical name of the Linux-TAP interface connecting a pod
	podLinuxSideTAPLogicalNamePrefix = "linux-tap-"
)

/****************************** Pod Configuration ******************************/

// podConnectivityConfig returns configuration for VPP<->Pod connectivity.
func (n *IPv4Net) podConnectivityConfig(pod *podmanager.LocalPod) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	// create VPP to POD interconnect interface
	if n.config.UseTAPInterfaces {
		// TAP
		key, vppTap := n.podVPPTap(pod)
		config[key] = vppTap
		key, linuxTap := n.podLinuxTAP(pod)
		config[key] = linuxTap
	} else {
		// VETH pair + AF_PACKET
		key, veth1 := n.podVeth1(pod)
		config[key] = veth1
		key, veth2 := n.podVeth2(pod)
		config[key] = veth2
		key, afpacket := n.podAfPacket(pod)
		config[key] = afpacket
	}

	// ARP to VPP
	key, podArp := n.podToVPPArpEntry(pod)
	config[key] = podArp

	// link scope route
	key, route := n.podToVPPLinkRoute(pod)
	config[key] = route

	// Add default route for the container
	key, route = n.podToVPPDefaultRoute(pod)
	config[key] = route

	// ARP entry for POD IP
	key, vppArp := n.vppToPodArpEntry(pod)
	config[key] = vppArp

	// route to PodIP via AF_PACKET / TAP
	key, vppRoute := n.vppToPodRoute(pod)
	config[key] = vppRoute
	return config
}

// podInterfaceName returns logical names of interfaces on both sides
// of the interconnection between VPP and the given Pod.
func (n *IPv4Net) podInterfaceName(pod *podmanager.LocalPod) (vppIfName, linuxIfName string) {
	if n.config.UseTAPInterfaces {
		return n.podVPPSideTAPName(pod), n.podLinuxSideTAPName(pod)
	}
	return n.podAFPacketName(pod), n.podVeth1Name(pod)
}

/******************************** TAP interface ********************************/

// podVPPSideTAPName returns logical name of the TAP interface on VPP connected to a given pod.
func (n *IPv4Net) podVPPSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (n *IPv4Net) podLinuxSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPTap returns the configuration for TAP interface on the VPP side
// connecting a given Pod.
func (n *IPv4Net) podVPPTap(pod *podmanager.LocalPod) (key string, config *interfaces.Interface) {
	tap := &interfaces.Interface{
		Name:        n.podVPPSideTAPName(pod),
		Type:        interfaces.Interface_TAP,
		Mtu:         n.config.MTUSize,
		Enabled:     true,
		Vrf:         n.GetPodVrfID(),
		IpAddresses: []string{n.ipAddrForPodVPPIf(pod)},
		PhysAddress: n.hwAddrForPod(pod, true),
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{},
		},
	}
	if n.config.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(n.config.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(n.config.TAPv2TxRingSize)
	}
	key = interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// podLinuxTAP returns the configuration for TAP interface on the Linux side
// connecting a given Pod to VPP.
func (n *IPv4Net) podLinuxTAP(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	tap := &linux_interfaces.Interface{
		Name:        n.podLinuxSideTAPName(pod),
		Type:        linux_interfaces.Interface_TAP_TO_VPP,
		Mtu:         n.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		IpAddresses: []string{n.ipam.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: n.podVPPSideTAPName(pod),
			},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

/************************* AF-Packet + VETH interfaces *************************/

// podAFPacketName returns logical name of AF-Packet interface connecting VPP with a given Pod.
func (n *IPv4Net) podAFPacketName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podAFPacketLogicalNamePrefix+n.podVeth2Name(pod), logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the namespace of the given pod.
func (n *IPv4Net) podVeth1Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH1LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPv4Net) podVeth2Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH2LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth2HostIfName returns host name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPv4Net) podVeth2HostIfName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(pod.ContainerID, linuxIfNameMaxLen)
}

// podVeth1 returns the configuration for pod-side of the VETH interface
// connecting the given pod with VPP.
func (n *IPv4Net) podVeth1(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:        n.podVeth1Name(pod),
		Type:        linux_interfaces.Interface_VETH,
		Mtu:         n.config.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		IpAddresses: []string{n.ipam.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth2Name(pod)},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_NETNS_REF_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if n.config.TCPChecksumOffloadDisabled {
		veth.GetVeth().RxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
		veth.GetVeth().TxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// podVeth2 returns the configuration for vswitch-side of the VETH interface
// connecting the given pod with VPP.
func (n *IPv4Net) podVeth2(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:       n.podVeth2Name(pod),
		Type:       linux_interfaces.Interface_VETH,
		Mtu:        n.config.MTUSize,
		Enabled:    true,
		HostIfName: n.podVeth2HostIfName(pod),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth1Name(pod)},
		},
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

func (n *IPv4Net) podAfPacket(pod *podmanager.LocalPod) (key string, config *interfaces.Interface) {
	afpacket := &interfaces.Interface{
		Name:        n.podAFPacketName(pod),
		Type:        interfaces.Interface_AF_PACKET,
		Mtu:         n.config.MTUSize,
		Enabled:     true,
		Vrf:         n.GetPodVrfID(),
		IpAddresses: []string{n.ipAddrForPodVPPIf(pod)},
		PhysAddress: n.hwAddrForPod(pod, true),
		Link: &interfaces.Interface_Afpacket{
			Afpacket: &interfaces.AfpacketLink{
				HostIfName: n.podVeth2HostIfName(pod),
			},
		},
	}
	key = interfaces.InterfaceKey(afpacket.Name)
	return key, afpacket
}

/***************************** Pod ARPs and routes *****************************/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (n *IPv4Net) podToVPPArpEntry(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticARPEntry) {
	_, linuxIfName := n.podInterfaceName(pod)
	arp := &linux_l3.StaticARPEntry{
		Interface: linuxIfName,
		IpAddress: n.ipam.PodGatewayIP().String(),
		HwAddress: n.hwAddrForPod(pod, true),
	}
	key = linux_l3.StaticArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podToVPPLinkRoute returns configuration for route that puts pod's default GW behind
// the interface connecting pod with VPP (even though the GW IP does not fall into
// the pod IP address network).
func (n *IPv4Net) podToVPPLinkRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticRoute) {
	_, linuxIfName := n.podInterfaceName(pod)
	route := &linux_l3.StaticRoute{
		OutgoingInterface: linuxIfName,
		Scope:             linux_l3.StaticRoute_LINK,
		DstNetwork:        n.ipam.PodGatewayIP().String() + "/32",
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPLinkRoute returns configuration for the default route of the given pod.
func (n *IPv4Net) podToVPPDefaultRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.StaticRoute) {
	_, linuxIfName := n.podInterfaceName(pod)
	route := &linux_l3.StaticRoute{
		OutgoingInterface: linuxIfName,
		DstNetwork:        ipv4NetAny,
		Scope:             linux_l3.StaticRoute_GLOBAL,
		GwAddr:            n.ipam.PodGatewayIP().String(),
	}
	key = linux_l3.StaticRouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/*************************** VSwitch ARPs and routes ***************************/

// vppToPodArpEntry return configuration for ARP entry used in VPP to resolve
// hardware address from the IP address of the given pod.
func (n *IPv4Net) vppToPodArpEntry(pod *podmanager.LocalPod) (key string, config *l3.ARPEntry) {
	vppIfName, _ := n.podInterfaceName(pod)
	arp := &l3.ARPEntry{
		Interface:   vppIfName,
		IpAddress:   n.ipam.GetPodIP(pod.ID).IP.String(),
		PhysAddress: n.hwAddrForPod(pod, false),
		Static:      true,
	}
	key = l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vppToPodRoute return configuration for route used in VPP to direct traffic destinated
// to the IP address of the given pod.
func (n *IPv4Net) vppToPodRoute(pod *podmanager.LocalPod) (key string, config *l3.StaticRoute) {
	podVPPIfName, _ := n.podInterfaceName(pod)
	podIP := n.ipam.GetPodIP(pod.ID)
	route := &l3.StaticRoute{
		OutgoingInterface: podVPPIfName,
		DstNetwork:        podIP.String(),
		NextHopAddr:       podIP.IP.String(),
		VrfId:             n.GetPodVrfID(),
	}
	key = l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/**************************** Address generators ******************************/

// ipAddrForPodVPPIf returns the IP address of the interface connecting pod on the VPP side.
func (n *IPv4Net) ipAddrForPodVPPIf(pod *podmanager.LocalPod) string {
	prefix, _ := ipv4ToUint32(*n.ipam.PodVPPSubnet())

	podAddr, _ := ipv4ToUint32(n.ipam.GetPodIP(pod.ID).IP)
	podMask, _ := ipv4ToUint32(net.IP(n.ipam.PodSubnetThisNode().Mask))
	podSuffix := podAddr &^ podMask

	address := uint32ToIpv4(prefix + podSuffix)

	return net.IP.String(address) + "/32"
}

// generateHwAddrForPod generates hardware address for Pod interface on the VPP
// side or on the host (Linux) side.
// TODO: Safer may be to use node ID + pod IP address index
func (n *IPv4Net) hwAddrForPod(pod *podmanager.LocalPod, vppSide bool) string {
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
func (n *IPv4Net) enableIPv6(pod *podmanager.LocalPod) error {
	var pid int
	fmt.Sscanf(pod.NetworkNamespace, "/proc/%d/ns/net", &pid)
	if pid == 0 {
		return fmt.Errorf("failed to parse PID from network namespace path '%v'",
			pod.NetworkNamespace)
	}

	// execute the sysctl in the namespace of given PID
	cmdStr := fmt.Sprintf("nsenter -t %d -n sysctl net.ipv6.conf.all.disable_ipv6=0", pid)
	n.Log.Infof("Executing CMD: %s", cmdStr)

	cmdArr := strings.Split(cmdStr, " ")
	cmd := exec.Command("nsenter", cmdArr[1:]...)

	// check the output of the exec
	output, err := cmd.CombinedOutput()
	if err != nil {
		n.Log.Errorf("CMD exec returned error: %v", err)
		return err
	}
	n.Log.Infof("CMD output: %s", output)

	return nil
}
