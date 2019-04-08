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

package ipnet

import (
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"strings"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/podmanager"

	"github.com/contiv/vpp/plugins/devicemanager"
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"sort"
)

const (
	// prefix for logical name of the Linux loopback interface in a pod
	podLinuxLoopLogicalNamePrefix = "linux-loop-"

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

const (
	ipv4LoopbackAddress = "127.0.0.1/8"
	ipv6LoopbackAddress = "::1/128"
)

const (
	contivCustomIfAnnotation = "contivpp.io/custom-if" // k8s annotation used to request custom pod interfaces
	contivCustomIfSeparator  = ","                     // separator used to split multiple interfaces in k8s annotation

	memifIfType = "memif"
)

/****************************** Pod Configuration ******************************/

// podConnectivityConfig returns configuration for VPP<->Pod connectivity.
func (n *IPNet) podConnectivityConfig(pod *podmanager.LocalPod) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	// create loopback in the POD
	key, linuxLoop := n.podLinuxLoop(pod)
	config[key] = linuxLoop

	// create VPP to POD interconnect interface
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
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

	// /32 (or /128 for ipv6) route from the host to POD (only in external IPAM case)
	if n.ContivConf.GetIPAMConfig().UseExternalIPAM {
		key, route := n.hostToPodRoute(pod)
		config[key] = route
	}

	return config
}

// podInterfaceName returns logical names of interfaces on both sides
// of the interconnection between VPP and the given Pod.
func (n *IPNet) podInterfaceName(pod *podmanager.LocalPod) (vppIfName, linuxIfName string) {
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		return n.podVPPSideTAPName(pod), n.podLinuxSideTAPName(pod)
	}
	return n.podAFPacketName(pod), n.podVeth1Name(pod)
}

/****************************** Pod custom interfaces configuration ******************************/

func (n *IPNet) podCustomIfsConfig(pod *podmanager.LocalPod, isAdd bool) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	if pod == nil || pod.Metadata == nil {
		return config
	}
	customIfs := getContivCustomIfs(pod.Metadata.Annotations)

	var (
		memifCnt  uint32
		memifInfo *devicemanager.MemifInfo
	)

	for _, customIf := range customIfs {
		ifName, ifType, _, err := parseCustomIfInfo(customIf)
		if err != nil {
			n.Log.Warnf("Error parsing custom interface definition (%v), skipping the interface %s", err, customIf)
			continue
		}

		// TODO: TAP & veth support
		if ifType == memifIfType {
			if memifInfo == nil {
				memifInfo, err = n.DeviceManager.GetPodMemifInfo(pod.ID)
				if err != nil || memifInfo == nil {
					n.Log.Warnf("Couldn't retrieve pod memif information, skipping memif configuration")
					break
				}
			}
			// configure the memif
			k, v := n.podVPPMemif(pod, ifName, memifInfo, memifCnt)
			config[k] = v
			memifCnt++
		}
	}

	if !isAdd && memifInfo != nil {
		// by delete, cleanup the memif-related resources
		n.DeviceManager.ReleasePodMemif(pod.ID)
	}

	return config
}

// getContivCustomIfs returns alphabetically ordered slice of custom interfaces defined in pod annotations.
func getContivCustomIfs(annotations map[string]string) []string {
	out := make([]string, 0)

	for k, v := range annotations {
		if strings.HasPrefix(k, contivCustomIfAnnotation) {
			ifs := strings.Split(v, contivCustomIfSeparator)
			for _, i := range ifs {
				out = append(out, strings.TrimSpace(i))
			}
		}
	}
	sort.Strings(out)
	return out
}

// parseCustomIfInfo
func parseCustomIfInfo(ifAnnotation string) (ifName, ifType, ifNet string, err error) {
	ifParts := strings.Split(ifAnnotation, "/")
	if len(ifParts) < 2 {
		err = fmt.Errorf("invalid %s annotation value: %s", contivCustomIfAnnotation, ifAnnotation)
		return
	}

	ifName = ifParts[0]
	ifType = ifParts[1]

	if len(ifParts) > 2 {
		ifNet = ifParts[2]
	}
	return
}

/******************************** loopback interface ********************************/

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (n *IPNet) podLinuxLoopName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podLinuxLoopLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podLinuxLoop returns the configuration for the loopback interface in the Linux namespace of the pod.
func (n *IPNet) podLinuxLoop(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	loop := &linux_interfaces.Interface{
		Name:    n.podLinuxLoopName(pod),
		Type:    linux_interfaces.Interface_LOOPBACK,
		Enabled: true,
		// IPv6 loopback address is included even in the IPv4 mode.
		// This is because IPv6 must be always enabled in the pods to allow the
		// agent to move TAP/VETH interfaces from the IPV6-enabled default
		// namespace into the namespaces of pods.
		IpAddresses: []string{ipv4LoopbackAddress, ipv6LoopbackAddress},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	key = linux_interfaces.InterfaceKey(loop.Name)
	return key, loop
}

/******************************** TAP interface ********************************/

// podVPPSideTAPName returns logical name of the TAP interface on VPP connected to a given pod.
func (n *IPNet) podVPPSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (n *IPNet) podLinuxSideTAPName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPTap returns the configuration for TAP interface on the VPP side
// connecting a given Pod.
func (n *IPNet) podVPPTap(pod *podmanager.LocalPod) (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	tap := &vpp_interfaces.Interface{
		Name:        n.podVPPSideTAPName(pod),
		Type:        vpp_interfaces.Interface_TAP,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, true),
		Unnumbered: &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		},
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{},
		},
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

// podLinuxTAP returns the configuration for TAP interface on the Linux side
// connecting a given Pod to VPP.
func (n *IPNet) podLinuxTAP(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	tap := &linux_interfaces.Interface{
		Name:        n.podLinuxSideTAPName(pod),
		Type:        linux_interfaces.Interface_TAP_TO_VPP,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		IpAddresses: []string{n.IPAM.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: n.podVPPSideTAPName(pod),
			},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

/************************* AF-Packet + VETH interfaces *************************/

// podAFPacketName returns logical name of AF-Packet interface connecting VPP with a given Pod.
func (n *IPNet) podAFPacketName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podAFPacketLogicalNamePrefix+n.podVeth2Name(pod), logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the namespace of the given pod.
func (n *IPNet) podVeth1Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH1LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPNet) podVeth2Name(pod *podmanager.LocalPod) string {
	return trimInterfaceName(podVETH2LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth2HostIfName returns host name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPNet) podVeth2HostIfName(pod *podmanager.LocalPod) string {
	return trimInterfaceName(pod.ContainerID, linuxIfNameMaxLen)
}

// podVeth1 returns the configuration for pod-side of the VETH interface
// connecting the given pod with VPP.
func (n *IPNet) podVeth1(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	veth := &linux_interfaces.Interface{
		Name:        n.podVeth1Name(pod),
		Type:        linux_interfaces.Interface_VETH,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		IpAddresses: []string{n.IPAM.GetPodIP(pod.ID).String()},
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth2Name(pod)},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if interfaceCfg.TCPChecksumOffloadDisabled {
		veth.GetVeth().RxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
		veth.GetVeth().TxChecksumOffloading = linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

// podVeth2 returns the configuration for vswitch-side of the VETH interface
// connecting the given pod with VPP.
func (n *IPNet) podVeth2(pod *podmanager.LocalPod) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:       n.podVeth2Name(pod),
		Type:       linux_interfaces.Interface_VETH,
		Mtu:        n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:    true,
		HostIfName: n.podVeth2HostIfName(pod),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth1Name(pod)},
		},
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

func (n *IPNet) podAfPacket(pod *podmanager.LocalPod) (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	afpacket := &vpp_interfaces.Interface{
		Name:        n.podAFPacketName(pod),
		Type:        vpp_interfaces.Interface_AF_PACKET,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, true),
		Unnumbered: &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		},
		Link: &vpp_interfaces.Interface_Afpacket{
			Afpacket: &vpp_interfaces.AfpacketLink{
				HostIfName: n.podVeth2HostIfName(pod),
			},
		},
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		afpacket.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(afpacket.Name)
	return key, afpacket
}

/******************************** memif interface ********************************/

// podVPPSideTAPName returns logical name of the TAP interface on VPP connected to a given pod.
func (n *IPNet) podVPPSideMemifName(pod *podmanager.LocalPod, ifName string) string {
	return trimInterfaceName(ifName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPMemif returns the configuration for memif interface on the VPP side connecting a given Pod.
func (n *IPNet) podVPPMemif(pod *podmanager.LocalPod, ifName string,
	memifInfo *devicemanager.MemifInfo, memifID uint32) (key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	tap := &vpp_interfaces.Interface{
		Name:    n.podVPPSideMemifName(pod, ifName),
		Type:    vpp_interfaces.Interface_MEMIF,
		Mtu:     interfaceCfg.MTUSize,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().PodVRFID,
		Unnumbered: &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		},
		Link: &vpp_interfaces.Interface_Memif{
			Memif: &vpp_interfaces.MemifLink{
				Master:         true,
				Mode:           vpp_interfaces.MemifLink_ETHERNET,
				SocketFilename: memifInfo.HostSocket,
				Secret:         memifInfo.Secret,
				Id:             memifID,
			},
		},
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		tap.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

/***************************** Pod ARPs and routes *****************************/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (n *IPNet) podToVPPArpEntry(pod *podmanager.LocalPod) (key string, config *linux_l3.ARPEntry) {
	_, linuxIfName := n.podInterfaceName(pod)
	arp := &linux_l3.ARPEntry{
		Interface: linuxIfName,
		IpAddress: n.IPAM.PodGatewayIP().String(),
		HwAddress: n.hwAddrForPod(pod, true),
	}
	key = linux_l3.ArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podToVPPLinkRoute returns configuration for route that puts pod's default GW behind
// the interface connecting pod with VPP (even though the GW IP does not fall into
// the pod IP address network).
func (n *IPNet) podToVPPLinkRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.Route) {
	_, linuxIfName := n.podInterfaceName(pod)
	route := &linux_l3.Route{
		OutgoingInterface: linuxIfName,
		Scope:             linux_l3.Route_LINK,
		DstNetwork:        n.IPAM.PodGatewayIP().String() + hostPrefixForAF(n.IPAM.PodGatewayIP()),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPLinkRoute returns configuration for the default route of the given pod.
func (n *IPNet) podToVPPDefaultRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.Route) {
	_, linuxIfName := n.podInterfaceName(pod)
	route := &linux_l3.Route{
		OutgoingInterface: linuxIfName,
		DstNetwork:        anyNetAddrForAF(n.IPAM.PodGatewayIP()),
		Scope:             linux_l3.Route_GLOBAL,
		GwAddr:            n.IPAM.PodGatewayIP().String(),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/*************************** VSwitch ARPs and routes ***************************/

// vppToPodArpEntry return configuration for ARP entry used in VPP to resolve
// hardware address from the IP address of the given pod.
func (n *IPNet) vppToPodArpEntry(pod *podmanager.LocalPod) (key string, config *vpp_l3.ARPEntry) {
	vppIfName, _ := n.podInterfaceName(pod)
	arp := &vpp_l3.ARPEntry{
		Interface:   vppIfName,
		IpAddress:   n.IPAM.GetPodIP(pod.ID).IP.String(),
		PhysAddress: n.hwAddrForPod(pod, false),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vppToPodRoute return configuration for route used in VPP to direct traffic destinated
// to the IP address of the given pod.
func (n *IPNet) vppToPodRoute(pod *podmanager.LocalPod) (key string, config *vpp_l3.Route) {
	podVPPIfName, _ := n.podInterfaceName(pod)
	podIP := n.IPAM.GetPodIP(pod.ID)
	route := &vpp_l3.Route{
		OutgoingInterface: podVPPIfName,
		DstNetwork:        podIP.String(),
		NextHopAddr:       podIP.IP.String(),
		VrfId:             n.ContivConf.GetRoutingConfig().PodVRFID,
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/**************************** Host routes ******************************/

// hostToPodRoute returns configuration for the route pointing to the pod IP from the linux host (main namespace).
func (n *IPNet) hostToPodRoute(pod *podmanager.LocalPod) (key string, config *linux_l3.Route) {
	podIP := n.IPAM.GetPodIP(pod.ID)
	route := &linux_l3.Route{
		DstNetwork: podIP.IP.String() + hostPrefixForAF(podIP.IP),
		Scope:      linux_l3.Route_GLOBAL,
	}
	if !n.ContivConf.InSTNMode() {
		route.GwAddr = n.IPAM.HostInterconnectIPInVPP().String()
	} else {
		route.GwAddr = n.stnGwIPForHost().String()
	}
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		route.OutgoingInterface = HostInterconnectTAPinLinuxLogicalName
	} else {
		route.OutgoingInterface = hostInterconnectVETH1LogicalName
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/**************************** Address generators ******************************/

// generateHwAddrForPod generates hardware address for Pod interface on the VPP
// side or on the host (Linux) side.
// TODO: Safer may be to use node ID + pod IP address index
func (n *IPNet) hwAddrForPod(pod *podmanager.LocalPod, vppSide bool) string {
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
func (n *IPNet) enableIPv6(pod *podmanager.LocalPod) error {
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
