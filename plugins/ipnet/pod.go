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
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"sort"
	"strings"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/podmanager"

	"github.com/contiv/vpp/plugins/devicemanager"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
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

	// prefix for logical name of the memif interface connecting a pod
	podMemifLogicalNamePrefix = "memif-"

	// special network name dedicated to "stub" custom interfaces - not connected to any VRF nor bridge domain.
	stubNetworkName = "stub"
)

const (
	ipv4LoopbackAddress = "127.0.0.1/8"
	ipv6LoopbackAddress = "::1/128"
)

const (
	contivMicroserviceLabel  = "contivpp.io/microservice-label" // k8s annotation used to request custom pod interfaces
	contivCustomIfAnnotation = "contivpp.io/custom-if"          // k8s annotation used to request custom pod interfaces
	contivCustomIfSeparator  = ","                              // separator used to split multiple interfaces in k8s annotation

	memifIfType = "memif"
	tapIfType   = "tap"
	vethIfType  = "veth"
)

// podCustomIfInfo holds information about a custom pod interface
type podCustomIfInfo struct {
	ifName string
	ifType string
	ifNet  string
}

/****************************** Pod Configuration ******************************/

// podConnectivityConfig returns configuration for VPP<->Pod connectivity.
func (n *IPNet) podConnectivityConfig(pod *podmanager.LocalPod) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	// create loopback in the POD
	key, linuxLoop := n.podLinuxLoop(pod)
	config[key] = linuxLoop

	podIP := n.IPAM.GetPodIP(pod.ID)

	// create VPP to POD interconnect interface
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		// TAP
		key, vppTap := n.podVPPTap(pod, podIP, "")
		config[key] = vppTap
		key, linuxTap := n.podLinuxTAP(pod, podIP, "")
		config[key] = linuxTap
	} else {
		// VETH pair + AF_PACKET
		key, veth1 := n.podVeth1(pod, podIP, "")
		config[key] = veth1
		key, veth2 := n.podVeth2(pod, "")
		config[key] = veth2
		key, afpacket := n.podAfPacket(pod, podIP, "")
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
	key, vppRoute := n.vppToPodRoute(pod, podIP, "", "")
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
func (n *IPNet) podInterfaceName(pod *podmanager.LocalPod, customIfName, customIfType string) (vppIfName, podIfName string) {
	if customIfType == memifIfType {
		return n.podVPPSideMemifName(pod, customIfName), n.podMicroserviceSideMemifName(pod, customIfName)
	}
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces && customIfType != vethIfType {
		return n.podVPPSideTAPName(pod, customIfName), n.podLinuxSideTAPName(pod, customIfName)
	}
	return n.podAFPacketName(pod, customIfName), n.podVeth1Name(pod, customIfName)
}

/****************************** Pod custom interfaces configuration ******************************/

// podCustomIfsConfig returns configuration for custom interfaces connectivity.
// If no custom interfaces are requested, returns empty config.
func (n *IPNet) podCustomIfsConfig(pod *podmanager.LocalPod, isAdd bool) (config controller.KeyValuePairs) {
	var (
		memifID   uint32
		memifInfo *devicemanager.MemifInfo
	)
	if pod == nil || pod.Metadata == nil {
		return config
	}
	config = make(controller.KeyValuePairs)
	microserviceConfig := make(controller.KeyValuePairs)

	customIfs := getContivCustomIfs(pod.Metadata.Annotations)
	serviceLabel := getContivMicroserviceLabel(pod.Metadata.Annotations)

	for _, customIfStr := range customIfs {
		customIf, err := parseCustomIfInfo(customIfStr)
		if err != nil {
			n.Log.Warnf("Error parsing custom interface definition (%v), skipping the interface %s", err, customIf)
			continue
		}
		if isAdd {
			n.podCustomIf[pod.ID.String()+customIf.ifName] = customIf
		} else {
			delete(n.podCustomIf, pod.ID.String()+customIf.ifName)
		}
		n.Log.Debugf("Configuring custom %s interface, name: %s, network: %s",
			customIf.ifType, customIf.ifName, customIf.ifNet)

		// allocate IP for the pod-side of the interface
		var podIP, podIPNet *net.IPNet
		if customIf.ifNet != stubNetworkName {
			if isAdd {
				_, err = n.IPAM.AllocatePodCustomIfIP(pod.ID, customIf.ifName, customIf.ifNet)
				if err != nil {
					n.Log.Warnf("%v, skipping the interface %s", err, customIf)
					continue
				}
			}
			podIP = n.IPAM.GetPodCustomIfIP(pod.ID, customIf.ifName, customIf.ifNet)
			if podIP == nil {
				n.Log.Warnf("No IP allocated for the interface %s, will be left in L2 mode", customIf)
			} else {
				podIPNet = &net.IPNet{IP: podIP.IP, Mask: n.IPAM.PodSubnetThisNode().Mask}
			}
		}

		switch customIf.ifType {
		case memifIfType:
			// handle custom memif interface
			if memifInfo == nil {
				memifInfo, err = n.DeviceManager.GetPodMemifInfo(pod.ID)
				if err != nil || memifInfo == nil {
					n.Log.Errorf("Couldn't retrieve pod memif information, skipping memif configuration")
					break
				}
			}
			// VPP side of the memif
			k, v := n.podVPPMemif(pod, podIPNet, customIf.ifName, memifInfo, memifID)
			config[k] = v
			// config for pod-side of the memif (if microservice label is defined)
			if serviceLabel != "" {
				k, memif := n.podMicroservioceMemif(pod, podIPNet, customIf.ifName, memifInfo, memifID)
				microserviceConfig[k] = memif

				k, route := n.podMicroservioceDefaultRoute(pod, customIf.ifName, customIf.ifType)
				microserviceConfig[k] = route
			}
			memifID++

		case tapIfType:
			// handle custom tap interface
			key, vppTap := n.podVPPTap(pod, podIPNet, customIf.ifName)
			config[key] = vppTap
			key, linuxTap := n.podLinuxTAP(pod, podIPNet, customIf.ifName)
			config[key] = linuxTap

		case vethIfType:
			// handle custom veth interface
			key, veth1 := n.podVeth1(pod, podIPNet, customIf.ifName)
			config[key] = veth1
			key, veth2 := n.podVeth2(pod, customIf.ifName)
			config[key] = veth2
			key, afpacket := n.podAfPacket(pod, podIPNet, customIf.ifName)
			config[key] = afpacket

		default:
			n.Log.Warnf("Unsupported custom interface type %s, skipping", customIf.ifType)
			continue
		}

		// route to pod IP from VPP
		if podIP != nil {
			key, vppRoute := n.vppToPodRoute(pod, podIP, customIf.ifName, customIf.ifType)
			config[key] = vppRoute
		}
	}

	// in case of non-empty microservice config, put the config into ETCD
	if len(microserviceConfig) > 0 {
		n.Log.Debugf("Adding pod-end interface config for microservice %s into ETCD", serviceLabel)
		txn := n.RemoteDB.NewBroker(servicelabel.GetDifferentAgentPrefix(serviceLabel)).NewTxn()
		for k, v := range microserviceConfig {
			if isAdd {
				txn.Put(k, v)
			} else {
				txn.Delete(k)
			}
		}
		err := txn.Commit(context.Background())
		if err != nil {
			n.Log.Errorf("Error by executing remote DB transaction: %v", err)
		}
	}

	return config
}

// getContivMicroserviceLabel returns microservice label defined in pod annotations
// (or an empty string if it is not defined).
func getContivMicroserviceLabel(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, contivMicroserviceLabel) {
			return v
		}
	}
	return ""
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

// parseCustomIfInfo parses custom interface annotation into individual parts.
func parseCustomIfInfo(ifAnnotation string) (ifInfo *podCustomIfInfo, err error) {
	ifParts := strings.Split(ifAnnotation, "/")
	if len(ifParts) < 2 {
		err = fmt.Errorf("invalid %s annotation value: %s", contivCustomIfAnnotation, ifAnnotation)
		return
	}

	ifInfo = &podCustomIfInfo{
		ifName: ifParts[0],
		ifType: ifParts[1],
	}

	if len(ifParts) > 2 {
		ifInfo.ifNet = ifParts[2]
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
func (n *IPNet) podVPPSideTAPName(pod *podmanager.LocalPod, customIfName string) string {
	if customIfName == "" {
		return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
	}
	return trimInterfaceName(podVPPSideTAPLogicalNamePrefix+customIfName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPSideTAPName returns logical name of the TAP interface of a given Pod connected to VPP.
func (n *IPNet) podLinuxSideTAPName(pod *podmanager.LocalPod, customIfName string) string {
	if customIfName == "" {
		return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
	}
	return trimInterfaceName(podLinuxSideTAPLogicalNamePrefix+customIfName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podVPPTap returns the configuration for TAP interface on the VPP side
// connecting a given Pod.
func (n *IPNet) podVPPTap(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName string) (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	tap := &vpp_interfaces.Interface{
		Name:        n.podVPPSideTAPName(pod, customIfName),
		Type:        vpp_interfaces.Interface_TAP,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, true),
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{
				EnableGso: interfaceCfg.EnableGSO,
			},
		},
	}
	if podIP != nil {
		tap.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		}
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
func (n *IPNet) podLinuxTAP(pod *podmanager.LocalPod, ip *net.IPNet, customIfName string) (key string, config *linux_interfaces.Interface) {
	tap := &linux_interfaces.Interface{
		Name:        n.podLinuxSideTAPName(pod, customIfName),
		Type:        linux_interfaces.Interface_TAP_TO_VPP,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: n.podVPPSideTAPName(pod, customIfName),
			},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if ip != nil {
		tap.IpAddresses = []string{ip.String()}
	}
	if customIfName != "" {
		tap.HostIfName = customIfName
	}
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

/************************* AF-Packet + VETH interfaces *************************/

// podAFPacketName returns logical name of AF-Packet interface connecting VPP with a given Pod.
func (n *IPNet) podAFPacketName(pod *podmanager.LocalPod, customIfName string) string {
	return trimInterfaceName(podAFPacketLogicalNamePrefix+n.podVeth2Name(pod, customIfName), logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the namespace of the given pod.
func (n *IPNet) podVeth1Name(pod *podmanager.LocalPod, customIfName string) string {
	if customIfName == "" {
		return trimInterfaceName(podVETH1LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
	}
	return trimInterfaceName(podVETH1LogicalNamePrefix+customIfName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth1Name returns logical name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPNet) podVeth2Name(pod *podmanager.LocalPod, customIfName string) string {
	if customIfName == "" {
		return trimInterfaceName(podVETH2LogicalNamePrefix+pod.ContainerID, logicalIfNameMaxLen)
	}
	return trimInterfaceName(podVETH2LogicalNamePrefix+customIfName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podVeth2HostIfName returns host name of the VETH interface in the default namespace
// connecting the given pod.
func (n *IPNet) podVeth2HostIfName(pod *podmanager.LocalPod, customIfName string) string {
	if customIfName == "" {
		return trimInterfaceName(pod.ContainerID, linuxIfNameMaxLen)
	}
	return trimInterfaceName(customIfName+"-"+pod.ContainerID, linuxIfNameMaxLen)
}

// podVeth1 returns the configuration for pod-side of the VETH interface
// connecting the given pod with VPP.
func (n *IPNet) podVeth1(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName string) (key string, config *linux_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	veth := &linux_interfaces.Interface{
		Name:        n.podVeth1Name(pod, customIfName),
		Type:        linux_interfaces.Interface_VETH,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, false),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth2Name(pod, customIfName)},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if podIP != nil {
		veth.IpAddresses = []string{podIP.String()}
	}
	if customIfName != "" {
		veth.HostIfName = customIfName
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
func (n *IPNet) podVeth2(pod *podmanager.LocalPod, customIfName string) (key string, config *linux_interfaces.Interface) {
	veth := &linux_interfaces.Interface{
		Name:       n.podVeth2Name(pod, customIfName),
		Type:       linux_interfaces.Interface_VETH,
		Mtu:        n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:    true,
		HostIfName: n.podVeth2HostIfName(pod, customIfName),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth1Name(pod, customIfName)},
		},
	}
	key = linux_interfaces.InterfaceKey(veth.Name)
	return key, veth
}

func (n *IPNet) podAfPacket(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName string) (key string, config *vpp_interfaces.Interface) {
	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	afpacket := &vpp_interfaces.Interface{
		Name:        n.podAFPacketName(pod, customIfName),
		Type:        vpp_interfaces.Interface_AF_PACKET,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, true),
		Link: &vpp_interfaces.Interface_Afpacket{
			Afpacket: &vpp_interfaces.AfpacketLink{
				HostIfName: n.podVeth2HostIfName(pod, customIfName),
			},
		},
	}
	if podIP != nil {
		afpacket.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		}
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

// podVPPSideTAPName returns logical name of the memif interface on VPP connected to a given pod.
func (n *IPNet) podVPPSideMemifName(pod *podmanager.LocalPod, ifName string) string {
	return trimInterfaceName(podMemifLogicalNamePrefix+ifName+"-"+pod.ContainerID, logicalIfNameMaxLen)
}

// podMicroserviceSideMemifName returns logical name of the memif interface in microservice running in a given pod.
func (n *IPNet) podMicroserviceSideMemifName(pod *podmanager.LocalPod, ifName string) string {
	return trimInterfaceName(podMemifLogicalNamePrefix+ifName, logicalIfNameMaxLen)
}

// podVPPMemif returns the configuration for memif interface on the VPP side connecting a given Pod.
func (n *IPNet) podVPPMemif(pod *podmanager.LocalPod, podIP *net.IPNet, ifName string,
	memifInfo *devicemanager.MemifInfo, memifID uint32) (key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	memif := &vpp_interfaces.Interface{
		Name:    n.podVPPSideMemifName(pod, ifName),
		Type:    vpp_interfaces.Interface_MEMIF,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().PodVRFID,
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
	if podIP != nil {
		memif.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: podGwLoopbackInterfaceName,
		}
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		memif.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(memif.Name)
	return key, memif
}

// podMicroservioceMemif returns the configuration for memif interface on the Pod (microservice) side.
func (n *IPNet) podMicroservioceMemif(pod *podmanager.LocalPod, ip *net.IPNet, ifName string,
	memifInfo *devicemanager.MemifInfo, memifID uint32) (key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	memif := &vpp_interfaces.Interface{
		Name:    n.podMicroserviceSideMemifName(pod, ifName),
		Type:    vpp_interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Memif{
			Memif: &vpp_interfaces.MemifLink{
				Master:         false,
				Mode:           vpp_interfaces.MemifLink_ETHERNET,
				SocketFilename: memifInfo.ContainerSocket,
				Secret:         memifInfo.Secret,
				Id:             memifID,
			},
		},
	}
	if ip != nil {
		memif.IpAddresses = []string{ip.String()}
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxModeSettings_DEFAULT {
		memif.RxModeSettings = &vpp_interfaces.Interface_RxModeSettings{
			RxMode: interfaceRxModeType(interfaceCfg.InterfaceRxMode),
		}
	}
	key = vpp_interfaces.InterfaceKey(memif.Name)
	return key, memif
}

// podMicroservioceDefaultRoute returns configuration for default route used on the Pod (microservice) side.
func (n *IPNet) podMicroservioceDefaultRoute(pod *podmanager.LocalPod, customIfName, customIfType string) (key string, config *vpp_l3.Route) {
	_, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	route := &vpp_l3.Route{
		OutgoingInterface: ifName,
		DstNetwork:        anyNetAddrForAF(n.IPAM.PodGatewayIP()),
		NextHopAddr:       n.IPAM.PodGatewayIP().String(),
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

/***************************** Pod ARPs and routes *****************************/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (n *IPNet) podToVPPArpEntry(pod *podmanager.LocalPod) (key string, config *linux_l3.ARPEntry) {
	_, linuxIfName := n.podInterfaceName(pod, "", "")
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
	_, linuxIfName := n.podInterfaceName(pod, "", "")
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
	_, linuxIfName := n.podInterfaceName(pod, "", "")
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
	vppIfName, _ := n.podInterfaceName(pod, "", "")
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
func (n *IPNet) vppToPodRoute(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName, customIfType string) (key string, config *vpp_l3.Route) {
	podVPPIfName, _ := n.podInterfaceName(pod, customIfName, customIfType)
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
