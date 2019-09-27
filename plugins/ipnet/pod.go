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
	"bytes"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/db/keyval"
	"hash/fnv"
	"net"
	"os/exec"
	"sort"
	"strings"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/devicemanager"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"github.com/ligato/vpp-agent/api/models/netalloc"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/pkg/models"
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

	// DefaultPodNetworkName is the network name dedicated to the default pod network
	DefaultPodNetworkName = "default"

	// prefix attached to custom network names inside IP allocations exposed by Contiv for CNFs
	ipAllocNetPrefix = "contiv-"
)

const (
	ipv4LoopbackAddress = "127.0.0.1/8"
	ipv6LoopbackAddress = "::1/128"
)

const (
	contivAnnotationPrefix            = "contivpp.io/"
	contivMicroserviceLabelAnnotation = contivAnnotationPrefix + "microservice-label"  // k8s annotation used to specify microservice label of a pod
	contivServiceEndpointIfAnnotation = contivAnnotationPrefix + "service-endpoint-if" // k8s annotation used to specify k8s service endpoint interface
	contivCustomIfAnnotation          = contivAnnotationPrefix + "custom-if"           // k8s annotation used to request custom pod interfaces
	contivCustomIfSeparator           = ","                                            // separator used to split multiple interfaces in k8s annotation

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
	var vppInterfaceToPod string
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		// TAP
		key, vppTap := n.podVPPTap(pod, podIP, "", DefaultPodNetworkName)
		config[key] = vppTap
		key, linuxTap := n.podLinuxTAP(pod, podIP, "", false)
		config[key] = linuxTap
		vppInterfaceToPod = vppTap.Name
	} else {
		// VETH pair + AF_PACKET
		key, veth1 := n.podVeth1(pod, podIP, "", false)
		config[key] = veth1
		key, veth2 := n.podVeth2(pod, "")
		config[key] = veth2
		key, afpacket := n.podAfPacket(pod, podIP, "", DefaultPodNetworkName)
		config[key] = afpacket
		vppInterfaceToPod = afpacket.Name
	}

	// ARP to VPP
	key, podArp := n.podToVPPArpEntry(pod, "", "", DefaultPodNetworkName)
	config[key] = podArp

	// link scope route
	key, route := n.podToVPPLinkRoute(pod, "", "", DefaultPodNetworkName)
	config[key] = route

	// Add default route for the container
	key, route = n.podToVPPDefaultRoute(pod, "", "", DefaultPodNetworkName)
	config[key] = route

	// ARP entry for POD IP
	key, vppArp := n.vppToPodArpEntry(pod, podIP, "", "")
	config[key] = vppArp

	// route to PodIP via AF_PACKET / TAP
	key, vppRoute := n.vppToPodRoute(pod, podIP, "", "", n.ContivConf.GetRoutingConfig().PodVRFID)
	config[key] = vppRoute

	// /32 (or /128 for ipv6) route from the host to POD (only in external IPAM case)
	if n.ContivConf.GetIPAMConfig().UseExternalIPAM {
		key, route := n.hostToPodRoute(pod)
		config[key] = route
	}

	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.SRv6Transport &&
		n.ContivConf.GetRoutingConfig().UseDX6ForSrv6NodetoNodeTransport {
		// create localsid with DX6 end function (decapsulate and crossconnect to interface of local pod)
		// -used for pod-to-pod communication
		podSid := n.IPAM.SidForNodeToNodePodLocalsid(podIP.IP)
		key, podLocalsid, err := n.srv6DX6PodTunnelEgress(podSid, vppInterfaceToPod, podIP.IP)
		if err != nil {
			n.Log.Errorf("can't create egress configuration part of SRv6 node-to-node tunnel ending with DX6 targeting interface to pod: %v", err)
		} else {
			config[key] = podLocalsid
		}
	}

	return config
}

// podInterfaceName returns logical names of interfaces on both sides
// of the interconnection between VPP and the given Pod.
func (n *IPNet) podInterfaceName(pod *podmanager.LocalPod, customIfName, customIfType string) (vppIfName, podIfName, msIfName string) {
	if customIfType == memifIfType {
		vppIfName = n.podVPPSideMemifName(pod, customIfName)
		msIfName = n.podMicroserviceSideIfName(pod, customIfName)
		// nothing configured by vswitch on the pod side in the memif case
		podIfName = ""
		return
	}
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces && customIfType != vethIfType {
		vppIfName = n.podVPPSideTAPName(pod, customIfName)
		podIfName = n.podLinuxSideTAPName(pod, customIfName)
		msIfName = n.podMicroserviceSideIfName(pod, customIfName)
		return

	}

	// AF-PACKET + VETH
	vppIfName = n.podAFPacketName(pod, customIfName)
	podIfName = n.podVeth1Name(pod, customIfName)
	msIfName = n.podMicroserviceSideIfName(pod, customIfName)
	return
}

func (n *IPNet) podCustomInterfaceHostName(pod *podmanager.LocalPod, ifName string) string {
	return trimInterfaceName(ifName, linuxIfNameMaxLen)
}

/****************************** Pod custom interfaces configuration ******************************/

// podCustomIfsConfig returns configuration for custom interfaces connectivity.
// If no custom interfaces are requested, returns empty config.
// - config contains config to be added/deleted
// - updateConfig contains config to be updated (by any operation)
func (n *IPNet) podCustomIfsConfig(pod *podmanager.LocalPod, eventType configEventType) (config, updateConfig controller.KeyValuePairs) {
	var (
		memifID   uint32
		memifInfo *devicemanager.MemifInfo
	)
	if pod == nil {
		return
	}
	podMeta, hadPodMeta := n.PodManager.GetPods()[pod.ID]
	if !hadPodMeta {
		return
	}

	config = make(controller.KeyValuePairs)
	updateConfig = make(controller.KeyValuePairs)
	microserviceConfig := make(controller.KeyValuePairs)

	customIfs := getContivCustomIfs(podMeta.Annotations)
	serviceLabel := getContivMicroserviceLabel(podMeta.Annotations)
	serviceEndpointIf := getContivServiceEndpointIf(podMeta.Annotations)

	for _, customIfStr := range customIfs {
		customIf, err := parseCustomIfInfo(customIfStr)
		if err != nil {
			n.Log.Warnf("Error parsing custom interface definition (%v), skipping the interface %s", err, customIf)
			continue
		}
		if eventType != configDelete {
			n.podCustomIf[pod.ID.String()+customIf.ifName] = customIf

			n.Log.Debugf("Configuring custom %s interface, name: %s, network: %s",
				customIf.ifType, customIf.ifName, customIf.ifNet)
		} else {
			delete(n.podCustomIf, pod.ID.String()+customIf.ifName)

			n.Log.Debugf("Deleting custom %s interface, name: %s, network: %s",
				customIf.ifType, customIf.ifName, customIf.ifNet)
		}

		isServiceEndpoint := n.isDefaultPodNetwork(customIf.ifNet) && (customIf.ifName == serviceEndpointIf)
		var podIP *net.IPNet
		if n.isDefaultPodNetwork(customIf.ifNet) || n.isL3Network(customIf.ifNet) {
			// in case of default / L3 network, allocate pod IP
			podIP, err = n.getOrAllocatePodCustomIfIP(pod, customIf, eventType == configAdd, isServiceEndpoint)
			if err != nil || podIP == nil {
				n.Log.Warnf("No IP allocated for the interface %s, will be left in L2 mode", customIf)
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
			k, v := n.podVPPMemif(pod, podIP, customIf.ifName, customIf.ifNet, memifInfo, memifID)
			config[k] = v
			memifID++

		case tapIfType:
			// handle custom tap interface
			key, vppTap := n.podVPPTap(pod, podIP, customIf.ifName, customIf.ifNet)
			config[key] = vppTap
			key, linuxTap := n.podLinuxTAP(pod, podIP, customIf.ifName, serviceLabel != "")
			config[key] = linuxTap

		case vethIfType:
			// handle custom veth interface
			key, veth1 := n.podVeth1(pod, podIP, customIf.ifName, serviceLabel != "")
			config[key] = veth1
			key, veth2 := n.podVeth2(pod, customIf.ifName)
			config[key] = veth2
			key, afpacket := n.podAfPacket(pod, podIP, customIf.ifName, customIf.ifNet)
			config[key] = afpacket

		default:
			n.Log.Warnf("Unsupported custom interface type %s, skipping", customIf.ifType)
			continue
		}

		// VPP side of the custom interface
		if podIP != nil {
			// route to pod IP from VPP
			vrf, _ := n.getOrAllocateVrfID(customIf.ifNet)
			key, vppRoute := n.vppToPodRoute(pod, podIP, customIf.ifName, customIf.ifType, vrf)
			config[key] = vppRoute
			// static ARP entry to pod IP from VPP
			if customIf.ifType != memifIfType && serviceLabel == "" {
				// only if the vswitch manages the pod interface (veth/tap without servicelabel)
				// TODO: enable also for the case with defined service label once netalloc supports MAC addresses
				key, vppArp := n.vppToPodArpEntry(pod, podIP, customIf.ifName, customIf.ifType)
				config[key] = vppArp
			}
		}
		if !n.isDefaultPodNetwork(customIf.ifNet) && !n.isStubNetwork(customIf.ifNet) {
			// post-configure interface in custom network
			vppIfName, _, _ := n.podInterfaceName(pod, customIf.ifName, customIf.ifType)
			n.cacheCustomNetworkInterface(customIf.ifNet, pod, nil, vppIfName, eventType != configDelete)
			if n.isL2Network(customIf.ifNet) {
				bdKey, bd := n.l2CustomNwBridgeDomain(n.customNetworks[customIf.ifNet])
				updateConfig[bdKey] = bd
			}
		}

		// pod-side of the custom interface
		if serviceLabel == "" {
			// microservice label not defined - the pod interface is:
			//  a) fully configured by the contiv-vswitch (linux interfaces)
			//  b) memif outside of our control
			if customIf.ifType != memifIfType && podIP != nil {
				linuxCfg := n.linuxPodL3CustomIfConfig(pod, customIf)
				mergeConfiguration(config, linuxCfg)
			}
		}
		if serviceLabel != "" {
			// if microservice label is defined, it is assumed that a ligato-based CNF is running inside the pod
			// and the non-link side of the interface will be managed by the agent of that CNF
			if customIf.ifType == memifIfType {
				// MEMIF microservice
				k, memif := n.podMicroserviceMemif(pod, podIP, customIf.ifName, memifInfo, memifID)
				microserviceConfig[k] = memif
				if podIP != nil {
					linuxCfg := n.vppPodL3CustomIfConfig(pod, customIf)
					mergeConfiguration(microserviceConfig, linuxCfg)
				}
			} else {
				// TAP / VETH microservice
				k, iface := n.podMicroserviceLinuxIface(pod, podIP, customIf.ifName, customIf.ifType)
				microserviceConfig[k] = iface
				if podIP != nil {
					linuxCfg := n.linuxPodL3CustomIfConfig(pod, customIf)
					mergeConfiguration(microserviceConfig, linuxCfg)
				}
			}
			if podIP != nil {
				// expose IP address to the pod via netalloc plugin
				//  - ligato-based CNF can reference the allocated IP from inside of VPP/Linux models
				//  - non-ligato CNF can read the allocated IP from etcd
				k, alloc := n.podMicroserviceIPAlloc(pod, podIP, customIf.ifName, customIf.ifType, customIf.ifNet)
				microserviceConfig[k] = alloc
			}
		}
	}

	// in case of non-empty microservice config, put the config into ETCD
	if len(microserviceConfig) > 0 {
		n.Log.Debugf("Adding pod-end interface config for microservice %s into ETCD", serviceLabel)
		broker := n.RemoteDB.NewBrokerWithAtomic(servicelabel.GetDifferentAgentPrefix(serviceLabel))
		for k, v := range microserviceConfig {
			err := n.updateMsConfigItem(broker, k, v, eventType)
			if err != nil {
				n.Log.Errorf("Error by executing remote DB operation for key %s: %v", k, err)
			}
		}
	}

	return
}

// getOrAllocatePodCustomIfIP retrieves or allocates custom pod interface IP address.
func (n *IPNet) getOrAllocatePodCustomIfIP(pod *podmanager.LocalPod, customIf *podCustomIfInfo,
	allocate, isServiceEndpoint bool) (podIP *net.IPNet, err error) {

	if allocate {
		ip, err := n.IPAM.AllocatePodCustomIfIP(pod.ID, customIf.ifName, customIf.ifNet, isServiceEndpoint)
		if err != nil {
			n.Log.Warnf("Unable to allocate IP for custom interface %s: %v", customIf.ifName, err)
			return nil, err
		}
		n.Log.Debugf("IP allocated for the custom interface %s: %s", customIf.ifName, ip.String())
	}

	podIP = n.IPAM.GetPodCustomIfIP(pod.ID, customIf.ifName, customIf.ifNet)
	if podIP != nil {
		_, podIP, _ = net.ParseCIDR(podIP.IP.String() + hostPrefixForAF(podIP.IP))
	}
	return
}

// linuxPodL3CustomIfConfig returns L3 config of a custom interface for a linux (non-VPP) pod.
func (n *IPNet) linuxPodL3CustomIfConfig(pod *podmanager.LocalPod, customIf *podCustomIfInfo) controller.KeyValuePairs {
	config := make(controller.KeyValuePairs)

	// ARP entry for the GW
	key, podArp := n.podToVPPArpEntry(pod, customIf.ifName, customIf.ifType, customIf.ifNet)
	config[key] = podArp

	// link scope route for the GW
	key, route := n.podToVPPLinkRoute(pod, customIf.ifName, customIf.ifType, customIf.ifNet)
	config[key] = route

	// route for the whole L3 subnet
	key, route = n.podToVPPRoute(pod, customIf.ifName, customIf.ifType, customIf.ifNet,
		n.IPAM.PodSubnetAllNodes(customIf.ifNet))
	config[key] = route

	return config
}

// vppPodL3CustomIfConfig returns L3 config of a custom interface for a VPP pod.
func (n *IPNet) vppPodL3CustomIfConfig(pod *podmanager.LocalPod, customIf *podCustomIfInfo) controller.KeyValuePairs {
	config := make(controller.KeyValuePairs)

	// ARP entry for the GW
	k, arp := n.podMicroserviceGatewayARP(pod, customIf.ifName, customIf.ifType, customIf.ifNet)
	config[k] = arp

	// route for the whole L3 subnet
	k, route := n.podMicroserviceRoute(pod, customIf.ifName, customIf.ifType, customIf.ifNet,
		n.IPAM.PodSubnetAllNodes(customIf.ifNet))
	config[k] = route

	return config
}

// updateMsConfigItem updates configuration written to etcd for a (ligato-based) microservice to apply.
// If the configuration item is managed from outside of Contiv (e.g. CustomConfiguration CRD), the value will not be
// changed.
func (n *IPNet) updateMsConfigItem(broker keyval.BytesBrokerWithAtomic, key string, value proto.Message, eventType configEventType) error {
	var succeeded bool
	serializer := keyval.SerializerJSON{}

	binData, err := serializer.Marshal(value)
	if err != nil {
		return err
	}
	prevData, hasPrevData := n.microserviceConfig[key]

	if eventType != configDelete {
		if !hasPrevData {
			succeeded, err = broker.PutIfNotExists(key, binData)
			if err != nil {
				return err
			}
			if !succeeded {
				// n.microserviceConfig might be out of sync (e.g. after vswitch restart)
				// - check if it is the same as expected
				data, found, _, err := broker.GetValue(key)
				if err != nil {
					return err
				}
				if found && bytes.Equal(data, binData) {
					succeeded = true
				}
			}
		} else {
			succeeded, err = broker.CompareAndSwap(key, prevData, binData)
			if err != nil {
				return err
			}
		}
		if succeeded {
			n.microserviceConfig[key] = binData
		} else {
			// giving up on this config, it is probably managed via CustomConfiguration CRD
			delete(n.microserviceConfig, key)
		}
	} else {
		// try to delete
		if hasPrevData {
			_, err = broker.CompareAndDelete(key, prevData)
			delete(n.microserviceConfig, key)
		}
	}
	return err
}

// getContivMicroserviceLabel returns microservice label defined in pod annotations
// (or an empty string if it is not defined).
func getContivMicroserviceLabel(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, contivMicroserviceLabelAnnotation) {
			return v
		}
	}
	return ""
}

// getContivServiceEndpointIf returns service endpoint interface defined in pod annotations
// (or an empty string if it is not defined).
func getContivServiceEndpointIf(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, contivServiceEndpointIfAnnotation) {
			return v
		}
	}
	return ""
}

// hasContivCustomIfAnnotation returns true if provided annotations contain contiv custom-if annotation, false otherwise.
func hasContivCustomIfAnnotation(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, contivCustomIfAnnotation) {
			return true
		}
	}
	return false
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
	} else {
		ifInfo.ifNet = DefaultPodNetworkName
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
func (n *IPNet) podVPPTap(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName, customIfNw string) (
	key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	tap := &vpp_interfaces.Interface{
		Name:        n.podVPPSideTAPName(pod, customIfName),
		Type:        vpp_interfaces.Interface_TAP,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, customIfName, true),
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{
				EnableGso: interfaceCfg.EnableGSO,
			},
		},
	}
	if podIP != nil {
		tap.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: n.podGwLoopbackInterfaceName(customIfNw),
		}
	}
	if interfaceCfg.TAPInterfaceVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(interfaceCfg.TAPv2RxRingSize)
		tap.GetTap().TxRingSize = uint32(interfaceCfg.TAPv2TxRingSize)
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxMode_DEFAULT {
		tap.RxModes = []*vpp_interfaces.Interface_RxMode{
			{
				DefaultMode: true,
				Mode:        interfaceRxModeType(interfaceCfg.InterfaceRxMode),
			},
		}
	}
	key = vpp_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// podLinuxTAP returns the configuration for TAP interface on the Linux side
// connecting a given Pod to VPP.
func (n *IPNet) podLinuxTAP(pod *podmanager.LocalPod, ip *net.IPNet, customIfName string, linkOnly bool) (
	key string, config *linux_interfaces.Interface) {

	tap := &linux_interfaces.Interface{
		Name:        n.podLinuxSideTAPName(pod, customIfName),
		Type:        linux_interfaces.Interface_TAP_TO_VPP,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, customIfName, false),
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: n.podVPPSideTAPName(pod, customIfName),
			},
		},
		LinkOnly: linkOnly,
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if ip != nil && !linkOnly {
		tap.IpAddresses = []string{ip.String()}
	}
	if customIfName != "" {
		tap.HostIfName = n.podCustomInterfaceHostName(pod, customIfName)
	}
	if linkOnly {
		tap.PhysAddress = ""
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
func (n *IPNet) podVeth1(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName string, linkOnly bool) (
	key string, config *linux_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	veth := &linux_interfaces.Interface{
		Name:        n.podVeth1Name(pod, customIfName),
		Type:        linux_interfaces.Interface_VETH,
		Mtu:         interfaceCfg.MTUSize,
		Enabled:     true,
		HostIfName:  podInterfaceHostName,
		PhysAddress: n.hwAddrForPod(pod, customIfName, false),
		Link: &linux_interfaces.Interface_Veth{
			Veth: &linux_interfaces.VethLink{PeerIfName: n.podVeth2Name(pod, customIfName)},
		},
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
	}
	if podIP != nil && !linkOnly {
		veth.IpAddresses = []string{podIP.String()}
	}
	if customIfName != "" {
		veth.HostIfName = n.podCustomInterfaceHostName(pod, customIfName)
	}
	if linkOnly {
		veth.PhysAddress = ""
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

func (n *IPNet) podAfPacket(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName, customIfNw string) (
	key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	afpacket := &vpp_interfaces.Interface{
		Name:        n.podAFPacketName(pod, customIfName),
		Type:        vpp_interfaces.Interface_AF_PACKET,
		Mtu:         n.ContivConf.GetInterfaceConfig().MTUSize,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, customIfName, true),
		Link: &vpp_interfaces.Interface_Afpacket{
			Afpacket: &vpp_interfaces.AfpacketLink{
				HostIfName: n.podVeth2HostIfName(pod, customIfName),
			},
		},
	}
	if podIP != nil {
		afpacket.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
			InterfaceWithIp: n.podGwLoopbackInterfaceName(customIfNw),
		}
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxMode_DEFAULT {
		afpacket.RxModes = []*vpp_interfaces.Interface_RxMode{
			{
				DefaultMode: true,
				Mode:        interfaceRxModeType(interfaceCfg.InterfaceRxMode),
			},
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

// podVPPMemif returns the configuration for memif interface on the VPP side connecting a given Pod.
func (n *IPNet) podVPPMemif(pod *podmanager.LocalPod, podIP *net.IPNet, ifName, ifNw string,
	memifInfo *devicemanager.MemifInfo, memifID uint32) (key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	memif := &vpp_interfaces.Interface{
		Name:        n.podVPPSideMemifName(pod, ifName),
		Type:        vpp_interfaces.Interface_MEMIF,
		Enabled:     true,
		Vrf:         n.ContivConf.GetRoutingConfig().PodVRFID,
		PhysAddress: n.hwAddrForPod(pod, ifName, true),
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
			InterfaceWithIp: n.podGwLoopbackInterfaceName(ifNw),
		}
	}
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxMode_DEFAULT {
		memif.RxModes = []*vpp_interfaces.Interface_RxMode{
			{
				DefaultMode: true,
				Mode:        interfaceRxModeType(interfaceCfg.InterfaceRxMode),
			},
		}
	}
	key = vpp_interfaces.InterfaceKey(memif.Name)
	return key, memif
}

/************************** microservice config *******************************/

// podMicroserviceSideIfName returns logical name of a custom interface in the namespace of a microservice
// running inside a given pod.
func (n *IPNet) podMicroserviceSideIfName(pod *podmanager.LocalPod, ifName string) string {
	return trimInterfaceName(ifName, logicalIfNameMaxLen)
}

// podMicroserviceMemif returns the configuration for memif interface on the Pod (microservice) side.
func (n *IPNet) podMicroserviceMemif(pod *podmanager.LocalPod, ip *net.IPNet, ifName string,
	memifInfo *devicemanager.MemifInfo, memifID uint32) (key string, config *vpp_interfaces.Interface) {

	interfaceCfg := n.ContivConf.GetInterfaceConfig()
	_, _, ifName = n.podInterfaceName(pod, ifName, memifIfType)
	memif := &vpp_interfaces.Interface{
		Name:    ifName,
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
	if interfaceRxModeType(interfaceCfg.InterfaceRxMode) != vpp_interfaces.Interface_RxMode_DEFAULT {
		memif.RxModes = []*vpp_interfaces.Interface_RxMode{
			{
				DefaultMode: true,
				Mode:        interfaceRxModeType(interfaceCfg.InterfaceRxMode),
			},
		}
	}
	// TODO: use hwAddrForPod to configure HW address (and add static ARP entry),
	//       but only once netalloc supports allocation of MAC addresses
	key = vpp_interfaces.InterfaceKey(memif.Name)
	return key, memif
}

// podMicroserviceTapOrVeth returns the configuration for Linux interface (TAP or VETH) on the Pod (microservice) side.
func (n *IPNet) podMicroserviceLinuxIface(pod *podmanager.LocalPod, ip *net.IPNet, customIfName,
	customIfType string) (key string, config *linux_interfaces.Interface) {

	_, _, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	tap := &linux_interfaces.Interface{
		Name:       ifName,
		Type:       linux_interfaces.Interface_EXISTING,
		Enabled:    true,
		HostIfName: n.podCustomInterfaceHostName(pod, customIfName),
	}
	if ip != nil {
		tap.IpAddresses = []string{ip.String()}
	}
	// TODO: use hwAddrForPod to configure HW address (and add static ARP entry),
	//       but only once netalloc supports allocation of MAC addresses
	key = linux_interfaces.InterfaceKey(tap.Name)
	return key, tap
}

// podMicroserviceGatewayARP returns configuration for a static arp entry for the default gateway of the Pod (microservice).
func (n *IPNet) podMicroserviceGatewayARP(pod *podmanager.LocalPod, customIfName, customIfType, customIfNw string) (
	key string, config *vpp_l3.ARPEntry) {

	_, _, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	arp := &vpp_l3.ARPEntry{
		Interface:   ifName,
		IpAddress:   n.IPAM.PodGatewayIP(customIfNw).String(),
		PhysAddress: n.hwAddrForPod(pod, customIfName, true),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podMicroserviceLinuxGatewayARP returns configuration for a Linux static arp entry
// for the default gateway of the Pod (microservice).
func (n *IPNet) podMicroserviceLinuxGatewayARP(pod *podmanager.LocalPod, customIfName,
	customIfType, customIfNw string) (key string, config *linux_l3.ARPEntry) {

	_, _, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	arp := &linux_l3.ARPEntry{
		Interface: ifName,
		IpAddress: n.IPAM.PodGatewayIP(customIfNw).String(),
		HwAddress: n.hwAddrForPod(pod, customIfName, true),
	}
	key = models.Key(arp)
	return key, arp
}

// podMicroserviceRoute returns configuration for a route used on the Pod (microservice) side.
func (n *IPNet) podMicroserviceRoute(pod *podmanager.LocalPod, customIfName,
	customIfType, customIfNw string, dstNet *net.IPNet) (key string, config *vpp_l3.Route) {

	_, _, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	route := &vpp_l3.Route{
		OutgoingInterface: ifName,
		DstNetwork:        dstNet.String(),
		NextHopAddr:       n.IPAM.PodGatewayIP(customIfNw).String(),
	}
	key = models.Key(route)
	return key, route
}

// podMicroserviceIPAlloc returns IP allocation entry for an address allocated to a custom pod interface.
func (n *IPNet) podMicroserviceIPAlloc(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName string,
	customIfType string, customIfNw string) (key string, config *netalloc.IPAllocation) {

	if customIfNw == "" {
		customIfNw = DefaultPodNetworkName
	}
	netLabel := ipAllocNetPrefix + customIfNw
	_, _, ifName := n.podInterfaceName(pod, customIfName, customIfType)
	alloc := &netalloc.IPAllocation{
		NetworkName:   netLabel,
		InterfaceName: ifName,
		Address:       podIP.String(),
		Gw:            n.IPAM.PodGatewayIP(customIfNw).String() + hostPrefixForAF(n.IPAM.PodGatewayIP(customIfNw)),
	}
	key = models.Key(alloc)
	return key, alloc
}

/***************************** Pod ARPs and routes *****************************/

// podToVPPArpEntry returns configuration for ARP entry resolving hardware address
// for pod gateway IP from VPP.
func (n *IPNet) podToVPPArpEntry(pod *podmanager.LocalPod, customIfName, customIfType, customIfNw string) (
	key string, config *linux_l3.ARPEntry) {

	_, linuxIfName, _ := n.podInterfaceName(pod, customIfName, customIfType)
	arp := &linux_l3.ARPEntry{
		Interface: linuxIfName,
		IpAddress: n.IPAM.PodGatewayIP(customIfNw).String(),
		HwAddress: n.hwAddrForPod(pod, customIfName, true),
	}
	key = linux_l3.ArpKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// podToVPPLinkRoute returns configuration for route that puts pod's default GW behind
// the interface connecting pod with VPP (even though the GW IP does not fall into
// the pod IP address network).
func (n *IPNet) podToVPPLinkRoute(pod *podmanager.LocalPod, customIfName, customIfType, customIfNw string) (
	key string, config *linux_l3.Route) {
	_, linuxIfName, _ := n.podInterfaceName(pod, customIfName, customIfType)
	route := &linux_l3.Route{
		OutgoingInterface: linuxIfName,
		Scope:             linux_l3.Route_LINK,
		DstNetwork:        n.IPAM.PodGatewayIP(customIfNw).String() + hostPrefixForAF(n.IPAM.PodGatewayIP(customIfNw)),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPDefaultRoute returns configuration for the default route of the given pod.
func (n *IPNet) podToVPPDefaultRoute(pod *podmanager.LocalPod, customIfName, customIfType, customIfNw string) (
	key string, config *linux_l3.Route) {
	_, linuxIfName, _ := n.podInterfaceName(pod, customIfName, customIfType)
	route := &linux_l3.Route{
		OutgoingInterface: linuxIfName,
		DstNetwork:        anyNetAddrForAF(n.IPAM.PodGatewayIP(customIfNw)),
		Scope:             linux_l3.Route_GLOBAL,
		GwAddr:            n.IPAM.PodGatewayIP(customIfNw).String(),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

// podToVPPRoute returns configuration for a route towards VPP of the given pod.
func (n *IPNet) podToVPPRoute(pod *podmanager.LocalPod, customIfName, customIfType, customIfNw string, dstNet *net.IPNet) (
	key string, config *linux_l3.Route) {
	_, linuxIfName, _ := n.podInterfaceName(pod, customIfName, customIfType)
	route := &linux_l3.Route{
		OutgoingInterface: linuxIfName,
		DstNetwork:        dstNet.String(),
		Scope:             linux_l3.Route_GLOBAL,
		GwAddr:            n.IPAM.PodGatewayIP(customIfNw).String(),
	}
	key = linux_l3.RouteKey(route.DstNetwork, route.OutgoingInterface)
	return key, route
}

/*************************** VSwitch ARPs and routes ***************************/

// vppToPodArpEntry return configuration for ARP entry used in VPP to resolve
// hardware address from the IP address of the given pod.
func (n *IPNet) vppToPodArpEntry(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName,
	customIfType string) (key string, config *vpp_l3.ARPEntry) {

	vppIfName, _, _ := n.podInterfaceName(pod, customIfName, customIfType)
	arp := &vpp_l3.ARPEntry{
		Interface:   vppIfName,
		IpAddress:   podIP.IP.String(),
		PhysAddress: n.hwAddrForPod(pod, customIfName, false),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vppToPodRoute return configuration for route used in VPP to direct traffic destinated
// to the IP address of the given pod.
func (n *IPNet) vppToPodRoute(pod *podmanager.LocalPod, podIP *net.IPNet, customIfName,
	customIfType string, vrf uint32) (key string, config *vpp_l3.Route) {

	podVPPIfName, _, _ := n.podInterfaceName(pod, customIfName, customIfType)
	route := &vpp_l3.Route{
		OutgoingInterface: podVPPIfName,
		DstNetwork:        podIP.String(),
		NextHopAddr:       podIP.IP.String(),
		VrfId:             vrf,
	}
	key = models.Key(route)
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
func (n *IPNet) hwAddrForPod(pod *podmanager.LocalPod, customIfName string, vppSide bool) string {
	hwAddr := make(net.HardwareAddr, 6)
	h := fnv.New32a()
	h.Write([]byte(pod.ContainerID + "/" + customIfName))
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
