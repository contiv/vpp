// Copyright (c) 2018 Cisco and/or its affiliates.
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

//go:generate protoc -I ./ipalloc --gogo_out=plugins=grpc:./ipalloc ./ipalloc/ipalloc.proto
//go:generate protoc -I ./vnialloc --gogo_out=plugins=grpc:./vnialloc ./vnialloc/vnialloc.proto

package ipam

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/apparentlymart/go-cidr/cidr"
	cnisb "github.com/containernetworking/cni/pkg/types/current"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	customnetmodel "github.com/contiv/vpp/plugins/crd/handler/customnetwork/model"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	"github.com/contiv/vpp/plugins/ksr"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/go-errors/errors"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
)

const (
	// sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)
	podGatewaySeqID = 1

	// sequence ID reserved for VPP-end of the VPP to host interconnect
	hostInterconnectInVPPIPSeqID = 1

	// sequence ID reserved for host(Linux)-end of the VPP to host interconnect
	hostInterconnectInLinuxIPSeqID = 2

	defaultPodNetworkName = "default" // name of the default pod network
)

// IPAM plugin implements IP address allocation for Contiv.
type IPAM struct {
	Deps

	mutex    sync.RWMutex
	dbBroker keyval.ProtoBroker

	excludedIPsfromNodeSubnet []net.IP // IPs from the NodeInterconnect Subnet that should not be assigned

	/********** POD related variables **********/
	podNetworks map[string]*podNetworkInfo

	/********** maps to convert between Pod and the assigned IP **********/
	// pool of assigned POD IP addresses
	assignedPodIPs map[string]*podIPAllocation
	// pod -> allocated IP address
	podToIP map[podmodel.ID]*podIPInfo
	// remote pod IP info
	remotePodToIP map[podmodel.ID]*podIPInfo
	// IP information about external interfaces
	extIfToIPNet map[string][]extIfIPInfo

	/********** VSwitch related variables **********/
	// IP subnet used across all nodes for VPP to host Linux stack interconnect
	hostInterconnectSubnetAllNodes *net.IPNet
	// IP subnet used by this node (given by nodeID) for VPP to host Linux stack interconnect,
	// hostInterconnectSubnetAllNodes + nodeID ==<computation>==> hostInterconnectSubnetThisNode
	hostInterconnectSubnetThisNode *net.IPNet
	// IP address for virtual ethernet's VPP-end on this node
	hostInterconnectIPInVpp net.IP
	// IP address for virtual ethernet's host(Linux)-end on this node
	hostInterconnectIPInLinux net.IP

	/********** node related variables **********/
	// IP subnet used for for inter-node connections
	nodeInterconnectSubnet *net.IPNet
	// IP subnet used for for inter-node VXLAN
	vxlanSubnet *net.IPNet
	// IP subnet used to allocate ClusterIPs for a service
	serviceCIDR *net.IPNet
}

type podNetworkInfo struct {
	// IP subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podSubnetAllNodes *net.IPNet
	// IP subnet prefix for all PODs on this node (given by nodeID),
	// podSubnetAllNodes + nodeID ==<computation>==> podSubnetThisNode
	podSubnetThisNode *net.IPNet
	// gateway IP address for PODs on this node (given by nodeID)
	podSubnetGatewayIP net.IP
	// counter denoting last assigned pod IP address
	lastPodIPAssigned int
}

// podIPAllocation represents allocation of an IP address from the IPAM pool.
// It holds the information about the pod and the interface to which this allocation belongs.
type podIPAllocation struct {
	pod             podmodel.ID // pod ID
	mainIP          bool        // true if this is a main pod IP
	customIfName    string      // empty if mainIP == false
	customIfNetwork string      // empty if mainIP == false
}

// podIPInfo holds the IP address allocation info related to a pod.
type podIPInfo struct {
	mainIP      net.IP            // IP address of the main interface
	customIfIPs map[string]net.IP // custom interface name + network to IP address map
}

// extIfIPInfo holds the IP allocation info for external interface
type extIfIPInfo struct {
	nodeID       uint32
	vppInterface string
	ipNet        *net.IPNet
}

// String provides human-readable representation of podNetworkInfo
func (i *podNetworkInfo) String() string {
	return fmt.Sprintf("<podSubnetAllNodes=%v, podSubnetThisNode=%v, podSubnetGatewayIP=%v, lastPodIPAssigned=%d>",
		i.podSubnetAllNodes, i.podSubnetThisNode, i.podSubnetGatewayIP, i.lastPodIPAssigned)
}

// String provides human-readable representation of podIPAllocation
func (a *podIPAllocation) String() string {
	if a.mainIP {
		return fmt.Sprintf("<pod=%s>", a.pod.String())
	}
	return fmt.Sprintf("<pod=%s, ifName=%s, ifNetwork=%s>", a.pod.String(), a.customIfName, a.customIfNetwork)
}

// String provides human-readable representation of podIPInfo
func (i *podIPInfo) String() string {
	if len(i.customIfIPs) == 0 {
		return fmt.Sprintf("<IP=%s>", i.mainIP)
	}
	return fmt.Sprintf("<mainIP=%s, customIPs=%+v>", i.mainIP, i.customIfIPs)
}

// String provides human-readable representation of extIfIPInfo
func (e *extIfIPInfo) String() string {
	return fmt.Sprintf("<nodeID=%v, vppInterface=%s, ipNet=%s>", e.nodeID, e.vppInterface, e.ipNet)
}

// Deps lists dependencies of the IPAM plugin.
type Deps struct {
	infra.PluginDeps
	NodeSync     nodesync.API
	ContivConf   contivconf.API
	ServiceLabel servicelabel.ReaderAPI
	EventLoop    controller.EventLoop
	HTTPHandlers rest.HTTPHandlers
	RemoteDB     nodesync.KVDBWithAtomic
}

// Init initializes the REST handlers of the plugin.
func (i *IPAM) Init() (err error) {

	// register REST handlers
	i.registerRESTHandlers()

	return nil
}

// HandlesEvent selects:
//   - any Resync event
//   - NodeUpdate for the current node if external IPAM is in use (may trigger PodCIDRChange)
//   - VNI allocation
//   - custom network update
func (i *IPAM) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
			return nodeUpdate.NodeName == i.ServiceLabel.GetAgentLabel()
		}
	}

	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case customnetmodel.Keyword:
			return true
		case ipalloc.Keyword:
			return true
		case podmodel.PodKeyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}

	// unhandled event
	return false
}

// Resync resynchronizes IPAM against the configuration and Kubernetes state data.
// A set of already allocated pod IPs is updated.
func (i *IPAM) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	// return any error as fatal
	defer func() {
		if err != nil {
			err = controller.NewFatalError(err)
		}
	}()

	// Normally it should not be needed to resync the set of allocated pod IP
	// addresses in the run-time - local pod should not be added/deleted without
	// the agent knowing about it. But if we are healing after an error, reload
	// the state of IPAM just in case.
	// In case that external IPAM is in use, we need to resync on POD CIDR change.
	_, isHealingResync := event.(*controller.HealingResync)
	_, isPodCIDRChange := event.(*PodCIDRChange)
	if resyncCount > 1 && !isHealingResync && !isPodCIDRChange {
		return nil
	}

	nodeID := i.NodeSync.GetNodeID()

	// exclude gateway from the set of allocated node IPs
	i.excludedIPsfromNodeSubnet = []net.IP{}
	defaultGW := i.ContivConf.GetStaticDefaultGW()
	gw := defaultGW.To4()
	if gw == nil {
		gw = defaultGW.To16()
	}
	if len(gw) > 0 {
		i.excludedIPsfromNodeSubnet = []net.IP{gw}
	}

	// initialize subnets based on the configuration
	ipamConfig := i.ContivConf.GetIPAMConfig()
	subnets := &ipamConfig.CustomIPAMSubnets
	if ipamConfig.ContivCIDR != nil {
		subnets, err = dissectContivCIDR(ipamConfig)
		if err != nil {
			return err
		}
	}
	if err := i.initializePodNetwork(kubeStateData, subnets, nodeID); err != nil {
		return err
	}
	if err := i.initializeVPPHostNetwork(subnets, nodeID); err != nil {
		return err
	}
	i.serviceCIDR = ipamConfig.ServiceCIDR
	i.nodeInterconnectSubnet = subnets.NodeInterconnectCIDR
	i.vxlanSubnet = subnets.VxlanCIDR

	// resync custom pod networks
	for _, extIfProto := range kubeStateData[customnetmodel.Keyword] {
		nw := extIfProto.(*customnetmodel.CustomNetwork)
		if nw.Type == customnetmodel.CustomNetwork_L3 && nw.SubnetCIDR != "" && nw.SubnetOneNodePrefix > 0 {
			err = i.initializeCustomPodNetwork(nw.Name, nw.SubnetCIDR, nw.SubnetOneNodePrefix)
			if err != nil {
				i.Log.Warnf("Error by initializing pod network %s: %v - skipping", nw.Name, err)
			}
		}
	}

	// resync allocated IP addresses (main pod interfaces)
	podNw := i.podNetworks[defaultPodNetworkName]
	networkPrefix := new(big.Int).SetBytes(podNw.podSubnetThisNode.IP)

	for _, podProto := range kubeStateData[podmodel.PodKeyword] {
		pod := podProto.(*podmodel.Pod)
		podID := podmodel.ID{Name: pod.Name, Namespace: pod.Namespace}
		podIPAddress := net.ParseIP(pod.IpAddress)
		// ignore pods without IP address
		if podIPAddress != nil {
			if podNw.podSubnetThisNode.Contains(podIPAddress) { // local pod
				// register address as already allocated
				addr := new(big.Int).SetBytes(podIPAddress)
				i.assignedPodIPs[podIPAddress.String()] = &podIPAllocation{
					pod:    podID,
					mainIP: true,
				}
				i.podToIP[podID] = &podIPInfo{
					mainIP:      podIPAddress,
					customIfIPs: map[string]net.IP{},
				}
				diff := int(addr.Sub(addr, networkPrefix).Int64())
				if podNw.lastPodIPAssigned < diff {
					podNw.lastPodIPAssigned = diff
				}
			} else { // remote pod
				i.remotePodToIP[podID] = &podIPInfo{
					mainIP:      podIPAddress,
					customIfIPs: map[string]net.IP{},
				}
			}
		}
	}

	// resync custom interface IP allocations
	for _, ipAllocProto := range kubeStateData[ipalloc.Keyword] {
		ipAlloc := ipAllocProto.(*ipalloc.CustomIPAllocation)

		for _, customAlloc := range ipAlloc.CustomInterfaces {
			podNw := i.podNetworks[customAlloc.Network]
			if podNw == nil || podNw.podSubnetThisNode == nil {
				i.Log.Warnf("Missing subnet information for the pod network %s, skipping", customAlloc.Network)
				continue
			}
			networkPrefix := new(big.Int).SetBytes(podNw.podSubnetThisNode.IP)

			podID := podmodel.ID{Name: ipAlloc.PodName, Namespace: ipAlloc.PodNamespace}
			podIPAddress := net.ParseIP(customAlloc.IpAddress)
			// ignore pods without IP address
			if podIPAddress != nil {
				if podNw.podSubnetThisNode.Contains(podIPAddress) { // local pod
					// register address as already allocated
					addr := new(big.Int).SetBytes(podIPAddress)
					i.assignedPodIPs[podIPAddress.String()] = &podIPAllocation{
						pod:             podID,
						mainIP:          false,
						customIfName:    customAlloc.Name,
						customIfNetwork: customAlloc.Network,
					}
					if _, found := i.podToIP[podID]; !found {
						i.podToIP[podID] = &podIPInfo{
							customIfIPs: map[string]net.IP{},
						}
					}
					i.podToIP[podID].customIfIPs[customIfID(customAlloc.Name, customAlloc.Network)] = podIPAddress
					diff := int(addr.Sub(addr, networkPrefix).Int64())
					if podNw.lastPodIPAssigned < diff {
						podNw.lastPodIPAssigned = diff
					}
				} else { // remote pod
					i.remotePodToIP[podID].customIfIPs[customIfID(customAlloc.Name, customAlloc.Network)] = podIPAddress
				}
			}
		}
	}

	i.Log.Infof("IPAM state after startup RESYNC: "+
		"podNetworks=%+v, excludedIPsfromNodeSubnet=%v, hostInterconnectSubnetAllNodes=%v, "+
		"hostInterconnectSubnetThisNode=%v, hostInterconnectIPInVpp=%v, hostInterconnectIPInLinux=%v, "+
		"nodeInterconnectSubnet=%v, vxlanSubnet=%v, serviceCIDR=%v, "+
		"assignedPodIPs=%+v, podToIP=%v, remotePodToIP=%+v, extIfToIPNet=%+v",
		i.podNetworks, i.excludedIPsfromNodeSubnet, i.hostInterconnectSubnetAllNodes,
		i.hostInterconnectSubnetThisNode, i.hostInterconnectIPInVpp, i.hostInterconnectIPInLinux,
		i.nodeInterconnectSubnet, i.vxlanSubnet, i.serviceCIDR,
		i.assignedPodIPs, i.podToIP, i.remotePodToIP, i.extIfToIPNet)
	return
}

// initializePodNetwork initializes pod network -related variables.
func (i *IPAM) initializePodNetwork(kubeStateData controller.KubeStateData, config *contivconf.CustomIPAMSubnets,
	nodeID uint32) (err error) {

	// init pod IP maps
	i.assignedPodIPs = make(map[string]*podIPAllocation)
	i.remotePodToIP = make(map[podmodel.ID]*podIPInfo)
	i.podToIP = make(map[podmodel.ID]*podIPInfo)
	i.extIfToIPNet = make(map[string][]extIfIPInfo)

	// init default pod network info
	i.podNetworks = make(map[string]*podNetworkInfo)
	podNw := &podNetworkInfo{
		podSubnetAllNodes: config.PodSubnetCIDR,
	}
	i.podNetworks[defaultPodNetworkName] = podNw

	// if external IPAM is in use, try to look up for this node's POD CIDR in k8s state data
	thisNodePodCIDR := ""
	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		nodeName := i.ServiceLabel.GetAgentLabel()
		for _, k8sNodeProto := range kubeStateData[nodemodel.NodeKeyword] {
			k8sNode := k8sNodeProto.(*nodemodel.Node)
			if k8sNode.Name == nodeName {
				thisNodePodCIDR = k8sNode.Pod_CIDR
				break
			}
		}
		i.Log.Infof("This node POD CIDR: %s", thisNodePodCIDR)
	}

	if thisNodePodCIDR != "" {
		// pod subnet as detected
		_, podNw.podSubnetThisNode, err = net.ParseCIDR(thisNodePodCIDR)
		if err != nil {
			return
		}
	} else {
		// pod subnet based on node ID
		podNw.podSubnetThisNode, err = dissectSubnetForNode(
			podNw.podSubnetAllNodes, config.PodSubnetOneNodePrefixLen, nodeID)
		if err != nil {
			return
		}
	}

	podNw.podSubnetGatewayIP, err = cidr.Host(podNw.podSubnetThisNode, podGatewaySeqID)
	if err != nil {
		return nil
	}
	podNw.lastPodIPAssigned = 1

	return nil
}

// initializeCustomPodNetwork initializes custom pod network -related variables.
func (i *IPAM) initializeCustomPodNetwork(name string, subnetCIDR string, subnetOneNodePrefix uint32) (err error) {
	podNw := &podNetworkInfo{}
	i.podNetworks[name] = podNw

	_, podNw.podSubnetAllNodes, err = net.ParseCIDR(subnetCIDR)
	if err != nil {
		i.Log.Errorf("unable to parse network %s subnet CIDR: %v: %v", name, subnetCIDR, err)
		return err
	}
	podNw.podSubnetThisNode, err = dissectSubnetForNode(podNw.podSubnetAllNodes, uint8(subnetOneNodePrefix),
		i.NodeSync.GetNodeID())
	podNw.podSubnetGatewayIP, err = cidr.Host(podNw.podSubnetThisNode, podGatewaySeqID)
	if err != nil {
		return err
	}
	podNw.lastPodIPAssigned = 1

	i.Log.Infof("New L3 pod network %s: %v", name, podNw)
	return nil
}

// initializeVPPHostNetwork initializes VPP-host interconnect-related variables.
func (i *IPAM) initializeVPPHostNetwork(config *contivconf.CustomIPAMSubnets, nodeID uint32) (err error) {
	i.hostInterconnectSubnetAllNodes = config.VPPHostSubnetCIDR
	i.hostInterconnectSubnetThisNode, err = dissectSubnetForNode(
		i.hostInterconnectSubnetAllNodes, config.VPPHostSubnetOneNodePrefixLen, nodeID)
	if err != nil {
		return
	}

	i.hostInterconnectIPInVpp, err = cidr.Host(i.hostInterconnectSubnetThisNode, hostInterconnectInVPPIPSeqID)
	if err != nil {
		return
	}
	i.hostInterconnectIPInLinux, err = cidr.Host(i.hostInterconnectSubnetThisNode, hostInterconnectInLinuxIPSeqID)
	if err != nil {
		return
	}
	return
}

// Update handles NodeUpdate event in case that external IPAM is in use.
func (i *IPAM) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {

	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		if nodeUpdate.NodeName == i.ServiceLabel.GetAgentLabel() {
			if nodeUpdate.NewState.PodCIDR != nodeUpdate.PrevState.PodCIDR {
				i.EventLoop.PushEvent(&PodCIDRChange{
					LocalPodCIDR: nodeUpdate.NewState.PodCIDR,
				})
				i.Log.Infof("Sent PodCIDRChange event to the event loop for PodCIDRChange")
			}
		}
	}

	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case ipalloc.Keyword:
			if newIPAlloc, newOK := ksChange.NewValue.(*ipalloc.CustomIPAllocation); newOK {
				podID := podmodel.ID{Name: newIPAlloc.PodName, Namespace: newIPAlloc.PodNamespace}
				for _, customAlloc := range newIPAlloc.CustomInterfaces {
					ifIPAddress := net.ParseIP(customAlloc.IpAddress)
					if i.isLocalPodInterface(ifIPAddress) { // local pod
						if _, found := i.podToIP[podID]; !found {
							i.podToIP[podID] = &podIPInfo{}
							i.podToIP[podID].customIfIPs = make(map[string]net.IP)
						}
						i.podToIP[podID].customIfIPs[customIfID(customAlloc.Name, customAlloc.Network)] = ifIPAddress
					} else { // remote pod
						if _, found := i.remotePodToIP[podID]; !found {
							i.remotePodToIP[podID] = &podIPInfo{}
							i.remotePodToIP[podID].customIfIPs = make(map[string]net.IP)
						}
						i.remotePodToIP[podID].customIfIPs[customIfID(customAlloc.Name, customAlloc.Network)] = ifIPAddress
					}
				}
			}
		case podmodel.PodKeyword:
			oldPod, _ := ksChange.PrevValue.(*podmodel.Pod)
			newPod, _ := ksChange.NewValue.(*podmodel.Pod)
			podNw := i.podNetworks[defaultPodNetworkName] // main pod interfaces
			if oldPod != nil && newPod == nil {           // delete pod event
				if !podNw.podSubnetThisNode.Contains(net.ParseIP(oldPod.IpAddress)) { // remote pod
					deletedPodID := podmodel.ID{Name: oldPod.Name, Namespace: oldPod.Namespace}
					delete(i.remotePodToIP, deletedPodID)
				}
			} else if newPod != nil { // update pod event
				updatedPodID := podmodel.ID{Name: newPod.Name, Namespace: newPod.Namespace}
				if newIPAddress := net.ParseIP(newPod.IpAddress); newIPAddress != nil &&
					!podNw.podSubnetThisNode.Contains(newIPAddress) { // remote pod
					if pod, exists := i.remotePodToIP[updatedPodID]; exists {
						pod.mainIP = newIPAddress
					} else {
						i.remotePodToIP[updatedPodID] = &podIPInfo{
							mainIP:      newIPAddress,
							customIfIPs: map[string]net.IP{},
						}
					}
				} else { // local pod
					if pod, exists := i.podToIP[updatedPodID]; exists {
						pod.mainIP = newIPAddress
					} else {
						i.podToIP[updatedPodID] = &podIPInfo{
							mainIP:      newIPAddress,
							customIfIPs: map[string]net.IP{},
						}
					}
				}
			}
		case customnetmodel.Keyword:
			// custom network data change
			if ksChange.NewValue != nil {
				nw := ksChange.NewValue.(*customnetmodel.CustomNetwork)
				if nw.Type == customnetmodel.CustomNetwork_L3 && nw.SubnetCIDR != "" && nw.SubnetOneNodePrefix > 0 {
					err = i.initializeCustomPodNetwork(nw.Name, nw.SubnetCIDR, nw.SubnetOneNodePrefix)
					if err != nil {
						return "", err
					}
				}
			}
		}
	}
	return "", nil
}

// isLocalPodInterface determines from pod interface IP address whether interface (and pod) is located on this node
func (i *IPAM) isLocalPodInterface(intefaceIPAddress net.IP) bool {
	for _, nw := range i.podNetworks {
		if nw.podSubnetThisNode.Contains(intefaceIPAddress) {
			return true
		}
	}
	return false
}

// Revert is NOOP - never called.
func (i *IPAM) Revert(event controller.Event) error {
	return nil
}

// NodeIPAddress computes IP address of the node based on the provided node ID.
func (i *IPAM) NodeIPAddress(nodeID uint32) (net.IP, *net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	nodeIP, err := i.computeNodeIPAddress(nodeID)
	if err != nil {
		return net.IP{}, nil, err
	}
	maskSize, bits := i.nodeInterconnectSubnet.Mask.Size()

	mask := net.CIDRMask(maskSize, bits)
	ip := make([]byte, len(nodeIP))
	copy(ip, nodeIP)
	nodeIPNetwork := &net.IPNet{
		IP:   net.IP(ip).Mask(mask),
		Mask: mask,
	}
	return nodeIP, nodeIPNetwork, nil
}

// VxlanIPAddress computes IP address of the VXLAN interface based on the provided node ID.
func (i *IPAM) VxlanIPAddress(nodeID uint32) (net.IP, *net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	vxlanIP, err := i.computeVxlanIPAddress(nodeID)
	if err != nil {
		return net.IP{}, nil, err
	}
	maskSize, _ := i.vxlanSubnet.Mask.Size()
	mask := net.CIDRMask(maskSize, addrLenFromNet(i.vxlanSubnet))
	vxlanNetwork := &net.IPNet{
		IP:   newIP(vxlanIP).Mask(mask),
		Mask: mask,
	}
	return vxlanIP, vxlanNetwork, nil
}

// HostInterconnectIPInVPP provides the IP address for the VPP-end of the VPP-to-host
// interconnect.
func (i *IPAM) HostInterconnectIPInVPP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.hostInterconnectIPInVpp)
}

// HostInterconnectIPInLinux provides the IP address of the host(Linux)-end of the VPP to host interconnect.
func (i *IPAM) HostInterconnectIPInLinux() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.hostInterconnectIPInLinux)
}

// HostInterconnectSubnetThisNode returns vswitch network used to connect VPP to its host Linux Stack
// on this node.
func (i *IPAM) HostInterconnectSubnetThisNode() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.hostInterconnectSubnetThisNode)
}

// HostInterconnectSubnetAllNodes returns vswitch base subnet used to connect VPP
// to its host Linux Stack on all nodes.
func (i *IPAM) HostInterconnectSubnetAllNodes() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.hostInterconnectSubnetAllNodes)
}

// HostInterconnectSubnetOtherNode returns VPP-host network of another node identified by nodeID.
func (i *IPAM) HostInterconnectSubnetOtherNode(nodeID uint32) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	oneNodePrefixLen, _ := i.hostInterconnectSubnetThisNode.Mask.Size()
	vSwitchNetworkIPPrefix, err := dissectSubnetForNode(
		i.hostInterconnectSubnetAllNodes, uint8(oneNodePrefixLen), nodeID)
	if err != nil {
		return nil, err
	}
	return newIPNet(vSwitchNetworkIPPrefix), nil
}

// PodSubnetAllNodes returns POD subnet that is a base subnet for all PODs of all nodes for given pod network.
func (i *IPAM) PodSubnetAllNodes(network string) *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.getPodNetwork(network)
	return newIPNet(podNw.podSubnetAllNodes)
}

// PodSubnetThisNode returns POD network for the current node (given by network name and nodeID given at IPAM creation).
func (i *IPAM) PodSubnetThisNode(network string) *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.getPodNetwork(network)
	return newIPNet(podNw.podSubnetThisNode)
}

// PodSubnetOtherNode returns the POD network of another node identified by by network name and nodeID.
func (i *IPAM) PodSubnetOtherNode(network string, nodeID uint32) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.getPodNetwork(network)
	oneNodePrefixLen, _ := podNw.podSubnetThisNode.Mask.Size()
	podSubnetThisNode, err := dissectSubnetForNode(
		podNw.podSubnetAllNodes, uint8(oneNodePrefixLen), nodeID)
	if err != nil {
		return nil, err
	}
	return newIPNet(podSubnetThisNode), nil
}

// PodGatewayIP returns gateway IP address of the POD subnet of this node.
func (i *IPAM) PodGatewayIP(network string) net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.getPodNetwork(network)
	return newIP(podNw.podSubnetGatewayIP)
}

// NodeIDFromPodIP returns node ID from provided main POD IP address.
func (i *IPAM) NodeIDFromPodIP(podIP net.IP) (uint32, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.podNetworks[defaultPodNetworkName]
	if !podNw.podSubnetAllNodes.Contains(podIP) {
		return 0, fmt.Errorf("pod IP %v not from pod subnet %v", podIP, podNw.podSubnetAllNodes)
	}

	subnet := podNw.podSubnetAllNodes.IP
	if !isIPv6Net(podNw.podSubnetAllNodes) {
		podIP = podIP.To4()
		subnet = subnet.To4()
	}
	ip := new(big.Int).SetBytes(podIP)
	podSubnetAllNodes := new(big.Int).SetBytes(subnet)

	addrLen := addrLenFromNet(podNw.podSubnetThisNode)
	oneNodePrefixLen, _ := podNw.podSubnetThisNode.Mask.Size()

	// zero pod subnet prefix for all nodes
	ip.Xor(ip, podSubnetAllNodes)

	// shift right to get rid of the node addressing part
	ip.Rsh(ip, uint(addrLen-oneNodePrefixLen))

	return uint32(ip.Uint64()), nil
}

// NatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (i *IPAM) NatLoopbackIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	podNw := i.podNetworks[defaultPodNetworkName]

	// Last unicast IP from the pod subnet is used as NAT-loopback.
	_, broadcastIP := cidr.AddressRange(podNw.podSubnetThisNode)
	return cidr.Dec(broadcastIP)
}

// ServiceNetwork returns range allocated for services.
func (i *IPAM) ServiceNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.serviceCIDR)
}

// AllocatePodIP tries to allocate IP address for the given pod.
func (i *IPAM) AllocatePodIP(podID podmodel.ID, ipamType string, ipamData string) (net.IP, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		// allocate IP using external IPAM
		return i.allocateExternalPodIP(podID, ipamType, ipamData)
	}

	// check whether IP is already allocated
	allocation, found := i.podToIP[podID]
	if found && allocation.mainIP != nil {
		return allocation.mainIP, nil
	}

	// allocate an IP
	ip, err := i.allocateIP(i.podNetworks[defaultPodNetworkName])
	if err != nil {
		i.Log.Errorf("Unable to allocate main pod IP: %v", err)
		return nil, err
	}

	// store the allocation internally
	i.assignedPodIPs[ip.String()] = &podIPAllocation{
		pod:    podID,
		mainIP: true,
	}
	if _, found := i.podToIP[podID]; !found {
		i.podToIP[podID] = &podIPInfo{
			customIfIPs: map[string]net.IP{},
		}
	}
	i.podToIP[podID].mainIP = ip
	i.logAssignedPodIPPool()

	return ip, nil
}

// AllocatePodCustomIfIP tries to allocate custom IP address for the given interface of a given pod.
func (i *IPAM) AllocatePodCustomIfIP(podID podmodel.ID, ifName, network string,
	isServiceEndpoint bool) (net.IP, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	podNw := i.podNetworks[network]
	if podNw == nil {
		err := fmt.Errorf("unable to allocate IP in pod network %s: missing subnet information", network)
		i.Log.Error(err)
		return nil, err
	}

	// allocate an IP
	ip, err := i.allocateIP(podNw)
	if err != nil {
		i.Log.Errorf("Unable to allocate pod custom interface IP: %v", err)
		return nil, err
	}

	// persist the allocation
	err = i.persistCustomIfIPAllocation(podID, ifName, network, ip, isServiceEndpoint)
	if err != nil {
		i.Log.Errorf("Unable to persist custom interface IP allocation: %v", err)
		return nil, err
	}

	// store the allocation internally
	i.assignedPodIPs[ip.String()] = &podIPAllocation{
		pod:             podID,
		mainIP:          false,
		customIfName:    ifName,
		customIfNetwork: network,
	}
	if _, found := i.podToIP[podID]; !found {
		i.podToIP[podID] = &podIPInfo{
			customIfIPs: map[string]net.IP{},
		}
	}
	i.podToIP[podID].customIfIPs[customIfID(ifName, network)] = ip
	i.logAssignedPodIPPool()

	return ip, nil
}

// persistCustomIfIPAllocation persists custom interface IP allocation into ETCD.
func (i *IPAM) persistCustomIfIPAllocation(podID podmodel.ID, ifName, network string, ip net.IP,
	isServiceEndpoint bool) error {
	key := ipalloc.Key(podID.Name, podID.Namespace)
	allocation := &ipalloc.CustomIPAllocation{}

	db, err := i.getDBBroker()
	if err != nil {
		return err
	}

	// try to read existing allocation, otherwise create new
	found, _, err := db.GetValue(key, allocation)
	if err != nil {
		i.Log.Errorf("Unable to read pod custom interface IP allocation: %v", err)
		return err
	}
	if !found {
		allocation = &ipalloc.CustomIPAllocation{
			PodName:      podID.Name,
			PodNamespace: podID.Namespace,
		}
	}

	// add IP allocation for this custom interface
	allocation.CustomInterfaces = append(allocation.CustomInterfaces, &ipalloc.CustomPodInterface{
		Name:            ifName,
		Network:         network,
		IpAddress:       ip.String(),
		ServiceEndpoint: isServiceEndpoint,
	})

	// save in ETCD
	err = db.Put(key, allocation)
	if err != nil {
		i.Log.Errorf("Unable to persist pod custom interface IP allocation: %v", err)
		return err
	}
	return nil
}

// getDBBroker returns broker for accessing remote database, error if database is not connected.
func (i IPAM) getDBBroker() (keyval.ProtoBroker, error) {
	// return error if ETCD is not connected
	dbIsConnected := false
	i.RemoteDB.OnConnect(func() error {
		dbIsConnected = true
		return nil
	})
	if !dbIsConnected {
		return nil, fmt.Errorf("remote database is not connected")
	}
	// return existing broker if possible
	if i.dbBroker == nil {
		i.dbBroker = i.RemoteDB.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
	}
	return i.dbBroker, nil
}

// getPodNetwork returns pod network information for the given pod network name.
func (i *IPAM) getPodNetwork(network string) *podNetworkInfo {
	podNw := i.podNetworks[defaultPodNetworkName]

	if network != defaultPodNetworkName && network != "" {
		if i.podNetworks[network] != nil {
			podNw = i.podNetworks[network]
		} else {
			i.Log.Warnf("Missing subnet information for the pod network %s", network)
		}
	}
	return podNw
}

// allocateExternalPodIP allocates IP address for the given pod using the external IPAM.
func (i *IPAM) allocateExternalPodIP(podID podmodel.ID, ipamType string, ipamData string) (net.IP, error) {

	i.Log.Debugf("IPAM type=%s data: %s", ipamType, ipamData)

	// parse the external IPAM result
	ipamResult := &cnisb.IPConfig{}
	err := ipamResult.UnmarshalJSON([]byte(ipamData))
	if err != nil {
		return nil, fmt.Errorf("error by unmarshalling external IPAM result: %v", err)
	}

	// save allocated IP to POD mapping
	ip := ipamResult.Address.IP
	i.podToIP[podID] = &podIPInfo{
		mainIP: ip,
	}

	i.Log.Infof("Assigned new pod IP %v for POD ID %v", ip, podID)

	return ip, nil
}

// allocateIP allocates a new IP from the pod IP pool of the given network.
func (i *IPAM) allocateIP(podNw *podNetworkInfo) (net.IP, error) {
	last := podNw.lastPodIPAssigned + 1
	// iterate over all possible IP addresses for pod network prefix
	// start from the last assigned and take first available IP
	prefixBits, totalBits := podNw.podSubnetThisNode.Mask.Size()
	// get the maximum sequence ID available in the provided range; the last valid unicast IP is used as "NAT-loopback"
	podBitSize := uint(totalBits - prefixBits)
	// IPAM currently support up to 2^63 pods
	if podBitSize >= 64 {
		podBitSize = 63
	}
	maxSeqID := (1 << podBitSize) - 2
	for j := last; j < maxSeqID; j++ {
		ipForAssign, success := i.tryToAllocateIP(j, podNw.podSubnetThisNode)
		if success {
			podNw.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	// iterate from the range start until lastPodIPAssigned
	for j := 1; j < last; j++ { // zero ending IP is reserved for network => skip seqID=0
		ipForAssign, success := i.tryToAllocateIP(j, podNw.podSubnetThisNode)
		if success {
			podNw.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	return nil, fmt.Errorf("no IP address is free for allocation in the subnet %v", podNw.podSubnetThisNode)
}

// tryToAllocatePodIP checks whether the IP at the given index is available.
func (i *IPAM) tryToAllocateIP(index int, networkPrefix *net.IPNet) (assignedIP net.IP, success bool) {
	if index == podGatewaySeqID {
		return nil, false // gateway IP address can't be assigned as pod
	}
	ip, err := cidr.Host(networkPrefix, index)
	if err != nil {
		return nil, false
	}
	if _, found := i.assignedPodIPs[ip.String()]; found {
		return nil, false // ignore already assigned IP addresses
	}

	i.Log.Infof("Assigned new pod IP %s", ip)

	return ip, true
}

// GetPodIP returns the allocated (main) pod IP, together with the mask.
// Searches for both local and remote pods
// Returns nil if the pod does not have allocated IP address.
func (i *IPAM) GetPodIP(podID podmodel.ID) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	podNw := i.podNetworks[defaultPodNetworkName]
	addrLen := addrLenFromNet(podNw.podSubnetAllNodes)
	if allocation, found := i.getPodIPInfo(podID); found {
		return &net.IPNet{IP: allocation.mainIP, Mask: net.CIDRMask(addrLen, addrLen)}
	}
	return nil
}

// GetExternalInterfaceIP returns the allocated external interface IP.
// Returns nil if the interface does not have allocated IP address.
func (i *IPAM) GetExternalInterfaceIP(vppInterface string, nodeID uint32) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	for _, ipInfos := range i.extIfToIPNet {
		for _, ipInfo := range ipInfos {
			if ipInfo.vppInterface == vppInterface && ipInfo.nodeID == nodeID {
				return ipInfo.ipNet
			}
		}
	}
	return nil
}

// GetPodCustomIfIP returns the allocated custom interface pod IP, together with the mask.
// Searches for both local and remote pods
// Returns nil if the pod does not have allocated custom interface IP address.
func (i *IPAM) GetPodCustomIfIP(podID podmodel.ID, ifName, network string) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	podNw := i.getPodNetwork(network)
	addrLen := addrLenFromNet(podNw.podSubnetAllNodes)
	if allocation, found := i.getPodIPInfo(podID); found {
		if ip, hasCustomIf := allocation.customIfIPs[customIfID(ifName, network)]; hasCustomIf {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(addrLen, addrLen)}
		}
	}
	return nil
}

// GetPodFromIP returns the pod information related to the allocated pod IP.
// found is false if the provided IP address has not been allocated to any local pod.
func (i *IPAM) GetPodFromIP(podIP net.IP) (podID podmodel.ID, found bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	allocation, found := i.assignedPodIPs[podIP.String()]

	if found {
		return allocation.pod, true
	}
	return podID, false
}

// ReleasePodIPs releases the pod IP address making it available for new PODs.
func (i *IPAM) ReleasePodIPs(podID podmodel.ID) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	allocation, found := i.podToIP[podID]
	if !found {
		i.Log.Warnf("Unable to find IP for pod %v", podID)
		return nil
	}
	delete(i.podToIP, podID)

	i.Log.Infof("Released IP %v for pod ID %v", allocation.mainIP, podID)

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		// no further processing for external IPAM
		return nil
	}

	delete(i.assignedPodIPs, allocation.mainIP.String())
	for _, ip := range allocation.customIfIPs {
		i.Log.Infof("Released custom interface IP %v for pod ID %v", ip, podID)
		delete(i.assignedPodIPs, ip.String())
	}
	if len(allocation.customIfIPs) > 0 {
		// release pod allocation from ETCD
		db, err := i.getDBBroker()
		if err != nil {
			i.Log.Errorf("Unable to erase persisted pod custom interface IP allocation: %v", err)
			return err
		}
		key := ipalloc.Key(podID.Name, podID.Namespace)
		_, err = db.Delete(key)
		if err != nil {
			i.Log.Errorf("Unable to erase persisted pod custom interface IP allocation: %v", err)
			return err
		}
	}

	i.logAssignedPodIPPool()
	return nil
}

// GetIPAMConfigForJSON returns actual (contivCIDR dissected
// into ranges, if  used) IPAM configuration
func (i *IPAM) GetIPAMConfigForJSON() *config.IPAMConfig {
	c := i.ContivConf.GetIPAMConfigForJSON()
	res := &config.IPAMConfig{
		UseExternalIPAM:      c.UseExternalIPAM,
		ContivCIDR:           c.ContivCIDR,
		ServiceCIDR:          c.ServiceCIDR,
		DefaultGateway:       c.DefaultGateway,
		NodeInterconnectDHCP: c.NodeInterconnectDHCP,
		NodeInterconnectCIDR: i.nodeInterconnectSubnet.String(),
		PodSubnetCIDR:        i.PodSubnetAllNodes(defaultPodNetworkName).String(),
		VPPHostSubnetCIDR:    i.HostInterconnectSubnetAllNodes().String(),
	}
	if i.vxlanSubnet != nil {
		res.VxlanCIDR = i.vxlanSubnet.String()
	}
	s, _ := i.PodSubnetThisNode(defaultPodNetworkName).Mask.Size()
	res.PodSubnetOneNodePrefixLen = uint8(s)

	s, _ = i.HostInterconnectSubnetThisNode().Mask.Size()
	res.VPPHostSubnetOneNodePrefixLen = uint8(s)

	return res
}

// BsidForServicePolicy creates a valid SRv6 binding SID for given k8s service IP addresses <serviceIPs>. This sid
// should be used only for k8s service policy
func (i *IPAM) BsidForServicePolicy(serviceIPs []net.IP) net.IP {
	// get lowest ip from service IP addresses
	var ip net.IP
	if len(serviceIPs) == 0 {
		ip = net.ParseIP("::1").To16()
	} else {
		sort.Slice(serviceIPs, func(i, j int) bool {
			return bytes.Compare(serviceIPs[i], serviceIPs[j]) < 0
		})
		ip = serviceIPs[0].To16()
	}
	return i.computeSID(ip, i.ContivConf.GetIPAMConfig().SRv6Settings.ServicePolicyBSIDSubnetCIDR)
}

// SidForServiceHostLocalsid creates a valid SRv6 SID for service locasid leading to host on the current node.
// Created SID doesn't depend on anything and is the same for each node, because there is only one way how to
// get to host in each node and localsid have local significance (their sid don't have to be globally unique)
func (i *IPAM) SidForServiceHostLocalsid() net.IP {
	return i.computeSID(net.ParseIP("::1"), i.ContivConf.GetIPAMConfig().SRv6Settings.ServiceHostLocalSIDSubnetCIDR)
}

// SidForServicePodLocalsid creates a valid SRv6 SID for service locasid leading to pod backend. The SID creation is
// based on backend IP <backendIP>.
func (i *IPAM) SidForServicePodLocalsid(backendIP net.IP) net.IP {
	return i.computeSID(backendIP, i.ContivConf.GetIPAMConfig().SRv6Settings.ServicePodLocalSIDSubnetCIDR)
}

// SidForNodeToNodePodLocalsid creates a valid SRv6 SID for locasid that is part of node-to-node Srv6 tunnel and
// outputs packets to pod VRF table.
func (i *IPAM) SidForNodeToNodePodLocalsid(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodePodLocalSIDSubnetCIDR)
}

// SidForNodeToNodeHostLocalsid creates a valid SRv6 SID for locasid that is part of node-to-node Srv6 tunnel and
// outputs packets to main VRF table.
func (i *IPAM) SidForNodeToNodeHostLocalsid(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodeHostLocalSIDSubnetCIDR)
}

// SidForServiceNodeLocalsid creates a valid SRv6 SID for service locasid serving as intermediate step in
// policy segment list.
func (i *IPAM) SidForServiceNodeLocalsid(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.ServiceNodeLocalSIDSubnetCIDR)
}

// BsidForNodeToNodePodPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and
// routes traffic to pod VRF table
func (i *IPAM) BsidForNodeToNodePodPolicy(nodeIP net.IP) net.IP {
	// bsid = binding sid -> using the same util method
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodePodPolicySIDSubnetCIDR)
}

// BsidForNodeToNodeHostPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and
// routes traffic to main VRF table
func (i *IPAM) BsidForNodeToNodeHostPolicy(nodeIP net.IP) net.IP {
	// bsid = binding sid -> using the same util method
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodeHostPolicySIDSubnetCIDR)
}

// BsidForSFCPolicy creates a valid SRv6 SID for policy used for SFC
func (i *IPAM) BsidForSFCPolicy(sfcName string) net.IP {
	// prepare computation values
	prefix := i.ContivConf.GetIPAMConfig().SRv6Settings.SFCPolicyBSIDSubnetCIDR
	prefixMaskSize, _ := prefix.Mask.Size()
	sfcID := i.computeSFCID(sfcName)

	// compute BSID as combination of configurable prefix and SFC ID
	return i.combineMultipleIPAddresses(
		newIPWithPositionableMaskFromIPNet(prefix),
		newIPWithPositionableMask(sfcID, prefixMaskSize, 128-prefixMaskSize))
}

// SidForSFCExternalIfLocalsid creates a valid SRv6 SID for external interface
func (i *IPAM) SidForSFCExternalIfLocalsid(externalIfName string, externalIfIP net.IP) net.IP {
	var ip net.IP
	if externalIfIP != nil {
		ip = i.SidForSFCEndLocalsid(externalIfIP)
	} else {
		ip = i.computeExtIfID(externalIfName)
	}

	prefix := i.ContivConf.GetIPAMConfig().SRv6Settings.SFCEndLocalSIDSubnetCIDR
	prefixMaskSize, _ := prefix.Mask.Size()
	return i.combineMultipleIPAddresses(
		newIPWithPositionableMaskFromIPNet(prefix),
		newIPWithPositionableMask(ip, prefixMaskSize, 128-prefixMaskSize))
}

// SidForSFCServiceFunctionLocalsid creates a valid SRv6 SID for locasid leading to pod of service function given by
// <serviceFunctionPodIP> IP address.
func (i *IPAM) SidForSFCServiceFunctionLocalsid(sfcName string, serviceFunctionPodIP net.IP) net.IP {
	// prepare computation values
	prefix := i.ContivConf.GetIPAMConfig().SRv6Settings.SFCServiceFunctionSIDSubnetCIDR
	prefixMaskSize, _ := prefix.Mask.Size()
	sfcID := i.computeSFCID(sfcName)
	sfcIDMaskLength := int(i.ContivConf.GetIPAMConfig().SRv6Settings.SFCIDLengthUsedInSidForServiceFunction)

	// compute SID as combination of configurable prefix, SFC ID and IP address of service function pod
	return i.combineMultipleIPAddresses(
		newIPWithPositionableMaskFromIPNet(prefix),
		newIPWithPositionableMask(sfcID, prefixMaskSize, sfcIDMaskLength),
		newIPWithPositionableMask(serviceFunctionPodIP, prefixMaskSize+sfcIDMaskLength,
			128-prefixMaskSize-sfcIDMaskLength))
}

// SidForSFCEndLocalsid creates a valid SRv6 SID for locasid of segment that is the last link of SFC chain
func (i *IPAM) SidForSFCEndLocalsid(serviceFunctionPodIP net.IP) net.IP {
	// prepare computation values
	prefix := i.ContivConf.GetIPAMConfig().SRv6Settings.SFCEndLocalSIDSubnetCIDR
	prefixMaskSize, _ := prefix.Mask.Size()

	// compute SID as combination of configurable prefix and IP address of service function pod
	return i.combineMultipleIPAddresses(
		newIPWithPositionableMaskFromIPNet(prefix),
		newIPWithPositionableMask(serviceFunctionPodIP, prefixMaskSize, 128-prefixMaskSize))
}

// UpdateExternalInterfaceIPInfo is notifying IPAM about external interfacew IP allocation
func (i *IPAM) UpdateExternalInterfaceIPInfo(extif, vppInterface string, nodeID uint32, ipNet *net.IPNet,
	isDelete bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if !isDelete {
		if _, exists := i.extIfToIPNet[extif]; !exists {
			i.extIfToIPNet[extif] = make([]extIfIPInfo, 0)
		}
		i.extIfToIPNet[extif] = append(i.extIfToIPNet[extif],
			extIfIPInfo{vppInterface: vppInterface, nodeID: nodeID, ipNet: ipNet})
	} else {
		if ipInfos, exists := i.extIfToIPNet[extif]; exists {
			ind := -1
			for index, ipInfo := range ipInfos { // try find a matching entry
				if ipInfo.vppInterface == vppInterface && ipInfo.nodeID == nodeID {
					ind = index
					break
				}
			}
			if ind >= 0 { // found entry, erase it
				ipInfos = append(ipInfos[0:ind], ipInfos[ind+1:]...)
			}
			if len(ipInfos) <= 0 { // no more ip infos, delete
				delete(i.extIfToIPNet, extif)
			}
		}
	}
}

// ipWithPositionableMask holds IP address with positionable mask that defines what part of IP address should
// be used in IP address combination functionality. The net.IPNet could not be used as it's mask start always
// on first bit of IP address.
type ipWithPositionableMask struct {
	ip               net.IP
	positionableMask net.IPMask
}

// newIPWithPositionableMaskFromIPNet creates ipWithPositionableMask with IP and mask from given <ipNet> (mask
// is from start of IP address)
func newIPWithPositionableMaskFromIPNet(ipNet *net.IPNet) *ipWithPositionableMask {
	return &ipWithPositionableMask{
		ip:               ipNet.IP,
		positionableMask: ipNet.Mask,
	}
}

// newIPWithPositionableMask creates ipWithPositionableMask with given IP address and mask that is zeroed except
// of one sequence of ones starting at <maskStartBit>-th bit and having length <maskBitLength>
func newIPWithPositionableMask(ip net.IP, maskStartBit int, maskBitLength int) *ipWithPositionableMask {
	leftToMask := net.CIDRMask(maskStartBit, 128)
	negatedRightToMask := net.CIDRMask(maskStartBit+maskBitLength, 128)
	mask := net.CIDRMask(128, 128) // empty mask
	for i := range mask {
		mask[i] = ^(leftToMask[i] | ^negatedRightToMask[i])
	}

	return &ipWithPositionableMask{
		ip:               ip,
		positionableMask: mask,
	}
}

// combineMultipleIPAddresses combines multiple addresses together into one IP address. The combining
// IP addresses have additional information(positionableMask) that is saying what part of given combining
// IP address should be used in combined IP address. It is expected that positionableMasks from all ipAddresses
// are not overlapping.
func (i *IPAM) combineMultipleIPAddresses(ipAddresses ...*ipWithPositionableMask) net.IP {
	result := net.IP(net.CIDRMask(128, 128))
	for _, ipWithPositionableMask := range ipAddresses {
		for i := range result {
			// copy/paste parts that won't be changed by applying this ipWithPositionableMask
			result[i] = (result[i] & ^ipWithPositionableMask.positionableMask[i]) |
				// apply part from this ipWithPositionableMask to result IP address
				(ipWithPositionableMask.ip[i] & ipWithPositionableMask.positionableMask[i])
		}
	}
	return result
}

// computeSFCID creates 128-bit SFC ID from SFC name
func (i *IPAM) computeSFCID(sfcName string) net.IP {
	return hashString(sfcName)
}

// computeExtIfID creates 128-bit External Interface ID from it's name
func (i *IPAM) computeExtIfID(extIfName string) net.IP {
	return hashString(extIfName)
}

// computeSID creates SID by applying network prefix from <prefixNetwork> to IP <ip>
func (i *IPAM) computeSID(ip net.IP, prefixNetwork *net.IPNet) net.IP {
	// prepare computation values
	ip = ip.To16()
	prefixNetworkMaskSize, _ := prefixNetwork.Mask.Size()

	// compute SID as combination of configurable prefix (PrefixNetwork) and IP address
	return i.combineMultipleIPAddresses(
		newIPWithPositionableMaskFromIPNet(prefixNetwork),
		newIPWithPositionableMask(ip, prefixNetworkMaskSize, 128-prefixNetworkMaskSize))
}

// Close is NOOP.
func (i *IPAM) Close() error {
	return nil
}

// dissectSubnetForNode dissects a smaller chunk from a given subnet to be used
// exclusively by the node of the given ID.
func dissectSubnetForNode(subnetCIDR *net.IPNet, oneNodePrefixLen uint8, nodeID uint32) (nodeSubnet *net.IPNet,
	err error) {
	// checking correct prefix sizes
	subnetPrefixLen, _ := subnetCIDR.Mask.Size()
	if oneNodePrefixLen <= uint8(subnetPrefixLen) {
		err = fmt.Errorf("prefix length for one node (%v) must be higher "+
			"than the cluster-wide subnet prefix length (%v) ",
			oneNodePrefixLen, subnetPrefixLen)
		return
	}

	newBits := int(oneNodePrefixLen) - subnetPrefixLen
	num := int(nodeID)
	// the biggest num is assigned subnet with 0
	if num == (1 << uint(newBits)) {
		num = 0
	}
	return cidr.Subnet(subnetCIDR, newBits, num)
}

// logAssignedPodIPPool logs assigned POD IPs.
func (i *IPAM) logAssignedPodIPPool() {
	i.Log.Debugf("Current pool of assigned pod IP addresses: %v", i.assignedPodIPs)
}

// computeNodeIPAddress computes IP address of node based on the given node ID.
func (i *IPAM) computeNodeIPAddress(nodeID uint32) (net.IP, error) {
	if i.nodeInterconnectSubnet == nil {
		return nil, errors.New("nodeInterconnectCIDR is undefined")
	}

	addrLen := addrLenFromNet(i.nodeInterconnectSubnet)

	// trimming nodeID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.nodeInterconnectSubnet.Mask.Size()
	nodePartBitSize := addrLen - subnetPrefixLen
	nodeIPPart, err := convertToNodeIPPart(nodeID, uint8(nodePartBitSize))
	if err != nil {
		return nil, err
	}
	// nodeIPPart equal to 0 is not valid for IP address
	if nodeIPPart == 0 {
		return nil, fmt.Errorf("no free address for nodeID %v", nodeID)
	}

	computedIP, err := cidr.Host(i.nodeInterconnectSubnet, int(nodeIPPart))
	if err != nil {
		return nil, err
	}

	// skip excluded IPs (gateway or other invalid address)
	for _, ex := range i.excludedIPsfromNodeSubnet {
		if bytes.Compare(ex, computedIP) <= 0 {
			computedIP = cidr.Inc(computedIP)
		}
	}

	return computedIP, nil
}

// computeVxlanIPAddress computes IP address of the VXLAN interface based on the given node ID.
func (i *IPAM) computeVxlanIPAddress(nodeID uint32) (net.IP, error) {
	addrLen := addrLenFromNet(i.vxlanSubnet)

	subnetPrefixLen, _ := i.vxlanSubnet.Mask.Size()
	nodePartBitSize := addrLen - subnetPrefixLen
	nodeIPPart, err := convertToNodeIPPart(nodeID, uint8(nodePartBitSize))
	if err != nil {
		return nil, err
	}
	// nodeIPpart equal to 0 is not valid for IP address
	if nodeIPPart == 0 {
		return nil, fmt.Errorf("no free address for nodeID %v", nodeID)
	}

	// combining it to get result IP address
	computedIP, err := cidr.Host(i.vxlanSubnet, int(nodeIPPart))
	if err != nil {
		return nil, err
	}

	return computedIP, nil
}

// getPodIPInfo returns local/remote pod IP information
func (i *IPAM) getPodIPInfo(podID podmodel.ID) (*podIPInfo, bool) {
	allocation, local := i.podToIP[podID]
	if local {
		return allocation, true
	}

	allocation, remote := i.remotePodToIP[podID]
	if remote {
		return allocation, true
	}

	return nil, false
}

func isIPv6Net(network *net.IPNet) bool {
	return strings.Contains(network.String(), ":")
}

func addrLenFromNet(network *net.IPNet) int {
	addrLen := net.IPv4len * 8
	if isIPv6Net(network) {
		addrLen = net.IPv6len * 8
	}
	return addrLen
}

// customIfID returns custom interface identifier string
func customIfID(ifName, network string) string {
	if network == "" {
		return ifName
	}
	return ifName + "/" + network
}

// hashString creates 128-bit ID from string
func hashString(s string) net.IP {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)[:16]
}
