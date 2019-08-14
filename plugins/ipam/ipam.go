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
	"encoding/json"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/apparentlymart/go-cidr/cidr"
	cnisb "github.com/containernetworking/cni/pkg/types/current"
	"github.com/go-errors/errors"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	"github.com/contiv/vpp/plugins/ipam/vnialloc"
	"github.com/contiv/vpp/plugins/ksr"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
)

const (
	// sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)
	podGatewaySeqID = 1

	// sequence ID reserved for VPP-end of the VPP to host interconnect
	hostInterconnectInVPPIPSeqID = 1

	// sequence ID reserved for host(Linux)-end of the VPP to host interconnect
	hostInterconnectInLinuxIPSeqID = 2

	// VXLAN VNI allocation pool range
	vxlanVNIPoolStart = 5000    // to leave enough space for custom config of the vswitch
	vxlanVNIPoolEnd   = 1 << 24 // given by VXLAN header
)

// IPAM plugin implements IP address allocation for Contiv.
type IPAM struct {
	Deps

	mutex    sync.RWMutex
	dbBroker keyval.ProtoBroker

	excludedIPsfromNodeSubnet []net.IP // IPs from the NodeInterconnect Subnet that should not be assigned

	/********** POD related variables **********/
	// IP subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podSubnetAllNodes *net.IPNet
	// IP subnet prefix for all PODs on this node (given by nodeID), podSubnetAllNodes + nodeID ==<computation>==> podSubnetThisNode
	podSubnetThisNode *net.IPNet
	// gateway IP address for PODs on this node (given by nodeID)
	podSubnetGatewayIP net.IP

	/********** maps to convert between Pod and the assigned IP **********/
	// pool of assigned POD IP addresses
	assignedPodIPs map[string]*podIPAllocation
	// pod -> allocated IP address
	podToIP map[podmodel.ID]*podIPInfo
	// counter denoting last assigned pod IP address
	lastPodIPAssigned int

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

	/********** VXLAN VNI allocation maps **********/
	allocatedVNIs map[uint32]string // allocated VNI number to VXLAN name
	vxlanVNIs     map[string]uint32 // VXLAN name to allocated VNI
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

// Deps lists dependencies of the IPAM plugin.
type Deps struct {
	infra.PluginDeps
	NodeSync     nodesync.API
	ContivConf   contivconf.API
	ServiceLabel servicelabel.ReaderAPI
	EventLoop    controller.EventLoop
	HTTPHandlers rest.HTTPHandlers
	RemoteDB     ClusterWideDB
}

// ClusterWideDB defines API that a DB client must provide for IPAM to be able
// to do cluster-wide allocations and persist them.
type ClusterWideDB interface {
	// OnConnect registers callback to be triggered once the (first) connection
	// to DB is established. If the connection is already established, the callback
	// should be called immediately (synchronously).
	OnConnect(callback func() error)
	// NewBroker creates a new instance of DB broker prefixing all keys with the
	// given prefix.
	NewBroker(prefix string) keyval.ProtoBroker
	// PutIfNotExists atomically puts given key-value pair into DB if there
	// is no value set for the key.
	PutIfNotExists(key string, value []byte) (succeeded bool, err error)
	// Close closes connection to DB and releases all allocated resources.
	Close() error
}

// Init initializes the REST handlers of the plugin.
func (i *IPAM) Init() (err error) {

	// register REST handlers
	i.registerRESTHandlers()

	return nil
}

// HandlesEvent selects any Resync event.
//   - any Resync event
//   - NodeUpdate for the current node if external IPAM is in use (may trigger PodCIDRChange)
//   - k8s change with VNI allocations
func (i *IPAM) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
			return nodeUpdate.NodeName == i.ServiceLabel.GetAgentLabel()
		}
	}

	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange &&
		ksChange.Resource == vnialloc.VxlanVNIKeyword {
		return true
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
	if err := i.initializePods(kubeStateData, subnets, nodeID); err != nil {
		return err
	}
	if err := i.initializeVPPHost(subnets, nodeID); err != nil {
		return err
	}
	i.serviceCIDR = ipamConfig.ServiceCIDR
	i.nodeInterconnectSubnet = subnets.NodeInterconnectCIDR
	i.vxlanSubnet = subnets.VxlanCIDR

	// resync allocated IP addresses (main pod interfaces)
	networkPrefix := new(big.Int).SetBytes(i.podSubnetThisNode.IP)

	for _, podProto := range kubeStateData[podmodel.PodKeyword] {
		pod := podProto.(*podmodel.Pod)
		// ignore pods deployed on other nodes or without IP address
		podIPAddress := net.ParseIP(pod.IpAddress)
		if podIPAddress == nil || !i.podSubnetThisNode.Contains(podIPAddress) {
			continue
		}

		// register address as already allocated
		addr := new(big.Int).SetBytes(podIPAddress)
		podID := podmodel.ID{Name: pod.Name, Namespace: pod.Namespace}
		i.assignedPodIPs[podIPAddress.String()] = &podIPAllocation{
			pod:    podID,
			mainIP: true,
		}
		i.podToIP[podID] = &podIPInfo{
			mainIP:      podIPAddress,
			customIfIPs: map[string]net.IP{},
		}
		diff := int(addr.Sub(addr, networkPrefix).Int64())
		if i.lastPodIPAssigned < diff {
			i.lastPodIPAssigned = diff
		}
	}

	// resync custom interface IP allocations
	for _, ipAllocProto := range kubeStateData[ipalloc.Keyword] {
		ipAlloc := ipAllocProto.(*ipalloc.CustomIPAllocation)

		for _, customAlloc := range ipAlloc.CustomInterfaces {
			podIPAddress := net.ParseIP(customAlloc.IpAddress)
			// ignore pods deployed on other nodes or without IP address
			if podIPAddress == nil || !i.podSubnetThisNode.Contains(podIPAddress) {
				continue
			}

			// register address as already allocated
			addr := new(big.Int).SetBytes(podIPAddress)
			podID := podmodel.ID{Name: ipAlloc.PodName, Namespace: ipAlloc.PodNamespace}
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
			if i.lastPodIPAssigned < diff {
				i.lastPodIPAssigned = diff
			}
		}
	}

	// resync VNI allocations
	i.allocatedVNIs = make(map[uint32]string)
	i.vxlanVNIs = make(map[string]uint32)
	for _, vniAllocProto := range kubeStateData[vnialloc.VxlanVNIKeyword] {
		alloc := vniAllocProto.(*vnialloc.VxlanVniAllocation)
		i.allocatedVNIs[alloc.Vni] = alloc.VxlanName
		i.vxlanVNIs[alloc.VxlanName] = alloc.Vni
	}

	i.Log.Infof("IPAM state after startup RESYNC: "+
		"excludedIPsfromNodeSubnet=%v, podSubnetAllNodes=%v, podSubnetThisNode=%v, "+
		"podSubnetGatewayIP=%v, hostInterconnectSubnetAllNodes=%v, "+
		"hostInterconnectSubnetThisNode=%v, hostInterconnectIPInVpp=%v, hostInterconnectIPInLinux=%v, "+
		"nodeInterconnectSubnet=%v, vxlanSubnet=%v, serviceCIDR=%v, "+
		"assignedPodIPs=%+v, podToIP=%v, lastPodIPAssigned=%v, vxlanVNIs=%v",
		i.excludedIPsfromNodeSubnet, i.podSubnetAllNodes, i.podSubnetThisNode,
		i.podSubnetGatewayIP, i.hostInterconnectSubnetAllNodes,
		i.hostInterconnectSubnetThisNode, i.hostInterconnectIPInVpp, i.hostInterconnectIPInLinux,
		i.nodeInterconnectSubnet, i.vxlanSubnet, i.serviceCIDR,
		i.assignedPodIPs, i.podToIP, i.lastPodIPAssigned, i.vxlanVNIs)
	return
}

// initializePodsIPAM initializes POD-related variables.
func (i *IPAM) initializePods(kubeStateData controller.KubeStateData, config *contivconf.CustomIPAMSubnets, nodeID uint32) (err error) {

	err = i.initializePodSubnets(kubeStateData, config, nodeID)
	if err != nil {
		return
	}

	i.podSubnetGatewayIP, err = cidr.Host(i.podSubnetThisNode, podGatewaySeqID)
	if err != nil {
		return nil
	}
	i.lastPodIPAssigned = 1
	i.assignedPodIPs = make(map[string]*podIPAllocation)
	i.podToIP = make(map[podmodel.ID]*podIPInfo)

	return nil
}

// initializePodsIPAM initializes POD-related variables.
func (i *IPAM) initializePodSubnets(kubeStateData controller.KubeStateData, config *contivconf.CustomIPAMSubnets, nodeID uint32) (err error) {
	i.podSubnetAllNodes = config.PodSubnetCIDR

	thisNodePodCIDR := ""

	// if external IPAM is in use, try to look up for this node's POD CIDR in k8s state data
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
		_, i.podSubnetThisNode, err = net.ParseCIDR(thisNodePodCIDR)
		if err != nil {
			return
		}
	} else {
		// pod subnet based on node ID
		i.podSubnetThisNode, err = dissectSubnetForNode(
			i.podSubnetAllNodes, config.PodSubnetOneNodePrefixLen, nodeID)
		if err != nil {
			return
		}
	}

	return nil
}

// initializeVPPHost initializes VPP-host interconnect-related variables.
func (i *IPAM) initializeVPPHost(config *contivconf.CustomIPAMSubnets, nodeID uint32) (err error) {
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

	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange &&
		ksChange.Resource == vnialloc.VxlanVNIKeyword {
		// update VNI allocations
		if ksChange.NewValue != nil {
			alloc := ksChange.NewValue.(*vnialloc.VxlanVniAllocation)
			i.allocatedVNIs[alloc.Vni] = alloc.VxlanName
			i.vxlanVNIs[alloc.VxlanName] = alloc.Vni
		} else if ksChange.PrevValue != nil {
			alloc := ksChange.PrevValue.(*vnialloc.VxlanVniAllocation)
			delete(i.allocatedVNIs, alloc.Vni)
			delete(i.vxlanVNIs, alloc.VxlanName)
		}
	}

	return "", nil
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

// PodSubnetAllNodes returns POD subnet that is a base subnet for all PODs of all nodes.
func (i *IPAM) PodSubnetAllNodes() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.podSubnetAllNodes)
}

// PodSubnetThisNode returns POD network for the current node (given by nodeID given at IPAM creation).
func (i *IPAM) PodSubnetThisNode() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.podSubnetThisNode)
}

// PodSubnetOtherNode returns the POD network of another node identified by nodeID.
func (i *IPAM) PodSubnetOtherNode(nodeID uint32) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	oneNodePrefixLen, _ := i.podSubnetThisNode.Mask.Size()
	podSubnetThisNode, err := dissectSubnetForNode(
		i.podSubnetAllNodes, uint8(oneNodePrefixLen), nodeID)
	if err != nil {
		return nil, err
	}
	return newIPNet(podSubnetThisNode), nil
}

// NodeIDFromPodIP returns node ID from provided POD IP address.
func (i *IPAM) NodeIDFromPodIP(podIP net.IP) (uint32, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	if !i.podSubnetAllNodes.Contains(podIP) {
		return 0, fmt.Errorf("pod IP %v not from pod subnet %v", podIP, i.podSubnetAllNodes)
	}

	subnet := i.podSubnetAllNodes.IP
	if !isIPv6Net(i.podSubnetAllNodes) {
		podIP = podIP.To4()
		subnet = subnet.To4()
	}
	ip := new(big.Int).SetBytes(podIP)
	podSubnetAllNodes := new(big.Int).SetBytes(subnet)

	addrLen := addrLenFromNet(i.podSubnetThisNode)
	oneNodePrefixLen, _ := i.podSubnetThisNode.Mask.Size()

	// zero pod subnet prefix for all nodes
	ip.Xor(ip, podSubnetAllNodes)

	// shift right to get rid of the node addressing part
	ip.Rsh(ip, uint(addrLen-oneNodePrefixLen))

	return uint32(ip.Uint64()), nil
}

// ServiceNetwork returns range allocated for services.
func (i *IPAM) ServiceNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIPNet(i.serviceCIDR)
}

// PodGatewayIP returns gateway IP address of the POD subnet of this node.
func (i *IPAM) PodGatewayIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.podSubnetGatewayIP)
}

// NatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (i *IPAM) NatLoopbackIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	// Last unicast IP from the pod subnet is used as NAT-loopback.
	_, broadcastIP := cidr.AddressRange(i.podSubnetThisNode)
	return cidr.Dec(broadcastIP)
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
	ip, err := i.allocateIP()
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
func (i *IPAM) AllocatePodCustomIfIP(podID podmodel.ID, ifName, network string, isServiceEndpoint bool) (net.IP, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// allocate an IP
	ip, err := i.allocateIP()
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
func (i *IPAM) persistCustomIfIPAllocation(podID podmodel.ID, ifName, network string, ip net.IP, isServiceEndpoint bool) error {
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

// allocateIP allocates a new IP from the main po IP pool.
func (i *IPAM) allocateIP() (net.IP, error) {
	last := i.lastPodIPAssigned + 1
	// iterate over all possible IP addresses for pod network prefix
	// start from the last assigned and take first available IP
	prefixBits, totalBits := i.podSubnetThisNode.Mask.Size()
	// get the maximum sequence ID available in the provided range; the last valid unicast IP is used as "NAT-loopback"
	podBitSize := uint(totalBits - prefixBits)
	// IPAM currently support up to 2^63 pods
	if podBitSize >= 64 {
		podBitSize = 63
	}
	maxSeqID := (1 << podBitSize) - 2
	for j := last; j < maxSeqID; j++ {
		ipForAssign, success := i.tryToAllocateIP(j, i.podSubnetThisNode)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	// iterate from the range start until lastPodIPAssigned
	for j := 1; j < last; j++ { // zero ending IP is reserved for network => skip seqID=0
		ipForAssign, success := i.tryToAllocateIP(j, i.podSubnetThisNode)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	return nil, fmt.Errorf("no IP address is free for allocation in the subnet %v", i.podSubnetThisNode)
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

// GetPodIP returns the allocated pod IP, together with the mask.
// Returns nil if the pod does not have allocated IP address.
func (i *IPAM) GetPodIP(podID podmodel.ID) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	allocation, found := i.podToIP[podID]
	if !found {
		return nil
	}
	addrLen := addrLenFromNet(i.podSubnetThisNode)
	return &net.IPNet{IP: allocation.mainIP, Mask: net.CIDRMask(addrLen, addrLen)}
}

// GetPodCustomIfIP returns the allocated custom interface pod IP, together with the mask.
// Returns nil if the pod does not have allocated custom interface IP address.
func (i *IPAM) GetPodCustomIfIP(podID podmodel.ID, ifName, network string) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	allocation, found := i.podToIP[podID]
	if !found {
		return nil
	}

	if ip, found := allocation.customIfIPs[customIfID(ifName, network)]; found {
		addrLen := addrLenFromNet(i.podSubnetThisNode)
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(addrLen, addrLen)}
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
		PodSubnetCIDR:        i.PodSubnetAllNodes().String(),
		VPPHostSubnetCIDR:    i.HostInterconnectSubnetAllNodes().String(),
	}
	if i.vxlanSubnet != nil {
		res.VxlanCIDR = i.vxlanSubnet.String()
	}
	s, _ := i.PodSubnetThisNode().Mask.Size()
	res.PodSubnetOneNodePrefixLen = uint8(s)

	s, _ = i.HostInterconnectSubnetThisNode().Mask.Size()
	res.VPPHostSubnetOneNodePrefixLen = uint8(s)

	return res
}

// AllocateVxlanVNI tries to allocate a free VNI for the VXLAN with given name.
// If the given VXLAN already has a VNI allocated, returns the existing allocation.
func (i *IPAM) AllocateVxlanVNI(vxlanName string) (vni uint32, err error) {

	// check if the given VXLAN has a VNI already allocated
	if vni, exists := i.vxlanVNIs[vxlanName]; exists {
		i.Log.Infof("Using already allocated VNI %d for VXLAN: %s", vni, vxlanName)
		return vni, nil
	}

	// get db broker - would return error if not connected
	db, err := i.getDBBroker()
	if err != nil {
		return 0, err
	}

	// step 1, allocate a free VNI number
	for vni = uint32(vxlanVNIPoolStart); vni <= vxlanVNIPoolEnd; vni++ {
		if _, used := i.allocatedVNIs[vni]; !used {
			// try to allocate this VNI
			ok, _ := i.dbPutIfNotExists(vnialloc.VNIAllocationKey(vni), nil)
			if ok {
				break // found a free VNI
			}
		}
	}

	// step 2, assign the VNI to the VXLAN
	alloc := &vnialloc.VxlanVniAllocation{VxlanName: vxlanName, Vni: vni}
	key := vnialloc.VxlanVNIKey(vxlanName)
	ok, _ := i.dbPutIfNotExists(key, alloc)
	if !ok {
		// this VXLAN may already have another VNI allocated
		// delete just allocated VNI number and try to use existing one
		db.Delete(vnialloc.VNIAllocationKey(vni))
		found, _, err := db.GetValue(key, alloc)
		if !found || err != nil {
			return 0, fmt.Errorf("error by getting existing allocation for vxlan %s: %v", vxlanName, err)
		}
		i.Log.Debugf("Using already allocated VNI %d for VXLAN: %s", vni, vxlanName)
		vni = alloc.Vni
	}

	i.Log.Infof("Allocated VNI %d for VXLAN: %s", vni, vxlanName)

	// save the allocation in internal maps
	i.allocatedVNIs[vni] = vxlanName
	i.vxlanVNIs[vxlanName] = vni

	return vni, nil
}

// GetVxlanVNI returns an existing VNI allocation for the VXLAN with given name.
// found is false if no allocation for the given VXLAN name exists.
func (i *IPAM) GetVxlanVNI(vxlanName string) (vni uint32, found bool) {
	vni, found = i.vxlanVNIs[vxlanName]
	return
}

// ReleaseVxlanVNI releases VNI allocated for the VXLAN with given name.
func (i *IPAM) ReleaseVxlanVNI(vxlanName string) error {

	// get db broker - would return error if not connected
	db, err := i.getDBBroker()
	if err != nil {
		i.Log.Errorf("Unable to release VXLAN VNI allocation: %v", err)
		return err
	}

	// retrieve the allocation from ETCD (may be already deleted from internal maps at this time)
	alloc := &vnialloc.VxlanVniAllocation{}
	key := vnialloc.VxlanVNIKey(vxlanName)
	found, _, err := db.GetValue(key, alloc)
	if !found {
		return nil // no need to release anything
	}
	if err != nil {
		i.Log.Errorf("Unable to retrieve VXLAN VNI allocation: %v", err)
		return err
	}

	// delete the allocations from ETCD
	// - do not check for errors, may fail if already deleted by other node
	db.Delete(vnialloc.VNIAllocationKey(alloc.Vni))
	db.Delete(vnialloc.VxlanVNIKey(vxlanName))

	i.Log.Infof("Released VNI %d allocated for VXLAN: %s", alloc.Vni, vxlanName)

	delete(i.vxlanVNIs, vxlanName)
	delete(i.allocatedVNIs, alloc.Vni)

	return nil
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

// SidForServiceHostLocalsid creates a valid SRv6 SID for service locasid leading to host on the current node. Created SID
// doesn't depend on anything and is the same for each node, because there is only one way how to get to host in each
// node and localsid have local significance (their sid don't have to be globally unique)
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

// SidForServiceNodeLocalsid creates a valid SRv6 SID for service locasid serving as intermediate step in policy segment list.
func (i *IPAM) SidForServiceNodeLocalsid(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.ServiceNodeLocalSIDSubnetCIDR)
}

// BsidForNodeToNodePodPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and routes traffic to pod VRF table
func (i *IPAM) BsidForNodeToNodePodPolicy(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodePodPolicySIDSubnetCIDR) // bsid = binding sid -> using the same util method
}

// BsidForNodeToNodeHostPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and routes traffic to main VRF table
func (i *IPAM) BsidForNodeToNodeHostPolicy(nodeIP net.IP) net.IP {
	return i.computeSID(nodeIP, i.ContivConf.GetIPAMConfig().SRv6Settings.NodeToNodeHostPolicySIDSubnetCIDR) // bsid = binding sid -> using the same util method
}

// computeSID creates SID by applying network prefix from <prefixNetwork> to IP <ip>
func (i *IPAM) computeSID(ip net.IP, prefixNetwork *net.IPNet) net.IP {
	ip = ip.To16()
	sid := net.IP(make([]byte, 16))
	for i := range ip {
		sid[i] = ip[i] & ^prefixNetwork.Mask[i] | prefixNetwork.IP[i]
	}
	return sid
}

// Close is NOOP.
func (i *IPAM) Close() error {
	return nil
}

// dissectSubnetForNode dissects a smaller chunk from a given subnet to be used
// exclusively by the node of the given ID.
func dissectSubnetForNode(subnetCIDR *net.IPNet, oneNodePrefixLen uint8, nodeID uint32) (nodeSubnet *net.IPNet, err error) {
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

// dbPutIfNotExists tries to put given proto value under given key.
func (i *IPAM) dbPutIfNotExists(key string, val proto.Message) (succeeded bool, err error) {
	encoded, err := json.Marshal(val)
	if err != nil {
		return false, err
	}
	ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
	return i.RemoteDB.PutIfNotExists(ksrPrefix+key, encoded)
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
