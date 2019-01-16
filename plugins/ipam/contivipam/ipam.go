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

package contivipam

import (
	"fmt"
	"net"
	"sync"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/cn-infra/infra"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/go-errors/errors"
)

const (
	// sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)
	podGatewaySeqID = 1

	// sequence ID reserved for VPP-end of the VPP to host interconnect
	hostInterconnectInVPPIPSeqID = 1

	// sequence ID reserved for host(Linux)-end of the VPP to host interconnect
	hostInterconnectInLinuxIPSeqID = 2
)

// IPAM plugin implements IP address allocation for Contiv.
type IPAM struct {
	Deps

	mutex sync.RWMutex

	excludedIPsfromNodeSubnet []uint32 // IPs from the NodeInterconnect Subnet that should not be assigned

	/********** POD related variables **********/
	// IPv4 subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podSubnetAllNodes *net.IPNet
	// IPv4 subnet prefix for all PODs on this node (given by nodeID), podSubnetAllNodes + nodeID ==<computation>==> podSubnetThisNode
	podSubnetThisNode *net.IPNet
	// gateway IP address for PODs on this node (given by nodeID)
	podSubnetGatewayIP net.IP

	/********** maps to convert between Pod and the assigned IP **********/
	// pool of assigned POD IP addresses
	assignedPodIPs map[uintIP]podmodel.ID
	// pod -> allocated IP address
	podToIP map[podmodel.ID]net.IP
	// counter denoting last assigned pod IP address
	lastPodIPAssigned int

	/********** VSwitch related variables **********/
	// IPv4 subnet used across all nodes for VPP to host Linux stack interconnect
	hostInterconnectSubnetAllNodes *net.IPNet
	// IPv4 subnet used by this node (given by nodeID) for VPP to host Linux stack interconnect,
	// hostInterconnectSubnetAllNodes + nodeID ==<computation>==> hostInterconnectSubnetThisNode
	hostInterconnectSubnetThisNode *net.IPNet
	// IPv4 address for virtual ethernet's VPP-end on this node
	hostInterconnectIPInVpp net.IP
	// IPv4 address for virtual ethernet's host(Linux)-end on this node
	hostInterconnectIPInLinux net.IP

	/********** node related variables **********/
	// IPv4 subnet used for for inter-node connections
	nodeInterconnectSubnet *net.IPNet
	// IPv4 subnet used for for inter-node VXLAN
	vxlanSubnet *net.IPNet
	// IPv4 subnet used to allocate ClusterIPs for a service
	serviceCIDR *net.IPNet
}

// Deps lists dependencies of the IPAM plugin.
type Deps struct {
	infra.PluginDeps
	NodeSync   nodesync.API
	ContivConf contivconf.API
}

type uintIP = uint32

// Init is NOOP - the plugin is initialized during the first resync.
func (i *IPAM) Init() (err error) {
	return nil
}

// HandlesEvent selects any Resync event.
func (i *IPAM) HandlesEvent(event controller.Event) bool {
	return event.Method() != controller.Update
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

	if resyncCount > 1 {
		// No need to run resync for IPAM in run-time - the IPAM configuration
		// cannot change and IP address will not be allocated to a local pod without
		// the agent knowing about it. Also there is a risk of a race condition
		//  - resync triggered shortly after Add/DelPod may work with K8s state
		// data that do not yet reflect the freshly added/removed pod.
		return nil
	}

	nodeID := i.NodeSync.GetNodeID()

	// exclude gateway from the set of allocated node IPs
	i.excludedIPsfromNodeSubnet = []uint32{}
	defaultGW := i.ContivConf.GetStaticDefaultGW()
	if len(defaultGW) > 0 {
		excluded, err := ipv4ToUint32(defaultGW)
		if err != nil {
			return err
		}
		i.excludedIPsfromNodeSubnet = []uint32{excluded}
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
	if err := i.initializePods(subnets, nodeID); err != nil {
		return err
	}
	if err := i.initializeVPPHost(subnets, nodeID); err != nil {
		return err
	}
	i.serviceCIDR = ipamConfig.ServiceCIDR
	i.nodeInterconnectSubnet = subnets.NodeInterconnectCIDR
	i.vxlanSubnet = subnets.VxlanCIDR

	// resync allocated IP addresses
	networkPrefix, err := ipv4ToUint32(i.podSubnetThisNode.IP)
	if err != nil {
		return err
	}
	for _, podProto := range kubeStateData[podmodel.PodKeyword] {
		pod := podProto.(*podmodel.Pod)
		// ignore pods deployed on other nodes or without IP address
		podIPAddress := net.ParseIP(pod.IpAddress)
		if podIPAddress == nil || !i.podSubnetThisNode.Contains(podIPAddress) {
			continue
		}

		// register address as already allocated
		addrIndex, _ := ipv4ToUint32(podIPAddress)
		podID := podmodel.ID{Name: pod.Name, Namespace: pod.Namespace}
		i.assignedPodIPs[addrIndex] = podID
		i.podToIP[podID] = podIPAddress

		diff := int(addrIndex - networkPrefix)
		if i.lastPodIPAssigned < diff {
			i.lastPodIPAssigned = diff
		}
	}

	i.Log.Infof("IPAM state after startup RESYNC: "+
		"excludedIPsfromNodeSubnet=%v, podSubnetAllNodes=%v, podSubnetThisNode=%v, "+
		"podSubnetGatewayIP=%v, hostInterconnectSubnetAllNodes=%v, "+
		"hostInterconnectSubnetThisNode=%v, hostInterconnectIPInVpp=%v, hostInterconnectIPInLinux=%v, "+
		"nodeInterconnectSubnet=%v, vxlanSubnet=%v, serviceCIDR=%v, "+
		"assignedPodIPs=%+v, podToIP=%v, lastPodIPAssigned=%v",
		i.excludedIPsfromNodeSubnet, i.podSubnetAllNodes, i.podSubnetThisNode,
		i.podSubnetGatewayIP, i.hostInterconnectSubnetAllNodes,
		i.hostInterconnectSubnetThisNode, i.hostInterconnectIPInVpp, i.hostInterconnectIPInLinux,
		i.nodeInterconnectSubnet, i.vxlanSubnet, i.serviceCIDR,
		i.assignedPodIPs, i.podToIP, i.lastPodIPAssigned)
	return
}

// initializePodsIPAM initializes POD-related variables.
func (i *IPAM) initializePods(config *contivconf.CustomIPAMSubnets, nodeID uint32) (err error) {
	i.podSubnetAllNodes = config.PodSubnetCIDR
	i.podSubnetThisNode, err = dissectSubnetForNode(
		i.podSubnetAllNodes, config.PodSubnetOneNodePrefixLen, nodeID)
	if err != nil {
		return
	}

	podNetworkPrefixUint32, err := ipv4ToUint32(i.podSubnetThisNode.IP)
	if err != nil {
		return
	}
	i.podSubnetGatewayIP = uint32ToIpv4(podNetworkPrefixUint32 + podGatewaySeqID)
	i.lastPodIPAssigned = 1
	i.assignedPodIPs = make(map[uintIP]podmodel.ID)
	i.podToIP = make(map[podmodel.ID]net.IP)
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

	vSwitchNetworkPrefixUint32, err := ipv4ToUint32(i.hostInterconnectSubnetThisNode.IP)
	if err != nil {
		return
	}
	i.hostInterconnectIPInVpp = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInVPPIPSeqID)
	i.hostInterconnectIPInLinux = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInLinuxIPSeqID)
	return
}

// Update is NOOP - never called.
func (i *IPAM) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
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
	maskSize, _ := i.nodeInterconnectSubnet.Mask.Size()
	mask := net.CIDRMask(maskSize, 32)
	nodeIPNetwork := &net.IPNet{
		IP:   newIP(nodeIP).Mask(mask),
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
	mask := net.CIDRMask(maskSize, 32)
	vxlanNetwork := &net.IPNet{
		IP:   newIP(vxlanIP).Mask(mask),
		Mask: mask,
	}
	return vxlanIP, vxlanNetwork, nil
}

// HostInterconnectIPInVPP provides the IPv4 address for the VPP-end of the VPP-to-host
// interconnect.
func (i *IPAM) HostInterconnectIPInVPP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.hostInterconnectIPInVpp)
}

// HostInterconnectIPInLinux provides the IPv4 address of the host(Linux)-end of the VPP to host interconnect.
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

	// get network prefix as uint32
	networkPrefix, err := ipv4ToUint32(i.podSubnetThisNode.IP)
	if err != nil {
		return nil, err
	}

	last := i.lastPodIPAssigned + 1
	// iterate over all possible IP addresses for pod network prefix
	// start from the last assigned and take first available IP
	prefixBits, totalBits := i.podSubnetThisNode.Mask.Size()
	// get the maximum sequence ID available in the provided range; the last valid unicast IP is used as "NAT-loopback"
	maxSeqID := (1 << uint(totalBits-prefixBits)) - 2
	for j := last; j < maxSeqID; j++ {
		ipForAssign, success := i.tryToAllocatePodIP(j, networkPrefix, podID)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	// iterate from the range start until lastPodIPAssigned
	for j := 1; j < last; j++ { // zero ending IP is reserved for network => skip seqID=0
		ipForAssign, success := i.tryToAllocatePodIP(j, networkPrefix, podID)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	return nil, fmt.Errorf("no IP address is free for allocation in the subnet %v", i.podSubnetThisNode)
}

// tryToAllocatePodIP checks whether the IP at the given index is available.
func (i *IPAM) tryToAllocatePodIP(index int, networkPrefix uint32, podID podmodel.ID) (assignedIP net.IP, success bool) {
	if index == podGatewaySeqID {
		return nil, false // gateway IP address can't be assigned as pod
	}
	ip := networkPrefix + uint32(index)
	if _, found := i.assignedPodIPs[ip]; found {
		return nil, false // ignore already assigned IP addresses
	}

	i.assignedPodIPs[ip] = podID

	ipForAssign := uint32ToIpv4(ip)
	i.podToIP[podID] = ipForAssign
	i.Log.Infof("Assigned new pod IP %s", ipForAssign)
	i.logAssignedPodIPPool()

	return ipForAssign, true
}

// GetPodIP returns the allocated pod IP, together with the mask.
// Returns nil if the pod does not have allocated IP address.
func (i *IPAM) GetPodIP(podID podmodel.ID) *net.IPNet {
	addr, found := i.podToIP[podID]
	if !found {
		return nil
	}
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8)}
}

// ReleasePodIP releases the pod IP address making it available for new PODs.
func (i *IPAM) ReleasePodIP(podID podmodel.ID) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	addr, found := i.podToIP[podID]
	if !found {
		i.Log.Warnf("Unable to find IP for pod %v", podID)
		return nil
	}
	addrIndex, _ := ipv4ToUint32(addr)
	delete(i.assignedPodIPs, addrIndex)
	delete(i.podToIP, podID)

	i.Log.Infof("Released IP %v for pod ID %v", addr, podID)
	i.logAssignedPodIPPool()
	return nil
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

	nodePartBitSize := oneNodePrefixLen - uint8(subnetPrefixLen)
	nodeIPPart, err := convertToNodeIPPart(nodeID, nodePartBitSize)
	if err != nil {
		return nil, err
	}

	subnetIPPartUint32, err := ipv4ToUint32(subnetCIDR.IP)
	if err != nil {
		return nil, err
	}
	nodeSubnetUint32 := subnetIPPartUint32 + (uint32(nodeIPPart) << (32 - oneNodePrefixLen))
	nodeSubnet = &net.IPNet{
		IP:   uint32ToIpv4(nodeSubnetUint32),
		Mask: net.CIDRMask(int(oneNodePrefixLen), 32),
	}
	return
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

	// trimming nodeID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.nodeInterconnectSubnet.Mask.Size()
	nodePartBitSize := 32 - uint8(subnetPrefixLen)
	nodeIPPart, err := convertToNodeIPPart(nodeID, nodePartBitSize)
	if err != nil {
		return nil, err
	}
	// nodeIPPart equal to 0 is not valid for IP address
	if nodeIPPart == 0 {
		return nil, fmt.Errorf("no free address for nodeID %v", nodeID)
	}

	// combining it to get result IP address
	networkIPPartUint32, err := ipv4ToUint32(i.nodeInterconnectSubnet.IP)
	if err != nil {
		return nil, err
	}
	computedIP := networkIPPartUint32 + uint32(nodeIPPart)

	// skip excluded IPs (gateway or other invalid address)
	for _, ex := range i.excludedIPsfromNodeSubnet {
		if ex <= computedIP {
			computedIP++
		}
	}

	return uint32ToIpv4(computedIP), nil
}

// computeVxlanIPAddress computes IP address of the VXLAN interface based on the given node ID.
func (i *IPAM) computeVxlanIPAddress(nodeID uint32) (net.IP, error) {
	// trimming nodeID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.vxlanSubnet.Mask.Size()
	nodePartBitSize := 32 - uint8(subnetPrefixLen)
	nodeIPPart, err := convertToNodeIPPart(nodeID, nodePartBitSize)
	if err != nil {
		return nil, err
	}
	// nodeIPpart equal to 0 is not valid for IP address
	if nodeIPPart == 0 {
		return nil, fmt.Errorf("no free address for nodeID %v", nodeID)
	}

	// combining it to get result IP address
	networkIPPartUint32, err := ipv4ToUint32(i.vxlanSubnet.IP)
	if err != nil {
		return nil, err
	}
	return uint32ToIpv4(networkIPPartUint32 + uint32(nodeIPPart)), nil
}
