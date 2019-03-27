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

package ipam

import (
	"fmt"
	"net"
	"sync"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/cn-infra/infra"

	"bytes"
	cnisb "github.com/containernetworking/cni/pkg/types/current"
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/go-errors/errors"
	"github.com/ligato/cn-infra/servicelabel"
	"math/big"
	"strings"
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
	assignedPodIPs map[string]podmodel.ID
	// pod -> allocated IP address
	podToIP map[podmodel.ID]net.IP
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
}

// Deps lists dependencies of the IPAM plugin.
type Deps struct {
	infra.PluginDeps
	NodeSync     nodesync.API
	ContivConf   contivconf.API
	ServiceLabel servicelabel.ReaderAPI
	EventLoop    controller.EventLoop
}

// Init is NOOP - the plugin is initialized during the first resync.
func (i *IPAM) Init() (err error) {
	return nil
}

// HandlesEvent selects any Resync event.
//   - any Resync event
//   - NodeUpdate for the current node if external IPAM is in use (may trigger PodCIDRChange)
func (i *IPAM) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
			return nodeUpdate.NodeName == i.ServiceLabel.GetAgentLabel()
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
	if err := i.initializePods(kubeStateData, subnets, nodeID); err != nil {
		return err
	}
	if err := i.initializeVPPHost(subnets, nodeID); err != nil {
		return err
	}
	i.serviceCIDR = ipamConfig.ServiceCIDR
	i.nodeInterconnectSubnet = subnets.NodeInterconnectCIDR
	i.vxlanSubnet = subnets.VxlanCIDR

	// resync allocated IP addresses
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
		i.assignedPodIPs[podIPAddress.String()] = podID
		i.podToIP[podID] = podIPAddress

		diff := int(addr.Sub(addr, networkPrefix).Int64())
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
	i.assignedPodIPs = make(map[string]podmodel.ID)
	i.podToIP = make(map[podmodel.ID]net.IP)

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
	ip, found := i.podToIP[podID]
	if found {
		return ip, nil
	}

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
		ipForAssign, success := i.tryToAllocatePodIP(j, i.podSubnetThisNode, podID)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	// iterate from the range start until lastPodIPAssigned
	for j := 1; j < last; j++ { // zero ending IP is reserved for network => skip seqID=0
		ipForAssign, success := i.tryToAllocatePodIP(j, i.podSubnetThisNode, podID)
		if success {
			i.lastPodIPAssigned = j
			return ipForAssign, nil
		}
	}

	return nil, fmt.Errorf("no IP address is free for allocation in the subnet %v", i.podSubnetThisNode)
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
	i.podToIP[podID] = ip

	i.Log.Infof("Assigned new pod IP %v for POD ID %v", ip, podID)

	return ip, nil
}

// tryToAllocatePodIP checks whether the IP at the given index is available.
func (i *IPAM) tryToAllocatePodIP(index int, networkPrefix *net.IPNet, podID podmodel.ID) (assignedIP net.IP, success bool) {
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

	i.assignedPodIPs[ip.String()] = podID

	i.podToIP[podID] = ip
	i.Log.Infof("Assigned new pod IP %s", ip)
	i.logAssignedPodIPPool()

	return ip, true
}

// GetPodIP returns the allocated pod IP, together with the mask.
// Returns nil if the pod does not have allocated IP address.
func (i *IPAM) GetPodIP(podID podmodel.ID) *net.IPNet {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	addr, found := i.podToIP[podID]
	if !found {
		return nil
	}
	addrLen := addrLenFromNet(i.podSubnetThisNode)
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(addrLen, addrLen)}
}

// GetPodFromIP returns the pod information related to the allocated pod IP.
// found is false if the provided IP address has not been allocated to any local pod.
func (i *IPAM) GetPodFromIP(podIP net.IP) (podID podmodel.ID, found bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	podID, found = i.assignedPodIPs[podIP.String()]
	return
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
	delete(i.podToIP, podID)

	i.Log.Infof("Released IP %v for pod ID %v", addr, podID)

	if i.ContivConf.GetIPAMConfig().UseExternalIPAM {
		// no further processing for external IPAM
		return nil
	}

	delete(i.assignedPodIPs, addr.String())

	i.logAssignedPodIPPool()
	return nil
}

func (i *IPAM) GetIPAMConfigForJSON() *contivconf.IPAMConfigForJSON {
	c := i.ContivConf.GetIPAMConfigForJSON()
	res := &contivconf.IPAMConfigForJSON{
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
