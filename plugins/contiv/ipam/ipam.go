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

package ipam

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/ligato/cn-infra/logging"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	podGatewaySeqID = 1 // sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)

	hostInterconnectInVPPIPSeqID   = 1 // sequence ID reserved for VPP-end of the VPP to host interconnect
	hostInterconnectInLinuxIPSeqID = 2 // sequence ID reserved for host(Linux)-end of the VPP to host interconnect

	defaultServiceCIDR = "10.96.0.0/12" // default subnet allocated for services
)

// IPAM implements IP address allocation for Contiv.
type IPAM struct {
	logger logging.Logger
	mutex  sync.RWMutex

	nodeID   uint32 // identifier of the node for which this IPAM is created for
	nodeName string // node name for which this IPAM is created for

	// POD related variables
	podSubnetAllNodes  net.IPNet // IPv4 subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podSubnetThisNode  net.IPNet // IPv4 subnet prefix for all PODs on this node (given by nodeID), podSubnetAllNodes + nodeID ==<computation>==> podSubnetThisNode
	podSubnetGatewayIP net.IP    // gateway IP address for PODs on this node (given by nodeID)
	podVPPSubnet       net.IPNet // IPv4 subnet from which individual VPP-side POD interfaces networks are allocated, this is subnet for all PODS within this node.

	// maps to convert between Pod and the assigned IP
	assignedPodIPs map[uintIP]podmodel.ID // pool of assigned POD IP addresses
	podToIP        map[podmodel.ID]net.IP // pod -> allocated IP address

	// VSwitch related variables
	hostInterconnectSubnetAllNodes net.IPNet // IPv4 subnet used across all nodes for VPP to host Linux stack interconnect
	hostInterconnectSubnetThisNode net.IPNet // IPv4 subnet used by this node (given by nodeID) for VPP to host Linux stack interconnect, hostInterconnectSubnetAllNodes + nodeID ==<computation>==> hostInterconnectSubnetThisNode
	hostInterconnectIPInVpp        net.IP    // IPv4 address for virtual ethernet's VPP-end on this node
	hostInterconnectIPInLinux      net.IP    // IPv4 address for virtual ethernet's host(Linux)-end on this node

	// node related variables
	nodeInterconnectDHCP   bool      // whether to use DHCP to acquire IP for inter-node interface by default (can be overridden in NodeConfig by defining IP)
	nodeInterconnectSubnet net.IPNet // IPv4 subnet used for for inter-node connections
	vxlanSubnet            net.IPNet // IPv4 subnet used for for inter-node VXLAN
	serviceCIDR            net.IPNet // IPv4 subnet used to allocate ClusterIPs for a service

	excludededIPsfromNodeSubnet []uint32 // IPs from the NodeInterconnect Subnet that should not be assigned

	lastPodIPAssigned int // counter denoting last assigned pod IP address

	config *Config // ipam configuration
}

type uintIP = uint32

// Config represents configuration of the IPAM module.
type Config struct {
	PodVPPSubnetCIDR              string `json:"podVPPSubnetCIDR"`              // subnet from which individual VPP-side POD interfaces networks are allocated, this subnet is reused by every node.
	PodSubnetCIDR                 string `json:"podSubnetCIDR"`                 // subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	PodSubnetOneNodePrefixLen     uint8  `json:"podSubnetOneNodePrefixLen"`     // prefix length of subnet used for all PODs within 1 node (pod network = pod subnet for one 1 node)
	VPPHostSubnetCIDR             string `json:"vppHostSubnetCIDR"`             // subnet used across all nodes for VPP to host Linux stack interconnect
	VPPHostSubnetOneNodePrefixLen uint8  `json:"vppHostSubnetOneNodePrefixLen"` // prefix length of subnet used for for VPP to host Linux stack interconnect within 1 node (VPPHost network = VPPHost subnet for one 1 node)
	NodeInterconnectCIDR          string `json:"nodeInterconnectCIDR"`          // subnet used for for inter-node connections
	NodeInterconnectDHCP          bool   `json:"nodeInterconnectDHCP"`          // if set to true DHCP is used to acquire IP for the main VPP interface (NodeInterconnectCIDR can be omitted in config)
	VxlanCIDR                     string `json:"vxlanCIDR"`                     // subnet used for for inter-node VXLAN
	ServiceCIDR                   string `json:"serviceCIDR"`                   // subnet used by services
	ContivCIDR                    string `json:"contivCIDR"`                    // subnet from which all subnets (pod/node/vxlan) will be created
}

// New returns new IPAM module to be used on the node specified by the nodeID.
func New(logger logging.Logger, nodeID uint32, config *Config, nodeInterconnectExcludedIPs []net.IP) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		logger:            logger,
		nodeID:            nodeID,
		lastPodIPAssigned: 1,
		config:            config,
	}

	// computing IPAM struct variables from IPAM config
	if err := initializePodsIPAM(ipam, config, nodeID); err != nil {
		return nil, err
	}
	if err := initializeVPPHostIPAM(ipam, config, nodeID); err != nil {
		return nil, err
	}
	if err := initializeNodeInterconnectIPAM(ipam, config); err != nil {
		return nil, err
	}
	if err := initializePodVPPSubnet(ipam, config); err != nil {
		return nil, err
	}
	excludedIPs, err := sortIPv4SliceToUint32(nodeInterconnectExcludedIPs)
	if err != nil {
		return nil, err
	}
	ipam.excludededIPsfromNodeSubnet = excludedIPs
	if excludedIPs != nil {
		logger.Info("Following IPs are excluded from NodeCIDR: ", nodeInterconnectExcludedIPs)
	}
	logger.Infof("IPAM values loaded: %+v", ipam)

	return ipam, nil
}

// Resync resynchronizes IPAM against Kubernetes state data.
// A set of already allocated pod IPs is updated.
func (i *IPAM) Resync(kubeStateData controller.KubeStateData) (err error) {
	networkPrefix, err := ipv4ToUint32(i.podSubnetThisNode.IP)
	if err != nil {
		return err
	}

	// reset internal state
	i.lastPodIPAssigned = 1
	i.assignedPodIPs = make(map[uintIP]podmodel.ID)
	i.podToIP = make(map[podmodel.ID]net.IP)

	// iterate over pod state data
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

	i.logger.Infof("IPAM state after RESYNC: (assignedPodIPs=%+v, lastPodIPAssigned=%v)",
		i.assignedPodIPs, i.lastPodIPAssigned)
	return err
}

// NodeInterconnectDHCPEnabled returns true if DHCP should be configured on the main
// vpp interface by default.
func (i *IPAM) NodeInterconnectDHCPEnabled() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.nodeInterconnectDHCP
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

// HostInterconnectIPInVPP provides the IPv4 address of the VPP-end of the VPP to host interconnect veth pair.
func (i *IPAM) HostInterconnectIPInVPP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.hostInterconnectIPInVpp) // defensive copy
}

// HostInterconnectIPInLinux provides the IPv4 address of the host(Linux)-end of the VPP to host interconnect veth pair.
func (i *IPAM) HostInterconnectIPInLinux() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.hostInterconnectIPInLinux) // defensive copy
}

// HostInterconnectSubnetThisNode returns vswitch network used to connect VPP to its host Linux Stack.
func (i *IPAM) HostInterconnectSubnetThisNode() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	vSwitchNetwork := newIPNet(i.hostInterconnectSubnetThisNode) // defensive copy
	return &vSwitchNetwork
}

// HostInterconnectSubnetAllNodes returns vswitch base subnet used to connect VPP to its host Linux Stack on all nodes.
func (i *IPAM) HostInterconnectSubnetAllNodes() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	vSwitchNetwork := newIPNet(i.hostInterconnectSubnetAllNodes) // defensive copy
	return &vSwitchNetwork
}

// HostInterconnectSubnetOtherNode returns VPP-host network of another node identified by nodeID.
func (i *IPAM) HostInterconnectSubnetOtherNode(nodeID uint32) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	networkSize, _ := i.hostInterconnectSubnetThisNode.Mask.Size()
	vSwitchNetworkIPPrefix, err := applyNodeID(i.hostInterconnectSubnetAllNodes, nodeID, uint8(networkSize))
	if err != nil {
		return nil, err
	}
	vSwitchNetwork := newIPNet(vSwitchNetworkIPPrefix) // defensive copy
	return &vSwitchNetwork, nil
}

// PodSubnetAllNodes returns POD subnet ("network_address/prefix_length") that is a base subnet for all PODs of all nodes.
func (i *IPAM) PodSubnetAllNodes() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podSubnet := newIPNet(i.podSubnetAllNodes) // defensive copy
	return &podSubnet
}

// PodSubnetThisNode returns POD network for the current node (given by nodeID given at IPAM creation).
func (i *IPAM) PodSubnetThisNode() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podNetwork := newIPNet(i.podSubnetThisNode) // defensive copy
	return &podNetwork
}

// PodSubnetOtherNode returns the POD network of another node identified by nodeID.
func (i *IPAM) PodSubnetOtherNode(nodeID uint32) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	networkSize, _ := i.podSubnetThisNode.Mask.Size()
	podSubnetThisNode, err := applyNodeID(i.podSubnetAllNodes, nodeID, uint8(networkSize))
	if err != nil {
		return nil, err
	}
	podNetwork := newIPNet(podSubnetThisNode) // defensive copy
	return &podNetwork, nil
}

// PodVPPSubnet returns VPP-side interface IP address prefix.
func (i *IPAM) PodVPPSubnet() *net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podIfIPPrefix := newIPNet(i.podVPPSubnet) // defensive copy
	return &podIfIPPrefix.IP
}

// ServiceNetwork returns range allocated for services.
func (i *IPAM) ServiceNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	serviceNetwork := newIPNet(i.serviceCIDR) // defensive copy
	return &serviceNetwork
}

// PodGatewayIP returns gateway IP address of the POD subnet of this node.
func (i *IPAM) PodGatewayIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.podSubnetGatewayIP) // defensive copy
}

// AllocatePodIP tries to allocate IP address for the given pod.
func (i *IPAM) AllocatePodIP(podID podmodel.ID) (net.IP, error) {
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
	i.logger.Infof("Assigned new pod IP %s", ipForAssign)
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
		i.logger.Warnf("Unable to find IP for pod %v", podID)
		return nil
	}
	addrIndex, _ := ipv4ToUint32(addr)
	delete(i.assignedPodIPs, addrIndex)
	delete(i.podToIP, podID)

	i.logger.Infof("Released IP %v for pod ID %v", addr, podID)
	i.logAssignedPodIPPool()
	return nil
}

// initializePodsIPAM initializes POD -related variables of IPAM.
func initializePodsIPAM(ipam *IPAM, config *Config, nodeID uint32) (err error) {
	ipam.podSubnetAllNodes, ipam.podSubnetThisNode, err = convertConfigNotation(config.PodSubnetCIDR, config.PodSubnetOneNodePrefixLen, nodeID)
	if err != nil {
		return
	}

	podNetworkPrefixUint32, err := ipv4ToUint32(ipam.podSubnetThisNode.IP)
	if err != nil {
		return
	}
	ipam.podSubnetGatewayIP = uint32ToIpv4(podNetworkPrefixUint32 + podGatewaySeqID)
	ipam.assignedPodIPs = make(map[uintIP]podmodel.ID)
	ipam.podToIP = make(map[podmodel.ID]net.IP)
	return nil
}

// initializeVPPHostIPAM initializes VPP-host interconnect -related variables of IPAM.
func initializeVPPHostIPAM(ipam *IPAM, config *Config, nodeID uint32) (err error) {
	ipam.hostInterconnectSubnetAllNodes, ipam.hostInterconnectSubnetThisNode, err = convertConfigNotation(config.VPPHostSubnetCIDR, config.VPPHostSubnetOneNodePrefixLen, nodeID)
	if err != nil {
		return
	}

	vSwitchNetworkPrefixUint32, err := ipv4ToUint32(ipam.hostInterconnectSubnetThisNode.IP)
	if err != nil {
		return
	}
	ipam.hostInterconnectIPInVpp = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInVPPIPSeqID)
	ipam.hostInterconnectIPInLinux = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInLinuxIPSeqID)

	if config.ServiceCIDR == "" {
		config.ServiceCIDR = defaultServiceCIDR
	}
	_, serviceSubnet, err := net.ParseCIDR(config.ServiceCIDR)
	if err != nil {
		return
	}
	ipam.serviceCIDR = *serviceSubnet

	return
}

// initializeNodeInterconnectIPAM initializes node interconnect -related variables of IPAM.
func initializeNodeInterconnectIPAM(ipam *IPAM, config *Config) (err error) {
	if config == nil || (config.NodeInterconnectCIDR == "" && config.NodeInterconnectDHCP == false) || config.VxlanCIDR == "" {
		return fmt.Errorf("missing NodeInterconnectCIDR or NodeInterconnectDHCP or VxlanCIDR configuration")
	}

	ipam.nodeInterconnectDHCP = config.NodeInterconnectDHCP

	if !ipam.nodeInterconnectDHCP {
		_, nodeSubnet, err := net.ParseCIDR(config.NodeInterconnectCIDR)
		if err != nil {
			return err
		}
		ipam.nodeInterconnectSubnet = *nodeSubnet
	}

	_, vxlanSubnet, err := net.ParseCIDR(config.VxlanCIDR)
	if err != nil {
		return
	}
	ipam.vxlanSubnet = *vxlanSubnet
	return
}

// initializePodVPPSubnet initializes node vpp-side POD interface -related variables of IPAM.
func initializePodVPPSubnet(ipam *IPAM, config *Config) (err error) {
	if config == nil || config.PodVPPSubnetCIDR == "" {
		return fmt.Errorf("missing PodVPPSubnetCIDR configuration")
	}

	_, podVPPSubnet, err := net.ParseCIDR(config.PodVPPSubnetCIDR)
	if err != nil {
		return
	}
	ipam.podVPPSubnet = *podVPPSubnet
	return
}

// convertConfigNotation converts config notation and given node ID to IPAM structure notation.
// I.e: input 1.2.3.4/16 (string), /24 (uint8), 5 (uint8) results in 1.2.0.0/16 (IPNet), 1.2.5.0/24 (IPNet)
func convertConfigNotation(subnetCIDR string, networkPrefixLen uint8, nodeID uint32) (subnetIPPrefix net.IPNet, networkIPPrefix net.IPNet, err error) {
	// convert subnetCIDR to net.IPNet
	_, pSubnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		err = fmt.Errorf("Can't parse SubnetCIDR \"%v\" : %v", subnetCIDR, err)
		return
	}
	subnetIPPrefix = *pSubnet

	// checking correct prefix sizes
	subnetPrefixLen, _ := subnetIPPrefix.Mask.Size()
	if networkPrefixLen <= uint8(subnetPrefixLen) {
		err = fmt.Errorf("Network prefix length (%v) must be higher than subnet prefix length (%v) ", networkPrefixLen, subnetPrefixLen)
		return
	}

	networkIPPrefix, err = applyNodeID(subnetIPPrefix, nodeID, networkPrefixLen)
	return
}

// applyNodeID creates network (IPNet) from subnet by adding transformed node ID to it.
func applyNodeID(subnetIPPrefix net.IPNet, nodeID uint32, networkPrefixLen uint8) (networkIPPrefix net.IPNet, err error) {
	// compute part of IP address representing host
	subnetPrefixLen, _ := subnetIPPrefix.Mask.Size()
	nodePartBitSize := networkPrefixLen - uint8(subnetPrefixLen)
	nodeIPPart, err := convertToNodeIPPart(nodeID, nodePartBitSize)
	if err != nil {
		return net.IPNet{}, err
	}

	// composing network IP prefix from previously computed parts
	subnetIPPartUint32, err := ipv4ToUint32(subnetIPPrefix.IP)
	if err != nil {
		return
	}
	networkPrefixUint32 := subnetIPPartUint32 + (uint32(nodeIPPart) << (32 - networkPrefixLen))
	networkIPPrefix = net.IPNet{
		IP:   uint32ToIpv4(networkPrefixUint32),
		Mask: net.CIDRMask(int(networkPrefixLen), 32),
	}
	return
}

// logAssignedPodIPPool logs assigned POD IPs.
func (i *IPAM) logAssignedPodIPPool() {
	if i.logger.GetLevel() <= logging.DebugLevel { // log only if debug level or more verbose
		var buffer bytes.Buffer
		for uintIP, podID := range i.assignedPodIPs {
			buffer.WriteString(" # " + uint32ToIpv4(uintIP).String() + ":" + podID.String())
		}
		i.logger.Debugf("Current pool of assigned pod IP addresses: %v", buffer.String())
	}

}

// computeNodeIPAddress computes IP address of node based on the given node ID.
func (i *IPAM) computeNodeIPAddress(nodeID uint32) (net.IP, error) {
	// trimming nodeID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.nodeInterconnectSubnet.Mask.Size()
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
	networkIPPartUint32, err := ipv4ToUint32(i.nodeInterconnectSubnet.IP)
	if err != nil {
		return nil, err
	}
	computedIP := networkIPPartUint32 + uint32(nodeIPPart)

	// skip excluded IPs (gateway or other invalid address)
	for _, ex := range i.excludededIPsfromNodeSubnet {
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

// convertToNodeIPPart converts nodeID to part of IP address that distinguishes network IP address prefix among
// different nodes.
func convertToNodeIPPart(nodeID uint32, expectedNodePartBitSize uint8) (res uint32, err error) {
	// the last valid nodeID correspond to 0 nodeIPpart,
	// this value is valid to be used for subnet, however not for IP address computation
	if nodeID == (1 << expectedNodePartBitSize) {
		return 0, nil
	}

	res = nodeID & ((1 << expectedNodePartBitSize) - 1)
	if res != nodeID {
		return 0, fmt.Errorf("nodeID is out of the valid range %v > %v", nodeID, 1<<expectedNodePartBitSize)
	}
	return res, nil
}

// ipv4ToUint32 is simple utility function for conversion between IPv4 and uint32.
func ipv4ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("Ip address %v is not ipv4 address (or ipv6 convertible to ipv4 address)", ip)
	}
	var tmp uint32
	for _, bytePart := range ip {
		tmp = tmp<<8 + uint32(bytePart)
	}
	return tmp, nil
}

func sortIPv4SliceToUint32(ips []net.IP) ([]uint32, error) {
	var res []uint32
	for _, ip := range ips {
		converted, err := ipv4ToUint32(ip)
		if err != nil {
			return nil, err
		}
		res = append(res, converted)
	}
	sort.Sort(sortableUint32(res))
	return res, nil
}

// uint32ToIpv4 is simple utility function for conversion between IPv4 and uint32.
func uint32ToIpv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4()
}

// uint32ToIpv4Mask is simple utility function for conversion between IPv4Mask and uint32.
func uint32ToIpv4Mask(ip uint32) net.IPMask {
	return net.IPv4Mask(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// newIPNet is simple utility function to create defend copy of net.IPNet.
func newIPNet(ipNet net.IPNet) net.IPNet {
	return net.IPNet{
		IP:   newIP(ipNet.IP),
		Mask: net.IPv4Mask(ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3]),
	}
}

// newIP is simple utility function to create defend copy of net.IP.
func newIP(ip net.IP) net.IP {
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4()
}

type sortableUint32 []uint32

func (d sortableUint32) Len() int { return len(d) }

func (d sortableUint32) Less(i, j int) bool {
	return d[i] <= d[j]
}

func (d sortableUint32) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
