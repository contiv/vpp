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
	"github.com/contiv/vpp/plugins/nodesync"
)

const (
	// sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)
	podGatewaySeqID = 1

	// sequence ID reserved for VPP-end of the VPP to host interconnect
	hostInterconnectInVPPIPSeqID   = 1

	// sequence ID reserved for host(Linux)-end of the VPP to host interconnect
	hostInterconnectInLinuxIPSeqID = 2

	// default subnet allocated for services
	defaultServiceCIDR = "10.96.0.0/12"
)

// IPAM plugin implements IP address allocation for Contiv.
type IPAM struct {
	mutex sync.RWMutex

	logger   logging.Logger
	nodeSync nodesync.API
	config   *Config // ipam configuration

	excludedIPsfromNodeSubnet []uint32 // IPs from the NodeInterconnect Subnet that should not be assigned

	// POD related variables
	podSubnetAllNodes  net.IPNet // IPv4 subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podSubnetThisNode  net.IPNet // IPv4 subnet prefix for all PODs on this node (given by nodeID), podSubnetAllNodes + nodeID ==<computation>==> podSubnetThisNode
	podSubnetGatewayIP net.IP    // gateway IP address for PODs on this node (given by nodeID)
	podVPPSubnet       net.IPNet // IPv4 subnet from which individual VPP-side POD interfaces networks are allocated, this is subnet for all PODS within this node.

	// maps to convert between Pod and the assigned IP
	assignedPodIPs    map[uintIP]podmodel.ID // pool of assigned POD IP addresses
	podToIP           map[podmodel.ID]net.IP // pod -> allocated IP address
	lastPodIPAssigned int                    // counter denoting last assigned pod IP address

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
}

type uintIP = uint32

/*
// ApplyIPAMConfig populates the Config struct with the calculated subnets
func (cfg *Config) ApplyIPAMConfig() error {

	// set default ContivCIDR if not defined by user
	if cfg.IPAMConfig.ContivCIDR == "" {
		return nil
	}

	// check if subnet is big enough to apply IPAM for subnets
	_, contivNetwork, _ := net.ParseCIDR(cfg.IPAMConfig.ContivCIDR)
	maskSize, _ := contivNetwork.Mask.Size()
	if maskSize > 14 {
		return fmt.Errorf("ContivCIDR is not valid, netmask size must be 14-bits or less")
	}

	// podSubnetCIDR has a requriement of minimum 65K pod ip addresses use /16 mask
	podPrefixLength := 16 - maskSize
	podSubnetCIDR, _ := subnet(contivNetwork, podPrefixLength, 0)
	podSubnetOneNodePrefixLen := uint8(25)

	// vppHostSubnetCIDR has a requriement of minimum 65K pod ip addresses use /16 mask
	vppHostSubnetCIDR, _ := subnet(contivNetwork, podPrefixLength, 1)
	vppHostSubnetOneNodePrefixLen := uint8(25)

	// use a /23 mask for the requirement of 500 nodes, same for vxlanCIDR
	nodePrefixLength := 23 - maskSize
	nodeInterconnectCIDR, _ := subnet(contivNetwork, nodePrefixLength, 256)
	vxlanCIDR, _ := subnet(contivNetwork, nodePrefixLength, 257)

	// podVPPSubnetCIDR uses a /25 network prefix length similar to vppHostSubnetOneNodePrefixLen
	podIfSubnetPrefixLength := 25 - maskSize
	podVPPSubnetCIDR, _ := subnet(contivNetwork, podIfSubnetPrefixLength, 1032)

	cfg.IPAMConfig = ipam.Config{
		PodVPPSubnetCIDR:              podVPPSubnetCIDR.String(),
		PodSubnetCIDR:                 podSubnetCIDR.String(),
		PodSubnetOneNodePrefixLen:     podSubnetOneNodePrefixLen,
		VPPHostSubnetCIDR:             vppHostSubnetCIDR.String(),
		VPPHostSubnetOneNodePrefixLen: vppHostSubnetOneNodePrefixLen,
		VxlanCIDR:                     vxlanCIDR.String(),
		NodeInterconnectCIDR:          cfg.IPAMConfig.NodeInterconnectCIDR,
		NodeInterconnectDHCP:          cfg.IPAMConfig.NodeInterconnectDHCP,
		ContivCIDR:                    cfg.IPAMConfig.ContivCIDR,
	}

	if cfg.IPAMConfig.NodeInterconnectCIDR == "" && cfg.IPAMConfig.NodeInterconnectDHCP == false {
		cfg.IPAMConfig.NodeInterconnectCIDR = nodeInterconnectCIDR.String()
	}

	return nil
}


// subnet takes a CIDR range and creates a subnet from it
// base: parent CIDR range
// newBits: number of additional prefix bits
// num: given network number.
//
// Example: 10.1.0.0/16, with additional 8 bits and a network number of 5
// result = 10.1.5.0/24
func subnet(base *net.IPNet, newBits int, num int) (*net.IPNet, error) {
	ip := base.IP
	mask := base.Mask

	baseLength, addressLength := mask.Size()
	newPrefixLen := baseLength + newBits

	// check if there is sufficient address space to extend the network prefix
	if newPrefixLen > addressLength {
		return nil, fmt.Errorf("not enought space to extend prefix of %d by %d", baseLength, newBits)
	}

	// calculate the maximum network number
	maxNetNum := uint64(1<<uint64(newBits)) - 1
	if uint64(num) > maxNetNum {
		return nil, fmt.Errorf("prefix extension of %d does not accommodate a subnet numbered %d", newBits, num)
	}

	return &net.IPNet{
		IP:   insertNetworkNumIntoIP(ip, num, newPrefixLen),
		Mask: net.CIDRMask(newPrefixLen, addressLength),
	}, nil
}

// ipToInt is simple utility function for conversion between IPv4/IPv6 and int.
func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32
	} else if len(ip) == net.IPv6len {
		return val, 128
	} else {
		return nil, 0
	}
}

// intToIP is simple utility function for conversion between int and IPv4/IPv6.
func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	val := make([]byte, bits/8)

	// big.Int.Bytes() removes front zero padding.
	// IP bytes packed at the end of the return array,
	for i := 1; i <= len(ipBytes); i++ {
		val[len(val)-i] = ipBytes[len(ipBytes)-i]
	}

	return net.IP(val)
}

func insertNetworkNumIntoIP(ip net.IP, num int, prefixLen int) net.IP {
	ipInt, totalBits := ipToInt(ip)
	bigNum := big.NewInt(int64(num))
	bigNum.Lsh(bigNum, uint(totalBits-prefixLen))
	ipInt.Or(ipInt, bigNum)

	return intToIP(ipInt, totalBits)
}

func (n *IPv4Net) excludedIPsFromNodeCIDR() []net.IP {
	if n.config == nil {
		return nil
	}
	var excludedIPs []string
	for _, oneNodeConfig := range n.config.NodeConfig {
		if oneNodeConfig.Gateway == "" {
			continue
		}
		excludedIPs = appendIfMissing(excludedIPs, oneNodeConfig.Gateway)
	}
	var res []net.IP
	for _, ip := range excludedIPs {
		res = append(res, net.ParseIP(ip))
	}
	return res
}


 */

// New returns new IPAM module to be used on the node specified by the nodeID.
func New(logger logging.Logger, nodeSync nodesync.API, config *Config, nodeInterconnectExcludedIPs []net.IP) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		logger:   logger,
		nodeSync: nodeSync,
		config:   config,
	}

	excludedIPs, err := sortIPv4SliceToUint32(nodeInterconnectExcludedIPs)
	if err != nil {
		return nil, err
	}
	ipam.excludedIPsfromNodeSubnet = excludedIPs
	if excludedIPs != nil {
		logger.Info("Following IPs are excluded from NodeCIDR: ", nodeInterconnectExcludedIPs)
	}

	return ipam, nil
}

// Resync resynchronizes IPAM against Kubernetes state data.
// A set of already allocated pod IPs is updated.
func (i *IPAM) Resync(kubeStateData controller.KubeStateData) (err error) {
	nodeID := i.nodeSync.GetNodeID()

	// initialize subnets based on the configuration
	if err := i.initializePods(i.config, nodeID); err != nil {
		return err
	}
	if err := i.initializeVPPHost(i.config, nodeID); err != nil {
		return err
	}
	if err := i.initializeNodeInterconnect(i.config); err != nil {
		return err
	}
	if err := i.initializePodVPPSubnet(i.config); err != nil {
		return err
	}

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

// initializePodsIPAM initializes POD-related variables.
func (i *IPAM) initializePods(config *Config, nodeID uint32) (err error) {
	i.podSubnetAllNodes, i.podSubnetThisNode, err = convertConfigNotation(config.PodSubnetCIDR, config.PodSubnetOneNodePrefixLen, nodeID)
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
func (i *IPAM) initializeVPPHost(config *Config, nodeID uint32) (err error) {
	i.hostInterconnectSubnetAllNodes, i.hostInterconnectSubnetThisNode, err = convertConfigNotation(config.VPPHostSubnetCIDR, config.VPPHostSubnetOneNodePrefixLen, nodeID)
	if err != nil {
		return
	}

	vSwitchNetworkPrefixUint32, err := ipv4ToUint32(i.hostInterconnectSubnetThisNode.IP)
	if err != nil {
		return
	}
	i.hostInterconnectIPInVpp = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInVPPIPSeqID)
	i.hostInterconnectIPInLinux = uint32ToIpv4(vSwitchNetworkPrefixUint32 + hostInterconnectInLinuxIPSeqID)

	if config.ServiceCIDR == "" {
		config.ServiceCIDR = defaultServiceCIDR
	}
	_, serviceSubnet, err := net.ParseCIDR(config.ServiceCIDR)
	if err != nil {
		return
	}
	i.serviceCIDR = *serviceSubnet

	return
}

// initializeNodeInterconnect initializes node interconnect-related variables.
func (i *IPAM) initializeNodeInterconnect(config *Config) (err error) {
	if config == nil || (config.NodeInterconnectCIDR == "" && config.NodeInterconnectDHCP == false) || config.VxlanCIDR == "" {
		return fmt.Errorf("missing NodeInterconnectCIDR or NodeInterconnectDHCP or VxlanCIDR configuration")
	}

	i.nodeInterconnectDHCP = config.NodeInterconnectDHCP

	if !i.nodeInterconnectDHCP {
		_, nodeSubnet, err := net.ParseCIDR(config.NodeInterconnectCIDR)
		if err != nil {
			return err
		}
		i.nodeInterconnectSubnet = *nodeSubnet
	}

	_, vxlanSubnet, err := net.ParseCIDR(config.VxlanCIDR)
	if err != nil {
		return
	}
	i.vxlanSubnet = *vxlanSubnet
	return
}

// initializePodVPPSubnet initializes node vpp-side POD interface-related variables.
func (i *IPAM) initializePodVPPSubnet(config *Config) (err error) {
	if config == nil || config.PodVPPSubnetCIDR == "" {
		return fmt.Errorf("missing PodVPPSubnetCIDR configuration")
	}

	_, podVPPSubnet, err := net.ParseCIDR(config.PodVPPSubnetCIDR)
	if err != nil {
		return
	}
	i.podVPPSubnet = *podVPPSubnet
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
