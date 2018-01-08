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
	"sync"

	"github.com/ligato/cn-infra/logging"
)

const (
	podGatewaySeqID    = 1 // sequence ID reserved for the gateway in POD IP subnet (cannot be assigned to any POD)
	vethVPPEndIPSeqID  = 1 // sequence ID reserved for VPP-end of the VPP to host interconnect
	vethHostEndIPSeqID = 2 // sequence ID reserved for host-end of the VPP to host interconnect
)

// IPAM represents the basic Contiv IPAM module.
type IPAM struct {
	logger logging.Logger
	mutex  sync.RWMutex

	nodeID uint8 // identifier of the node for which this IPAM is created for

	// POD related variables
	podSubnetIPPrefix   net.IPNet        // IPv4 subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	podNetworkIPPrefix  net.IPNet        // IPv4 subnet prefix for all PODs on the node (given by nodeID), podSubnetIPPrefix + nodeID ==<computation>==> podNetworkIPPrefix
	podNetworkGatewayIP net.IP           // gateway IP address for PODs on the node (given by nodeID)
	assignedPodIPs      map[uintIP]podID // pool of assigned POD IP addresses

	// VSwitch related variables
	vppHostSubnetIPPrefix  net.IPNet // IPv4 subnet used across all nodes for VPP to host Linux stack interconnect
	vppHostNetworkIPPrefix net.IPNet // IPv4 subnet used by the node (given by nodeID) for VPP to host Linux stack interconnect, vppHostSubnetIPPrefix + nodeID ==<computation>==> vppHostNetworkIPPrefix
	vethVPPEndIP           net.IP    // IPv4 address for virtual ethernet's VPP-end on given node
	vethHostEndIP          net.IP    // IPv4 address for virtual ethernet's host-end on given node

	// node related variables
	nodeInterconnectCIDR net.IPNet // IPv4 subnet used for for inter-node connections
}

type uintIP = uint32
type podID = string

// Config represents configuration of the IPAM module.
type Config struct {
	PodSubnetCIDR           string // subnet from which individual POD networks are allocated, this is subnet for all PODs across all nodes
	PodNetworkPrefixLen     uint8  // prefix length of subnet used for all PODs within 1 node (pod network = pod subnet for one 1 node)
	VPPHostSubnetCIDR       string // subnet used across all nodes for VPP to host Linux stack interconnect
	VPPHostNetworkPrefixLen uint8  // prefix length of subnet used for for VPP to host Linux stack interconnect within 1 node (VPPHost network = VPPHost subnet for one 1 node)
	NodeInterconnectCIDR    string // subnet used for for inter-node connections
}

// New returns new IPAM module to be used on the node specified by the nodeID.
func New(logger logging.Logger, nodeID uint8, config *Config) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		logger: logger,
		nodeID: nodeID,
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
	logger.Infof("IPAM values loaded: %+v", ipam)

	return ipam, nil
}

// NodeIPAddress computes IP address of the node based on the provided node ID.
func (i *IPAM) NodeIPAddress(nodeID uint8) (net.IP, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.computeNodeIPAddress(nodeID)
}

// NodeIPNetwork computes node network address based on the provided node ID.
func (i *IPAM) NodeIPNetwork(nodeID uint8) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	hostIP, err := i.computeNodeIPAddress(nodeID)
	if err != nil {
		return nil, err
	}
	maskSize, _ := i.nodeInterconnectCIDR.Mask.Size()
	hostIPNetwork := net.IPNet{
		IP:   hostIP,
		Mask: uint32ToIpv4Mask(((1 << uint(maskSize)) - 1) << (32 - uint8(maskSize))),
	}
	return &hostIPNetwork, nil
}

// VEthVPPEndIP provides the IPv4 address of the VPP-end of the VPP to host interconnect veth pair.
func (i *IPAM) VEthVPPEndIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.vethVPPEndIP) // defensive copy
}

// VEthHostEndIP provides the IPv4 address of the host-end of the VPP to host interconnect veth pair.
func (i *IPAM) VEthHostEndIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.vethHostEndIP) // defensive copy
}

// VPPHostNetwork returns vswitch network used to connect VPP to its host Linux Stack.
func (i *IPAM) VPPHostNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	vSwitchNetwork := newIPNet(i.vppHostNetworkIPPrefix) // defensive copy
	return &vSwitchNetwork
}

// OtherNodeVPPHostNetwork returns VPP-host network of another node identified by nodeID.
func (i *IPAM) OtherNodeVPPHostNetwork(nodeID uint8) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	networkSize, _ := i.vppHostNetworkIPPrefix.Mask.Size()
	vSwitchNetworkIPPrefix, err := applyNodeID(i.vppHostSubnetIPPrefix, nodeID, uint8(networkSize))
	if err != nil {
		return nil, err
	}
	vSwitchNetwork := newIPNet(vSwitchNetworkIPPrefix) // defensive copy
	return &vSwitchNetwork, nil
}

// PodSubnet returns POD subnet ("network_address/prefix_length") that is a base subnet for all PODs of all nodes.
func (i *IPAM) PodSubnet() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podSubnet := newIPNet(i.podSubnetIPPrefix) // defensive copy
	return &podSubnet
}

// PodNetwork returns POD network for the current node (given by nodeID given at IPAM creation).
func (i *IPAM) PodNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podNetwork := newIPNet(i.podNetworkIPPrefix) // defensive copy
	return &podNetwork
}

// OtherNodePodNetwork returns the POD network of another node identified by nodeID.
func (i *IPAM) OtherNodePodNetwork(nodeID uint8) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	networkSize, _ := i.podNetworkIPPrefix.Mask.Size()
	podNetworkIPPrefix, err := applyNodeID(i.podSubnetIPPrefix, nodeID, uint8(networkSize))
	if err != nil {
		return nil, err
	}
	podNetwork := newIPNet(podNetworkIPPrefix) // defensive copy
	return &podNetwork, nil
}

// PodGatewayIP returns gateway IP address of the POD network of this node.
func (i *IPAM) PodGatewayIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.podNetworkGatewayIP) // defensive copy
}

// NodeID returns unique host ID used to calculate the IP addresses.
func (i *IPAM) NodeID() uint8 {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.nodeID
}

// NextPodIP returns next available POD IP address and remembers that this IP is meant to be used for the POD with the id <podID>.
func (i *IPAM) NextPodIP(podID string) (net.IP, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if len(podID) == 0 { // zero byte length <=> zero character size
		return nil, fmt.Errorf("Pod ID can't be empty because it is used to release the assigned IP address")
	}

	// get network prefix as uint32
	networkPrefix, err := ipv4ToUint32(i.podNetworkIPPrefix.IP)
	if err != nil {
		return nil, err
	}

	// iterate over all possible IP addresses for pod network prefix
	// and take first not assigned IP
	prefixBits, totalBits := i.podNetworkIPPrefix.Mask.Size()
	maxSeqID := 1 << uint(totalBits-prefixBits) //max IP addresses in network range
	for j := 1; j < maxSeqID; j++ {             // zero ending IP is reserved for network => skip seqID=0
		if j == podGatewaySeqID {
			continue // gateway IP address can't be assigned as pod
		}
		if _, found := i.assignedPodIPs[networkPrefix+uint32(j)]; found {
			continue // ignore already assigned IP addresses
		}
		i.assignedPodIPs[networkPrefix+uint32(j)] = podID
		//TODO set etcd for new assigned value

		ipForAssign := uint32ToIpv4(networkPrefix + uint32(j))
		i.logger.Infof("Assigned new pod IP %s", ipForAssign)
		i.logAssignedPodIPPool()
		return ipForAssign, nil
	}

	return nil, fmt.Errorf("No IP address is free for assignment. All IP addresses for pod network %v are already assigned", i.podNetworkIPPrefix)
}

// ReleasePodIP releases the pod IP address remembered for POD id string, so that it can be reused by the next PODs.
func (i *IPAM) ReleasePodIP(podID string) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if len(podID) == 0 {
		i.logger.Warn("Ignoring pod IP releasing for pod ID that is empty string (possible echoes from restart?)")
		return nil
	}

	ip, err := i.findIP(podID)
	if err != nil {
		return fmt.Errorf("Can't release pod IP: %v", err)
	}
	delete(i.assignedPodIPs, ip)
	//TODO remove from etcd (if inside etcd)

	i.logger.Infof("Released IP %v for pod ID %v", uint32ToIpv4(ip), podID)
	i.logAssignedPodIPPool()
	return nil
}

// initializePodsIPAM initializes POD -related variables of IPAM.
func initializePodsIPAM(ipam *IPAM, config *Config, nodeID uint8) (err error) {
	ipam.podSubnetIPPrefix, ipam.podNetworkIPPrefix, err = convertConfigNotation(config.PodSubnetCIDR, config.PodNetworkPrefixLen, nodeID)
	if err != nil {
		return
	}

	podNetworkPrefixUint32, err := ipv4ToUint32(ipam.podNetworkIPPrefix.IP)
	if err != nil {
		return
	}
	ipam.podNetworkGatewayIP = uint32ToIpv4(podNetworkPrefixUint32 + podGatewaySeqID)
	ipam.assignedPodIPs = make(map[uintIP]podID) // TODO: load allocated IP addresses from ETCD (failover use case)
	return
}

// initializeVPPHostIPAM initializes VPP-host interconnect -related variables of IPAM.
func initializeVPPHostIPAM(ipam *IPAM, config *Config, nodeID uint8) (err error) {
	ipam.vppHostSubnetIPPrefix, ipam.vppHostNetworkIPPrefix, err = convertConfigNotation(config.VPPHostSubnetCIDR, config.VPPHostNetworkPrefixLen, nodeID)
	if err != nil {
		return
	}

	vSwitchNetworkPrefixUint32, err := ipv4ToUint32(ipam.vppHostNetworkIPPrefix.IP)
	if err != nil {
		return
	}
	ipam.vethVPPEndIP = uint32ToIpv4(vSwitchNetworkPrefixUint32 + vethVPPEndIPSeqID)
	ipam.vethHostEndIP = uint32ToIpv4(vSwitchNetworkPrefixUint32 + vethHostEndIPSeqID)

	return
}

// initializeNodeInterconnectIPAM initializes node interconnect -related variables of IPAM.
func initializeNodeInterconnectIPAM(ipam *IPAM, config *Config) (err error) {
	_, pSubnet, err := net.ParseCIDR(config.NodeInterconnectCIDR)
	if err != nil {
		return
	}
	ipam.nodeInterconnectCIDR = *pSubnet
	return
}

// convertConfigNotation converts config notation and given node ID to IPAM structure notation.
// I.e: input 1.2.3.4/16 (string), /24 (uint8), 5 (uint8) results in 1.2.0.0/16 (IPNet), 1.2.5.0/24 (IPNet)
func convertConfigNotation(subnetCIDR string, networkPrefixLen uint8, nodeID uint8) (subnetIPPrefix net.IPNet, networkIPPrefix net.IPNet, err error) {
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
func applyNodeID(subnetIPPrefix net.IPNet, nodeID uint8, networkPrefixLen uint8) (networkIPPrefix net.IPNet, err error) {
	// compute part of IP address representing host
	subnetPrefixLen, _ := subnetIPPrefix.Mask.Size()
	nodePartBitSize := networkPrefixLen - uint8(subnetPrefixLen)
	nodeIPPart := convertToNodeIPPart(nodeID, nodePartBitSize)

	// composing network IP prefix from previously computed parts
	subnetIPPartUint32, err := ipv4ToUint32(subnetIPPrefix.IP)
	if err != nil {
		return
	}
	networkPrefixUint32 := subnetIPPartUint32 + (uint32(nodeIPPart) << (32 - networkPrefixLen))
	networkIPPrefix = net.IPNet{
		IP:   uint32ToIpv4(networkPrefixUint32),
		Mask: uint32ToIpv4Mask(((1 << uint(networkPrefixLen)) - 1) << (32 - networkPrefixLen)),
	}
	return
}

// logAssignedPodIPPool logs assigned POD IPs.
func (i *IPAM) logAssignedPodIPPool() {
	if i.logger.GetLevel() <= logging.DebugLevel { // log only if debug level or more verbose
		var buffer bytes.Buffer
		for uintIP, podID := range i.assignedPodIPs {
			buffer.WriteString(" # " + uint32ToIpv4(uintIP).String() + ":" + podID)
		}
		i.logger.Debugf("Actual pool of assigned pod IP addresses: %v", buffer.String())
	}

}

// computeNodeIPAddress computes IP address of node based on the given node ID.
func (i *IPAM) computeNodeIPAddress(nodeID uint8) (net.IP, error) {
	// trimming nodeID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.nodeInterconnectCIDR.Mask.Size()
	nodePartBitSize := 32 - uint8(subnetPrefixLen)
	nodeIPPart := convertToNodeIPPart(nodeID, nodePartBitSize)

	//combining it to get result IP address
	networkIPPartUint32, err := ipv4ToUint32(i.nodeInterconnectCIDR.IP)
	if err != nil {
		return nil, err
	}
	return uint32ToIpv4(networkIPPartUint32 + uint32(nodeIPPart)), nil
}

// findIP finds assigned IP address (in uint form) for given POD id or returns an error if no entry is found.
func (i *IPAM) findIP(podID string) (uintIP, error) {
	for ip, curPodID := range i.assignedPodIPs {
		if curPodID == podID {
			return ip, nil
		}
	}
	return 0, fmt.Errorf("Can't find assigned pod IP address for pod ID \"%v\"", podID)
}

// convertToNodeIPPart converts nodeID to part of IP address that distinguishes network IP address prefix among
// different nodes. The result doesn't have to be that whole nodeID, because in IP address there can be allocated
// less space than the size of the nodeID.
func convertToNodeIPPart(nodeID uint8, expectedNodePartBitSize uint8) uint8 {
	return nodeID & ((1 << expectedNodePartBitSize) - 1) //TODO this is only trimming nodeID to expected bit count, do we want to map nodeID to some value from config?
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
