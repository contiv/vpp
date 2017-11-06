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

// Package ipam is responsible for IP addresses management
package ipam

import (
	"fmt"
	"net"
	"sync"

	"github.com/ligato/cn-infra/logging"
)

const (
	gatewayPodSeqID        = 1
	vethVPPEndIPHostSeqID  = 1
	vethHostEndIPHostSeqID = 2
)

// IPAM represents the basic Contiv IPAM module.
type IPAM struct {
	logger logging.Logger
	mutex  sync.RWMutex

	hostID uint8 // identifier of host node for which this IPAM is created for

	// pods related variables
	podSubnetIPPrefix   net.IPNet        // IPv4 subnet from which individual pod networks are allocated, this is subnet for all pods across all host nodes
	podNetworkIPPrefix  net.IPNet        // IPv4 subnet prefix for all pods of one host node (given by hostID), podSubnetIPPrefix + hostID ==<computation>==> podNetworkIPPrefix
	podNetworkGatewayIP net.IP           // gateway IP address for pod network of one host node (given by hostID)
	assignedPodIPs      map[uintIP]podID // pool of assigned IP addresses

	// VSwitch related variables
	vSwitchNetworkIPPrefix net.IPNet // IPv4 subnet used in one host (given by hostID) for vswitch-to-its-host connection
	vethVPPEndIP           net.IP    // for given host(given by hostID), it is the IPv4 address for virtual ethernet's VPP end point
	vethHostEndIP          net.IP    // for given host(given by hostID), it is the IPv4 address for virtual ethernet's host end point

	// host node related variables
	hostNodeNetworkIPPrefix net.IPNet // IPv4 subnet used for all hosts node referencing IP addresses
}

type uintIP = uint32
type podID = string

// Config is configuration for IPAM module
type Config struct {
	PodSubnetCIDR           string // subnet used for all pods across all nodes
	PodNetworkPrefixLen     uint8  // prefix length of subnet used for all pods of 1 host node (pod network = pod subnet for one 1 host node)
	VSwitchSubnetCIDR       string // subnet used in each host for vswitch-to-its-host connection
	VSwitchNetworkPrefixLen uint8  // prefix length of subnet used for vswitch-to-its-host connection on 1 host node (VSwitch network = VSwitch subnet for one 1 host node)
	HostNodeSubnetCidr      string // subnet used for all hosts node referencing IP addresses
}

// New returns new IPAM module to be used on the host.
func New(logger logging.Logger, hostID uint8, config *Config) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		logger: logger,
		hostID: hostID,
	}

	// computing IPAM struct variables from IPAM config
	if err := initializePodsIPAM(ipam, config, hostID); err != nil {
		return nil, err
	}
	if err := initializeVSwitchIPAM(ipam, config, hostID); err != nil {
		return nil, err
	}
	if err := initializeHostNodeIPAM(ipam, config); err != nil {
		return nil, err
	}
	logger.Infof("IPAM values loaded: %+v", ipam)

	return ipam, nil
}

// initializeHostNodeIPAM initializes host nodes related variables of IPAM
func initializeHostNodeIPAM(ipam *IPAM, config *Config) error {
	_, pSubnet, err := net.ParseCIDR(config.HostNodeSubnetCidr)
	ipam.hostNodeNetworkIPPrefix = *pSubnet
	return err
}

// initializeVSwitchIPAM initializes VSwitch related variables of IPAM
func initializeVSwitchIPAM(ipam *IPAM, config *Config, hostID uint8) (err error) {
	_, ipam.vSwitchNetworkIPPrefix, err = convertConfigNotation(config.VSwitchSubnetCIDR, config.VSwitchNetworkPrefixLen, hostID)
	if err != nil {
		return
	}

	vSwitchNetworkPrefixUint32, err := ipv4ToUint32(ipam.vSwitchNetworkIPPrefix.IP)
	if err != nil {
		return
	}
	ipam.vethVPPEndIP = uint32ToIpv4(vSwitchNetworkPrefixUint32 + vethVPPEndIPHostSeqID)
	ipam.vethHostEndIP = uint32ToIpv4(vSwitchNetworkPrefixUint32 + vethHostEndIPHostSeqID)

	return
}

// initializePodsIPAM initializes pod related variables of IPAM
func initializePodsIPAM(ipam *IPAM, config *Config, hostID uint8) (err error) {
	ipam.podSubnetIPPrefix, ipam.podNetworkIPPrefix, err = convertConfigNotation(config.PodSubnetCIDR, config.PodNetworkPrefixLen, hostID)
	if err != nil {
		return
	}

	podNetworkPrefixUint32, err := ipv4ToUint32(ipam.podNetworkIPPrefix.IP)
	if err != nil {
		return
	}
	ipam.podNetworkGatewayIP = uint32ToIpv4(podNetworkPrefixUint32 + gatewayPodSeqID)
	ipam.assignedPodIPs = make(map[uintIP]podID) // TODO: load allocated IP addresses from ETCD (failover use case)
	return
}

// convertConfigNotation converts config notation and given host ID to IPAM structure notation.
// I.e: input 1.2.3.4/16 (string), /24 (uint8), 5 (uint8) results in 1.2.0.0/16 (IPNet), 1.2.5.0/24 (IPNet)
func convertConfigNotation(subnetCIDR string, networkPrefixLen uint8, hostID uint8) (subnetIPPrefix net.IPNet, networkIPPrefix net.IPNet, err error) {
	// convert subnetCIDR to net.IPNet
	_, pSubnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		err = fmt.Errorf("Can't parse SubnetCIDR \"%v\" : %v", subnetCIDR, err)
		return
	}
	subnetIPPrefix = *pSubnet

	// computing host part of IP address/network
	subnetPrefixLen, _ := subnetIPPrefix.Mask.Size()
	if networkPrefixLen <= uint8(subnetPrefixLen) {
		err = fmt.Errorf("Network prefix length (%v) must be higher than subnet prefix length (%v)", networkPrefixLen, subnetPrefixLen)
		return
	}
	hostPartBitSize := networkPrefixLen - uint8(subnetPrefixLen)
	hostIPPart := convertToHostIPPart(hostID, hostPartBitSize)

	// composing network IP prefix from previously computed parts
	subnetIPPartUint32, err := ipv4ToUint32(subnetIPPrefix.IP)
	if err != nil {
		return
	}
	networkPrefixUint32 := subnetIPPartUint32 + (uint32(hostIPPart) << (32 - networkPrefixLen))
	networkIPPrefix = net.IPNet{
		IP:   uint32ToIpv4(networkPrefixUint32),
		Mask: uint32ToIpv4Mask(((1 << uint(networkPrefixLen)) - 1) << (32 - networkPrefixLen)),
	}
	return
}

// HostIPAddress computes IP address of host node based on host id
func (i *IPAM) HostIPAddress(hostID uint8) (net.IP, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.computeHostIPAddress(hostID)
}

// HostIPNetwork computes host node network with IP address of host node based on provided host id
func (i *IPAM) HostIPNetwork(hostID uint8) (*net.IPNet, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	hostIP, err := i.computeHostIPAddress(hostID)
	if err != nil {
		return nil, err
	}
	maskSize, _ := i.hostNodeNetworkIPPrefix.Mask.Size()
	hostIPNetwork := net.IPNet{
		IP:   hostIP,
		Mask: uint32ToIpv4Mask(((1 << uint(maskSize)) - 1) << (32 - uint8(maskSize))),
	}
	return &hostIPNetwork, nil
}

// VEthVPPEndIP provides (for host given to IPAM) the IPv4 address for virtual ethernet's VPP end point
func (i *IPAM) VEthVPPEndIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.vethVPPEndIP) // defensive copy
}

// VEthHostEndIP provides (for host given to IPAM) the IPv4 address for virtual ethernet's host end point
func (i *IPAM) VEthHostEndIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.vethHostEndIP) // defensive copy
}

// VSwitchNetwork returns vswitch network used to connect vswitch to its host (given by hostID given at IPAM creation)
func (i *IPAM) VSwitchNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	vSwitchNetwork := newIPNet(i.vSwitchNetworkIPPrefix) // defensive copy
	return &vSwitchNetwork
}

// PodSubnet returns pod subnet ("network_address/prefix_length") that is base subnet for all pods of all hosts.
func (i *IPAM) PodSubnet() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podSubnet := newIPNet(i.podSubnetIPPrefix) // defensive copy
	return &podSubnet
}

// PodNetwork returns pod network for current host (given by hostID given at IPAM creation)
func (i *IPAM) PodNetwork() *net.IPNet {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	podNetwork := newIPNet(i.podNetworkIPPrefix) // defensive copy
	return &podNetwork
}

// PodGatewayIP returns gateway IP address for the pod network.
func (i *IPAM) PodGatewayIP() net.IP {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return newIP(i.podNetworkGatewayIP) // defensive copy
}

// HostID returns unique host ID used to calculate the pod network CIDR.
func (i *IPAM) HostID() uint8 {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.hostID
}

// NextPodIP returns next available pod IP address and remembers that this IP is meant to be used for pod with pod id <podID>
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
		if j == gatewayPodSeqID {
			continue // gateway IP address can't be assigned as pod
		}
		if _, found := i.assignedPodIPs[networkPrefix+uint32(j)]; found {
			continue // ignore already assigned IP addresses
		}
		i.assignedPodIPs[networkPrefix+uint32(j)] = podID
		//TODO set etcd for new assigned value

		ipForAssign := uint32ToIpv4(networkPrefix + uint32(j))
		i.logger.Infof("Assigned new pod IP %s", ipForAssign)
		return ipForAssign, nil
	}

	return nil, fmt.Errorf("No IP address is free for assignment. All IP addresses for pod network %v are already assigned", i.podNetworkIPPrefix)
}

// ReleasePodIP releases the pod IP address remembered by pod ID string, so that it can be reused by the next pods.
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
	return nil
}

// computeHostIPAddress computes IP address of host node based on host id
func (i *IPAM) computeHostIPAddress(hostID uint8) (net.IP, error) {
	// trimming hostID if its place in IP address is narrower than actual uint8 size
	subnetPrefixLen, _ := i.hostNodeNetworkIPPrefix.Mask.Size()
	hostPartBitSize := 32 - uint8(subnetPrefixLen)
	hostIPPart := convertToHostIPPart(hostID, hostPartBitSize)

	//combining it to get result IP address
	networkIPPartUint32, err := ipv4ToUint32(i.hostNodeNetworkIPPrefix.IP)
	if err != nil {
		return nil, err
	}
	return uint32ToIpv4(networkIPPartUint32 + uint32(hostIPPart)), nil
}

// findIP finds assignet IP address (in uint form) by pod id or returns error
func (i *IPAM) findIP(podID string) (uintIP, error) {
	for ip, curPodID := range i.assignedPodIPs {
		if curPodID == podID {
			return ip, nil
		}
	}
	return 0, fmt.Errorf("Can't find assigned pod IP address for pod ID \"%v\"", podID)
}

// convertToHostIPPart converts hostID to part of IP address that distinguishes network IP address prefix among
// different hosts. The result don't have to be that whole hostID, because in IP address there can be allocated
// less space than the size of hostID.
func convertToHostIPPart(hostID uint8, expectedHostPartBitSize uint8) uint8 {
	return hostID & ((1 << expectedHostPartBitSize) - 1) //TODO this is only trimming hostID to expected bit count, do we want to map hostID to some value from config?
}

// ipv4ToUint32 is simple utility function for conversion between IPv4 and uint32
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

// uint32ToIpv4 is simple utility function for conversion between IPv4 and uint32
func uint32ToIpv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4()
}

// uint32ToIpv4Mask is simple utility function for conversion between IPv4Mask and uint32
func uint32ToIpv4Mask(ip uint32) net.IPMask {
	return net.IPv4Mask(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// newIPNet is simple utility function to create defend copy of net.IPNet
func newIPNet(ipNet net.IPNet) net.IPNet {
	return net.IPNet{
		IP:   newIP(ipNet.IP),
		Mask: net.IPv4Mask(ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3]),
	}
}

// newIP is simple utility function to create defend copy of net.IP
func newIP(ip net.IP) net.IP {
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4()
}
