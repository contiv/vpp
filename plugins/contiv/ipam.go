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

package contiv

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
	logging.Logger
	sync.RWMutex

	hostID uint8 // identifier of host node for which this IPAM is created for

	// pods related variables
	podSubnetIPPrefix   net.IPNet        // IPv4 subnet from which individual pod networks are allocated, this is subnet for all pods across all host nodes
	podNetworkIPPrefix  net.IPNet        // IPv4 subnet prefix for all pods of one host node (given by hostID), podSubnetIPPrefix + hostID ==<computation>==> podNetworkIPPrefix
	podNetworkGatewayIP net.IP           // gateway IP address for pod network of one host node (given by hostID)
	assignedPodIPs      map[uintIP]podID // pool of assigned IP addresses

	// host related variables
	hostNetworkIPPrefix net.IPNet // IPv4 subnet used in one host (given by hostID) for vswitch-to-its-host connection
	vethVPPEndIP        net.IP    // for given host(given by hostID), it is the IPv4 address for virtual ethernet's VPP end point
	vethHostEndIP       net.IP    // for given host(given by hostID), it is the IPv4 address for virtual ethernet's host end point
}

type uintIP = uint32
type podID = string

// IPAMConfig is configuration for IPAM module
type IPAMConfig struct {
	PodSubnetCIDR        string // subnet used for all pods across all nodes
	PodNetworkPrefixLen  uint8  // prefix length of subnet used for all pods of 1 host node (pod network = pod subnet for one 1 host node)
	HostSubnetCIDR       string // subnet used in all hosts for vswitch-to-its-host connection
	HostNetworkPrefixLen uint8  // prefix length of subnet used for vswitch-to-its-host connection on 1 host node (host network = host subnet for one 1 host node)
}

// newIPAM returns new IPAM module to be used on the host.
func newIPAM(logger logging.Logger, hostID uint8, config *IPAMConfig) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		Logger: logger,
		hostID: hostID,
	}

	// computing IPAM struct variables from IPAM config
	if err := initializePodsIPAM(ipam, config, hostID); err != nil {
		return nil, err
	}
	if err := initializeHostIPAM(ipam, config, hostID); err != nil {
		return nil, err
	}
	logger.Infof("IPAM values loaded: %+v", ipam)

	return ipam, nil
}

// initializeHostIPAM initializes host related variables of IPAM
func initializeHostIPAM(ipam *IPAM, config *IPAMConfig, hostID uint8) (err error) {
	_, ipam.hostNetworkIPPrefix, err = convertConfigNotation(config.PodSubnetCIDR, config.PodNetworkPrefixLen, hostID)
	if err != nil {
		return
	}

	podNetworkPrefixUint32, err := ipv4ToUint32(ipam.hostNetworkIPPrefix.IP)
	if err != nil {
		return
	}
	ipam.vethVPPEndIP = uint32ToIpv4(podNetworkPrefixUint32 + vethVPPEndIPHostSeqID)
	ipam.vethHostEndIP = uint32ToIpv4(podNetworkPrefixUint32 + vethHostEndIPHostSeqID)

	return
}

// initializePodsIPAM initializes pod related variables of IPAM
func initializePodsIPAM(ipam *IPAM, config *IPAMConfig, hostID uint8) (err error) {
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
		Mask: uint32ToIpv4Mask((1 << uint(networkPrefixLen)) - 1),
	}
	return
}

// getVEthVPPEndIP provides (for host given to IPAM) the IPv4 address for virtual ethernet's VPP end point
func (i *IPAM) getVEthVPPEndIP() net.IP {
	i.RLock()
	defer i.RUnlock()
	return newIP(i.vethHostEndIP) // defensive copy
}

// getVEthHostEndIP provides (for host given to IPAM) the IPv4 address for virtual ethernet's host end point
func (i *IPAM) getVEthHostEndIP() net.IP {
	i.RLock()
	defer i.RUnlock()
	return newIP(i.vethHostEndIP) // defensive copy
}

func (i *IPAM) getHostNetwork() *net.IPNet {
	i.RLock()
	defer i.RUnlock()
	hostNetwork := newIPNet(i.hostNetworkIPPrefix) // defensive copy
	return &hostNetwork
}

// getPodSubnet returns pod subnet ("network_address/prefix_length") that is base subnet for all pods of all hosts.
func (i *IPAM) getPodSubnet() *net.IPNet {
	i.RLock()
	defer i.RUnlock()
	podSubnet := newIPNet(i.podSubnetIPPrefix) // defensive copy
	return &podSubnet
}

// getPodNetwork returns pod network for current host (given by hostID given at IPAM creation)
func (i *IPAM) getPodNetwork() *net.IPNet {
	i.RLock()
	defer i.RUnlock()
	podNetwork := newIPNet(i.podNetworkIPPrefix) // defensive copy
	return &podNetwork
}

// getPodGatewayIP returns gateway IP address for the pod network.
func (i *IPAM) getPodGatewayIP() net.IP {
	i.RLock()
	defer i.RUnlock()
	return newIP(i.podNetworkGatewayIP) // defensive copy
}

// getHostID returns unique host ID used to calculate the pod network CIDR.
func (i *IPAM) getHostID() uint8 {
	i.RLock()
	defer i.RUnlock()
	return i.hostID
}

// getNextPodIP returns next available pod IP address and remembers that this IP is meant to be used for pod with pod id <podID>
func (i *IPAM) getNextPodIP(podID string) (net.IP, error) {
	i.Lock()
	defer i.Unlock()

	// get network prefix as uint32
	networkPrefix, err := ipv4ToUint32(i.podNetworkIPPrefix.IP)
	if err != nil {
		return nil, err
	}

	// iterate over all possible IP addresses for pod network prefix
	// and take first not assigned IP
	prefixBits, totalBits := i.podNetworkIPPrefix.Mask.Size()
	maxAssignableIPs := 1 << uint(totalBits-prefixBits)
	for j := 0; j < maxAssignableIPs; j++ {
		if j == gatewayPodSeqID {
			continue // gateway IP address can't be assigned as pod
		}
		if _, found := i.assignedPodIPs[networkPrefix+uint32(j)]; found {
			continue // ignore already assigned IP addresses
		}
		i.assignedPodIPs[networkPrefix+uint32(j)] = podID
		//TODO set etcd for new assigned value

		ipForAssign := uint32ToIpv4(networkPrefix + uint32(j))
		i.Logger.Infof("Assigned new pod IP %s", ipForAssign)
		return ipForAssign, nil
	}

	return nil, fmt.Errorf("No IP address is free for assignment. All IP addresses for pod network %v are already assigned", i.podNetworkIPPrefix)
}

// releasePodIP releases the pod IP address remembered by pod ID string, so that it can be reused by the next pods.
func (i *IPAM) releasePodIP(podID string) error {
	i.Lock()
	defer i.Unlock()

	ip, err := i.findIP(podID)
	if err != nil {
		return fmt.Errorf("Can't release pod IP: %v", err)
	}
	delete(i.assignedPodIPs, ip)
	//TODO remove from etcd (if inside etcd)
	return nil
}

func (i *IPAM) findIP(podID string) (uintIP, error) {
	for ip, curPodID := range i.assignedPodIPs {
		if curPodID == podID {
			return ip, nil
		}
	}
	return 0, fmt.Errorf("Can't find assigned pod IP address for pod ID \"%v\"", podID)
}

// convertToHostIPPart converts hostID to part of IP address that distinguishes pod network IP address prefix among
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
	for bytePart := range ip {
		tmp = tmp<<8 + uint32(bytePart)
	}
	return tmp, nil
}

// uint32ToIpv4 is simple utility function for conversion between IPv4 and uint32
func uint32ToIpv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
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
	return net.IPv4(ip[0], ip[1], ip[2], ip[3])
}
