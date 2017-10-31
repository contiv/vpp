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
	gatewayPodSeqID = 1
)

// IPAM represents the basic Contiv IPAM module.
type IPAM struct {
	logging.Logger
	sync.RWMutex

	hostID                uint8           // identifier of host node for which this IPAM is created for
	podNetworkIPPrefix    net.IPNet       // IPv4 subnet prefix for all pods of one host node (given by hostID)
	allHostsPodSubnetMask net.IPMask      // mask for subnet for all pods across all host nodes
	podNetworkGatewayIP   net.IP          // gateway IP address for pod network of one host node (given by hostID)
	assignedIPs           map[uint32]bool // pool of assigned IP addresses
}

// IPAMConfig is configuration for IPAM module
type IPAMConfig struct {
	PodSubnetCIDR       string // subnet used for all pods across all nodes
	PodNetworkPrefixLen uint8  // prefix length of subnet used for all pods of 1 host node (pod network = pod subnet for one 1 host node)
}

// newIPAM returns new IPAM module to be used on the host.
func newIPAM(logger logging.Logger, hostID uint8, config *IPAMConfig) (*IPAM, error) {
	// create basic IPAM
	ipam := &IPAM{
		Logger: logger,
		hostID: hostID,
	}

	// computing IPAM struct variables from IPAM config
	_, podSubnet, err := net.ParseCIDR(config.PodSubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("Can't parse PodSubnetCIDR \"%v\" : %v", config.PodSubnetCIDR, err)
	}
	podSubnetPrefix, err := ipv4ToUint32(podSubnet.IP)
	if err != nil {
		return nil, err
	}
	podSubnetPrefixLen, _ := podSubnet.Mask.Size()
	if config.PodNetworkPrefixLen <= uint8(podSubnetPrefixLen) {
		return nil, fmt.Errorf("Pod network prefix length (%v) must be higher than pod subnet prefix length (%v)", config.PodNetworkPrefixLen, podSubnetPrefixLen)
	}
	hostPartBitSize := config.PodNetworkPrefixLen - uint8(podSubnetPrefixLen)
	hostIPPart := convertToHostIPPart(hostID, hostPartBitSize)
	podNetworkPrefixUint32 := podSubnetPrefix + (uint32(hostIPPart) << (32 - config.PodNetworkPrefixLen))

	ipam.podNetworkIPPrefix = net.IPNet{
		IP:   uint32ToIpv4(podNetworkPrefixUint32),
		Mask: uint32ToIpv4Mask((1 << uint(config.PodNetworkPrefixLen)) - 1),
	}
	ipam.allHostsPodSubnetMask = uint32ToIpv4Mask((1 << uint(podSubnetPrefixLen)) - 1)
	ipam.podNetworkGatewayIP = uint32ToIpv4(podNetworkPrefixUint32 + gatewayPodSeqID)
	ipam.assignedIPs = make(map[uint32]bool) // TODO: load allocated IP addresses from ETCD (failover use case)

	logger.Infof("IPAM values loaded: %+v", ipam)

	return ipam, nil
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

// getNextPodIP returns next available pod IP address.
func (i *IPAM) getNextPodIP() (net.IP, error) {
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
		if _, found := i.assignedIPs[networkPrefix+uint32(j)]; found {
			continue // ignore already assigned IP addresses
		}
		i.assignedIPs[networkPrefix+uint32(j)] = true
		//TODO set etcd for new assigned value

		ipForAssign := uint32ToIpv4(networkPrefix + uint32(j))
		i.Logger.Infof("Assigned new pod IP %s", ipForAssign)
		return ipForAssign, nil
	}

	return nil, fmt.Errorf("No IP address is free for assignment. All IP addresses for pod network %v are already assigned", i.podNetworkIPPrefix)
}

//TODO use releasePodIP func to proper release pod IP addresses
// releasePodIP releases the pod IP address, so that it can be reused by the next pods.
func (i *IPAM) releasePodIP(ip net.IP) error {
	i.Lock()
	defer i.Unlock()

	ipUint32, err := ipv4ToUint32(ip)
	if err != nil {
		return fmt.Errorf("Can't release pod IP: %v", err)
	}
	delete(i.assignedIPs, ipUint32)
	//TODO remove from etcd (if inside etcd)
	return nil
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
