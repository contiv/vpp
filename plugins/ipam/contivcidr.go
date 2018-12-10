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
	"fmt"
	"math/big"
	"net"

	"github.com/go-errors/errors"

	"github.com/contiv/vpp/plugins/contivconf"
)

// dissectContivCIDR splits one big ContivCIDR into smaller disjoint subnets,
// each dedicated for a specific kind of endpoints (pods, nodes, vxlans...).
func dissectContivCIDR(ipamConfig *contivconf.IPAMConfig) (subnets *contivconf.CustomIPAMSubnets, err error) {
	contivCIDR := ipamConfig.ContivCIDR
	// check if subnet is big enough to apply IPAM for subnets
	maskSize, _ := contivCIDR.Mask.Size()
	if maskSize > 14 {
		return nil, errors.New("ContivCIDR is not valid, netmask size must be 14-bits or less")
	}

	// podSubnetCIDR has a requirement of minimum 65K pod ip addresses use /16 mask
	podPrefixLength := 16 - maskSize
	podSubnetCIDR, _ := subnet(contivCIDR, podPrefixLength, 0)
	podSubnetOneNodePrefixLen := uint8(25)

	// vppHostSubnetCIDR has a requirement of minimum 65K pod ip addresses use /16 mask
	vppHostSubnetCIDR, _ := subnet(contivCIDR, podPrefixLength, 1)
	vppHostSubnetOneNodePrefixLen := uint8(25)

	// use a /23 mask for the requirement of 500 nodes, same for vxlanCIDR
	nodePrefixLength := 23 - maskSize
	nodeInterconnectCIDR, _ := subnet(contivCIDR, nodePrefixLength, 256)
	vxlanCIDR, _ := subnet(contivCIDR, nodePrefixLength, 257)

	// podVPPSubnetCIDR uses a /25 network prefix length similar to vppHostSubnetOneNodePrefixLen
	podIfSubnetPrefixLength := 25 - maskSize
	podVPPSubnetCIDR, _ := subnet(contivCIDR, podIfSubnetPrefixLength, 1032)

	subnets = &contivconf.CustomIPAMSubnets{
		PodVPPSubnetCIDR:              podVPPSubnetCIDR,
		PodSubnetCIDR:                 podSubnetCIDR,
		PodSubnetOneNodePrefixLen:     podSubnetOneNodePrefixLen,
		VPPHostSubnetCIDR:             vppHostSubnetCIDR,
		VPPHostSubnetOneNodePrefixLen: vppHostSubnetOneNodePrefixLen,
		VxlanCIDR:                     vxlanCIDR,
		NodeInterconnectCIDR:          ipamConfig.NodeInterconnectCIDR,
	}

	if subnets.NodeInterconnectCIDR == nil && ipamConfig.NodeInterconnectDHCP == false {
		subnets.NodeInterconnectCIDR = nodeInterconnectCIDR
	}

	return subnets, nil
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
