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
	"github.com/go-errors/errors"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/contiv/vpp/plugins/contivconf"
)

// dissectContivCIDR splits one big ContivCIDR into smaller disjoint subnets,
// each dedicated for a specific kind of endpoints (pods, nodes, vxlans...).
func dissectContivCIDR(ipamConfig *contivconf.IPAMConfig) (subnets *contivconf.CustomIPAMSubnets, err error) {
	contivCIDR := ipamConfig.ContivCIDR
	// check if subnet is big enough to apply IPAM for subnets
	maskSize, size := contivCIDR.Mask.Size()
	if size-maskSize < 18 {
		return nil, errors.New("ContivCIDR is not valid, network must provide at least 18bit space")
	}

	// podSubnetCIDR has a requirement of minimum 65K pod ip addresses use 16-bit space
	podPrefixLength := size - 16 - maskSize
	podSubnetCIDR, _ := cidr.Subnet(contivCIDR, podPrefixLength, 0)
	podSubnetOneNodePrefixLen := uint8(size - 7)

	// vppHostSubnetCIDR has a requirement of minimum 65K pod ip addresses use 16-bit space
	vppHostSubnetCIDR, _ := cidr.Subnet(contivCIDR, podPrefixLength, 1)
	vppHostSubnetOneNodePrefixLen := uint8(size - 7)

	// use a 9-bit space for the requirement of 500 nodes, same for vxlanCIDR
	nodePrefixLength := size - 9 - maskSize
	nodeInterconnectCIDR, _ := cidr.Subnet(contivCIDR, nodePrefixLength, 256)
	vxlanCIDR, _ := cidr.Subnet(contivCIDR, nodePrefixLength, 257)

	subnets = &contivconf.CustomIPAMSubnets{
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
