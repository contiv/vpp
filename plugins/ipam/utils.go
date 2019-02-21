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
	"net"
)

// convertToNodeIPPart converts nodeID to part of IP address that distinguishes
// network IP address prefix among different nodes.
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

// newIPNet is simple utility function to create defend copy of net.IPNet.
func newIPNet(ipNet *net.IPNet) *net.IPNet {
	mask := make(net.IPMask, len(ipNet.Mask))
	copy(mask, ipNet.Mask)
	return &net.IPNet{
		IP:   newIP(ipNet.IP),
		Mask: mask,
	}
}

// newIP is simple utility function to create defend copy of net.IP.
func newIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
