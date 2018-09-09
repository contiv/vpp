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
//

package utils

import (
	"strings"
	"regexp"
	"fmt"
	"strconv"
)

// MaskLength2Mask will tank in an int and return the bit mask for the number given
func MaskLength2Mask(ml int) uint32 {
	var mask uint32
	for i := 0; i < 32-ml; i++ {
		mask = mask << 1
		mask++
	}
	return mask
}

// Ipv4ToUint32 converts an ipv4 address in form '1.2.3.4' to an uint32
// representation of the address.
func Ipv4ToUint32(ipv4Address string) (uint32, error) {
	var ipu uint32

	ipv4Address = strings.Trim(ipv4Address, " ")

	re, _ := regexp.Match(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`,
		[]byte(ipv4Address))

	if !re {
		return 0, fmt.Errorf("invalid IP address %s", ipv4Address)
	}

	parts := strings.Split(ipv4Address, ".")
	for _, p := range parts {
		num, _ := strconv.Atoi(p)
		ipu = (ipu << 8) + uint32(num)
	}

	return ipu, nil
}

// Ipv4CidrToAddressAndMask converts an ipv4 CIDR address in form '1.2.3.4/12' to
// corresponding uint32 representations of the address and the mask
func Ipv4CidrToAddressAndMask(ip string) (uint32, uint32, error) {
	addressParts := strings.Split(ip, "/")
	if len(addressParts) != 2 {
		return 0, 0, fmt.Errorf("invalid address format)")
	}

	maskLen, err := strconv.Atoi(addressParts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid mask")
	}

	address, err := Ipv4ToUint32(addressParts[0])
	if err != nil {
		return 0, 0, err
	}
	mask := MaskLength2Mask(maskLen)

	return address, mask, nil
}