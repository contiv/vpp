/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package natplugin

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/service/configurator"
)

// IdentityMappings represents a list of identity mappings.
type IdentityMappings struct {
	list []*IdentityMapping
}

// IdentityMapping represents a single identity mapping.
type IdentityMapping struct {
	IP       net.IP
	Port     uint16
	Protocol configurator.ProtocolType
}

// String converts a list of identity mappings into a human-readable string.
func (ims *IdentityMappings) String() string {
	mappings := ""
	for idx, mapping := range ims.list {
		mappings += mapping.String()
		if idx < len(ims.list)-1 {
			mappings += ", "
		}
	}
	return fmt.Sprintf("IdentityMappings [%s]", mappings)
}

// Count returns the number of mappings in the list.
func (ims *IdentityMappings) Count() int {
	return len(ims.list)
}

// Has returns true if the given mapping is already in the list.
func (ims *IdentityMappings) Has(im *IdentityMapping) bool {
	for _, mapping := range ims.list {
		if mapping.Equals(im) {
			return true
		}
	}
	return false
}

// Add adds new identity mapping into the list if it is not there yet.
func (ims *IdentityMappings) Add(im *IdentityMapping) bool {
	if ims.Has(im) {
		return false
	}
	ims.list = append(ims.list, im)
	return true
}

// Join adds all mappings from <ims2> into this list.
// Returns true if there were no duplicates.
func (ims *IdentityMappings) Join(ims2 *IdentityMappings) bool {
	allAdded := true
	for _, im2 := range ims2.list {
		if !ims.Add(im2) {
			allAdded = false
		}
	}
	return allAdded
}

// Subtract removes all mappings that are in <ims2> from this list.
// Returns true if ims2 is subset of ims.
func (ims *IdentityMappings) Subtract(ims2 *IdentityMappings) bool {
	allRemoved := true
	for _, im2 := range ims2.list {
		removed := false
		filtered := []*IdentityMapping{}
		for _, im := range ims.list {
			if im.Equals(im2) {
				removed = true
			} else {
				filtered = append(filtered, im)
			}
		}
		if !removed {
			allRemoved = false
		} else {
			ims.list = filtered
		}

	}
	return allRemoved
}

// String converts identity mapping into a human-readable string.
func (im *IdentityMapping) String() string {
	return fmt.Sprintf("IdentityMapping <IP:%s Port:%d Protocol:%s>",
		im.IP.String(), im.Port, im.Protocol.String())
}

// Equals compares this identity mapping with <im2>.
func (im *IdentityMapping) Equals(im2 *IdentityMapping) bool {
	return im.IP.Equal(im2.IP) && im.Port == im2.Port && im.Protocol == im2.Protocol
}
