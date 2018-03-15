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

// StaticMappings represents a list of static mappings.
type StaticMappings struct {
	list []*StaticMapping
}

// StaticMapping represents a single static mapping.
type StaticMapping struct {
	ExternalIP   net.IP
	ExternalPort uint16
	Protocol     configurator.ProtocolType
	Locals       []*Local
}

// Local represents a single backend for VPP NAT mapping.
type Local struct {
	IP          net.IP
	Port        uint16
	Probability uint8
}

// String converts a list of static mappings into a human-readable string.
func (sms *StaticMappings) String() string {
	mappings := ""
	for idx, mapping := range sms.list {
		mappings += mapping.String()
		if idx < len(sms.list)-1 {
			mappings += ", "
		}
	}
	return fmt.Sprintf("StaticMappings [%s]", mappings)
}

// Count returns the number of mappings in the list.
func (sms *StaticMappings) Count() int {
	return len(sms.list)
}

// Has returns true if the given mapping is already in the list.
func (sms *StaticMappings) Has(sm *StaticMapping) bool {
	for _, mapping := range sms.list {
		if mapping.Equals(sm) {
			return true
		}
	}
	return false
}

// Add adds new static mapping into the list if it is not there yet.
func (sms *StaticMappings) Add(sm *StaticMapping) bool {
	if sms.Has(sm) {
		return false
	}
	sms.list = append(sms.list, sm)
	return true
}

// Join adds all mappings from <sms2> into this list.
// Returns true if there were no duplicates.
func (sms *StaticMappings) Join(sms2 *StaticMappings) bool {
	allAdded := true
	for _, sm2 := range sms2.list {
		if !sms.Add(sm2) {
			allAdded = false
		}
	}
	return allAdded
}

// Subtract removes all mappings that are in <sms2> from this list.
// Returns true if sms2 is subset of sms.
func (sms *StaticMappings) Subtract(sms2 *StaticMappings) bool {
	allRemoved := true
	for _, sm2 := range sms2.list {
		removed := false
		filtered := []*StaticMapping{}
		for _, sm := range sms.list {
			if sm.Equals(sm2) {
				removed = true
			} else {
				filtered = append(filtered, sm)
			}
		}
		if !removed {
			allRemoved = false
		} else {
			sms.list = filtered
		}

	}
	return allRemoved
}

// String converts static mapping into a human-readable string.
func (sm *StaticMapping) String() string {
	locals := ""
	for idx, local := range sm.Locals {
		locals += local.String()
		if idx < len(sm.Locals)-1 {
			locals += ", "
		}
	}
	return fmt.Sprintf("StaticMapping <ExternalIP:%s ExternalPort:%d Protocol:%s, Locals:[%s]>",
		sm.ExternalIP.String(), sm.ExternalPort, sm.Protocol.String(), locals)
}

// String converts local into a human-readable string.
func (l *Local) String() string {
	return fmt.Sprintf("Local <IP:%s Port:%d Probability:%d>",
		l.IP.String(), l.Port, l.Probability)
}

// Equals compares this static mapping with <sm2>.
func (sm *StaticMapping) Equals(sm2 *StaticMapping) bool {
	if !sm.ExternalIP.Equal(sm2.ExternalIP) ||
		sm.ExternalPort != sm2.ExternalPort ||
		sm.Protocol != sm2.Protocol {
		return false
	}
	if len(sm.Locals) != len(sm2.Locals) {
		return false
	}
	for _, local := range sm.Locals {
		found := false
		for _, local2 := range sm2.Locals {
			if local.IP.Equal(local2.IP) && local.Port == local2.Port && local.Probability == local2.Probability {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
