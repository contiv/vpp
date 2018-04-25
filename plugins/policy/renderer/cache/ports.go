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

package cache

import (
	"net"

	"fmt"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// Ports is a set of port numbers.
type Ports map[uint16]struct{}

// AnyPort is a constant that represents any port.
const AnyPort uint16 = 0

// NewPorts is a constructor for Ports.
func NewPorts(portNums ...uint16) Ports {
	ports := make(Ports)
	for _, portNum := range portNums {
		ports.Add(portNum)
	}
	return ports
}

// Add port number into the set
func (p Ports) Add(port uint16) {
	p[port] = struct{}{}
}

// Has returns true if the given port is in the set.
func (p Ports) Has(port uint16) bool {
	return p.HasExplicit(0) || p.HasExplicit(port)
}

// HasExplicit returns true if the given port is in the set regardless of AnyPort
// presence.
func (p Ports) HasExplicit(port uint16) bool {
	_, has := p[port]
	return has
}

// IsSubsetOf returns true if this set is a subset of <p2>.
func (p Ports) IsSubsetOf(p2 Ports) bool {
	if p2.Has(AnyPort) {
		return true
	}
	if p.Has(AnyPort) {
		return false
	}
	for port := range p {
		if !p2.Has(port) {
			return false
		}
	}
	return true
}

// Intersection returns the set of ports which are both in this set and in <p2>.
func (p Ports) Intersection(p2 Ports) Ports {
	if p.Has(AnyPort) {
		return p2
	}
	if p2.Has(AnyPort) {
		return p
	}
	intersection := NewPorts()
	for port := range p {
		if p2.Has(port) {
			intersection.Add(port)
		}
	}
	return intersection
}

// String converts Ports into a human-readable string
// representation.
func (p Ports) String() string {
	ports := "{"
	count := 0
	for port := range p {
		ports += fmt.Sprintf("%d", port)
		count++
		if count < len(p) {
			ports += ","
		}
	}
	ports += "}"
	return ports
}

// getAllowedEgressPorts returns allowed destination UDP and TCP ports for a given
// source pod IP wrt. egress rules.
func getAllowedEgressPorts(srcIP *net.IPNet, egress []*renderer.ContivRule) (tcp, udp Ports, any bool) {
	tcp = NewPorts()
	udp = NewPorts()
	hasDeny := false
	for _, rule := range egress {
		if rule.Action == renderer.ActionDeny {
			// This implementation assumes there is only the single default deny-all rule (for ANY protocol),
			// or no deny rule at all.
			hasDeny = true
			continue
		}
		if len(rule.SrcNetwork.IP) > 0 && !rule.SrcNetwork.Contains(srcIP.IP) {
			continue
		}
		/* matching ALLOW rule */
		switch rule.Protocol {
		case renderer.TCP:
			tcp.Add(rule.DestPort)
		case renderer.UDP:
			udp.Add(rule.DestPort)
		case renderer.ANY:
			tcp.Add(AnyPort)
			udp.Add(AnyPort)
			any = true
		}
	}
	if !hasDeny {
		return NewPorts(AnyPort), NewPorts(AnyPort), true
	}
	return tcp, udp, any
}

// getAllowedIngressPorts returns allowed destination UDP and TCP ports for a given
// destination pod IP wrt. ingress rules.
func getAllowedIngressPorts(dstIP *net.IPNet, ingress []*renderer.ContivRule) (tcp, udp Ports, any bool) {
	tcp = NewPorts()
	udp = NewPorts()
	hasDeny := false
	for _, rule := range ingress {
		if rule.Action == renderer.ActionDeny {
			// This implementation assumes there is only the single default deny-all rule (for ANY protocol),
			// or no deny rule at all.
			hasDeny = true
			continue
		}
		if len(rule.DestNetwork.IP) > 0 && !rule.DestNetwork.Contains(dstIP.IP) {
			continue
		}
		/* matching ALLOW rule */
		switch rule.Protocol {
		case renderer.TCP:
			tcp.Add(rule.DestPort)
		case renderer.UDP:
			udp.Add(rule.DestPort)
		case renderer.ANY:
			tcp.Add(AnyPort)
			udp.Add(AnyPort)
			any = true
		}
	}
	if !hasDeny {
		return NewPorts(AnyPort), NewPorts(AnyPort), true
	}
	return tcp, udp, any
}
