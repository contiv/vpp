/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
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

package configurator

import (
	"fmt"
	"net"
	"strconv"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// PolicyConfiguratorAPI defines the API of Policy Configurator.
// For a given pod, the configurator translates a set of Contiv Policies into
// ingress and egress lists of Contiv Rules (n-tuples with the most basic policy
// rule definition) and applies them into the target vswitch via registered
// renderers. Allows to register multiple renderers for different network stacks.
// For the best performance, creates a shortest possible sequence of rules
// that implement a given policy.
// For the sake of renderers that install rules into per-interface tables
// (as opposed to one or more global tables), the configurator ensures that the
// same set of policies always results in the same list of rules, allowing
// renderers to group and share them across multiple interfaces (if supported
// by the destination network stack)
type PolicyConfiguratorAPI interface {
	// RegisterRenderer registers a new renderer.
	// The renderer will be receiving rules for all pods in this K8s node.
	// It is up to the render to possibly filter out rules for pods without
	// an inter-connection in the destination network stack.
	RegisterRenderer(renderer renderer.PolicyRendererAPI) error

	// NewTxn starts a new transaction. The re-configuration executes only
	// after Commit() is called.
	// If <resync> is enabled, the supplied configuration will completely
	// replace the existing one, otherwise pods not mentioned in the transaction
	// are left unchanged.
	NewTxn(resync bool) Txn
}

// Txn defines the API of PolicyConfigurator transaction.
type Txn interface {
	// Configure applies the set of policies for a given pod.
	// The existing policies are replaced.
	// The order of policies is not important (it is a set).
	Configure(pod podmodel.ID, policies []*ContivPolicy) Txn

	// Commit proceeds with the reconfiguration.
	Commit() error
}

// ContivPolicy is a less-abstract, free of indirect references representation
// of K8s Network Policy.
// It has:
//   - expanded namespaces
//   - translated port names
//   - evaluated label selectors
//   - IP network addresses converted to net.IP
// It is produced in this form and passed to Configurator by Policy Processor.
// Traffic matched by a Contiv policy should by ALLOWED. Traffic not matched
// by any policy from a **non-empty** set of policies assigned
// to the source/destination pod should be DENIED.
type ContivPolicy struct {
	// ID should uniquely identify policy across all namespaces.
	ID policymodel.ID

	// Type selects the rule types that the network policy relates to.
	Type PolicyType

	// Matches is an array of Match-es: predicates that select a subset of the
	// traffic to be ALLOWED.
	Matches []Match
}

// String converts ContivPolicy into a human-readable string.
func (cp ContivPolicy) String() string {
	matches := ""
	for idx, match := range cp.Matches {
		matches += match.String()
		if idx < len(cp.Matches)-1 {
			matches += ", "
		}
	}
	return fmt.Sprintf("ContivPolicy %s <Type:%s, Matches:[%s]>",
		cp.ID, cp.Type, matches)
}

// Match is a predicate that select a subset of the traffic.
type Match struct {
	// Type selects the direction of the traffic.
	Type MatchType

	// Layer 3: destinations (egress) / sources (ingress)
	// If both arrays are nils, then this predicate matches all
	// sources(ingress) / destinations(egress). Otherwise, this predicate
	// applies to a given traffic only if the traffic matches at least one item
	// in one of the lists.
	Pods     []podmodel.ID
	IPBlocks []IPBlock

	// Layer 4: destination ports
	// If the array is empty or nil, then this predicate matches all ports
	// (traffic not restricted by port).
	// If the array is non-empty, then this applies to a given traffic only
	// if the traffic matches at least one port in the list.
	Ports []Port
}

// String converts Match into a human-readable string.
func (m Match) String() string {
	pods := "<nil>"
	if m.Pods != nil {
		pods = "["
		for idx, pod := range m.Pods {
			pods += pod.String()
			if idx < len(m.Pods)-1 {
				pods += ", "
			}
		}
		pods += "]"
	}

	blocks := "<nil>"
	if m.IPBlocks != nil {
		blocks = "["
		for idx, block := range m.IPBlocks {
			blocks += block.String()
			if idx < len(m.IPBlocks)-1 {
				blocks += ", "
			}
		}
		blocks += "]"
	}

	ports := "<nil>"
	if m.Ports != nil {
		ports = "["
		for idx, port := range m.Ports {
			ports += port.String()
			if idx < len(m.Ports)-1 {
				ports += ", "
			}
		}
		ports += "]"
	}
	return fmt.Sprintf("<Type:%s, Pods:%s, Blocks:%s, Ports:%s>",
		m.Type, pods, blocks, ports)
}

// PolicyType selects the rule types that the network policy relates to.
type PolicyType int

const (

	// PolicyIngress tells policy to apply to ingress only.
	PolicyIngress = iota

	// PolicyEgress tells policy to apply to egress only.
	PolicyEgress

	// PolicyAll tells policy to apply to both traffic directions.
	PolicyAll
)

// String converts PolicyType into a human-readable string.
func (pt PolicyType) String() string {
	switch pt {
	case PolicyIngress:
		return "INGRESS"
	case PolicyEgress:
		return "EGRESS"
	case PolicyAll:
		return "ALL"
	}
	return "INVALID"
}

// MatchType selects the direction of the traffic to apply a Match to.
// The direction is from the Pod point of view!
type MatchType int

const (
	// MatchIngress matches ingress traffic.
	MatchIngress MatchType = iota

	// MatchEgress matches egress traffic.
	MatchEgress
)

// String converts MatchType into a human-readable string.
func (mt MatchType) String() string {
	switch mt {
	case MatchIngress:
		return "INGRESS"
	case MatchEgress:
		return "EGRESS"
	}
	return "INVALID"
}

// ProtocolType is either TCP or UDP.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota

	// UDP protocol.
	UDP
)

// String converts ProtocolType into a human-readable string.
func (pt ProtocolType) String() string {
	switch pt {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	}
	return "INVALID"
}

// Port represent a TCP or UDP port.
// Number=0 represents all ports for a given protocol.
type Port struct {
	Protocol ProtocolType
	Number   uint16
}

// String return a human-readable string representation of the Port.
func (port Port) String() string {
	if port.Number == 0 {
		return port.Protocol.String() + ":ANY"
	}
	return port.Protocol.String() + ":" + strconv.Itoa(int(port.Number))
}

// IPBlock selects a particular CIDR with possible exceptions.
type IPBlock struct {
	Network net.IPNet
	Except  []net.IPNet
}

// String return a human-readable string representation of the IP Block.
func (ipb IPBlock) String() string {
	excepts := ""
	for idx, except := range ipb.Except {
		excepts += except.String()
		if idx < len(ipb.Except)-1 {
			excepts += ", "
		}
	}
	return fmt.Sprintf("<Net:%s, Except:[%s]>",
		ipb.Network, excepts)

}
