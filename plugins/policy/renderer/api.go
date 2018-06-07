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

package renderer

import (
	"fmt"
	"net"
	"strconv"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// PolicyRendererAPI defines the API of Policy Renderer.
// Policy Renderer implements rendering of Contiv rules for a specific network
// stack. How the rules are actually installed is up to the implementation.
// The interface is used to plug the renderer into the layer above,
// which is Policy Configurator.
type PolicyRendererAPI interface {
	// NewTxn starts a new transaction. The rendering should execute only after
	// Commit() is called. Ideally, the transaction should support rollback
	// to recover from an in-progress fail.
	// If <resync> is enabled, the supplied configuration should completely
	// replace the existing one. Otherwise, perform the changes incrementally,
	// i.e. pods not mentioned in the transaction should remain unaffected.
	NewTxn(resync bool) Txn
}

// Txn defines API of PolicyRenderer transaction.
type Txn interface {
	// Render applies the set of ingress & egress rules for a given pod.
	// The existing rules are replaced.
	// The traffic direction (ingress, egress) is considered from the vswitch
	// point of view!
	// For ingress rules the source IP is unset, i.e. 0.0.0.0/ (match all).
	// For egress rules the destination IP is unset, i.e. 0.0.0.0/ (match all).
	// The renderer may use the provided pod IP to make the rules fully specific
	// in case they are installed globally and not assigned to interfaces.
	// Empty set of rules should allow any traffic in that direction.
	// The flag *removed* is set to true if the pod was just removed - in such
	// case *podIP* may be nil and both list of rules are empty.
	Render(pod podmodel.ID, podIP *net.IPNet /* one host subnet */, ingress []*ContivRule, egress []*ContivRule, removed bool) Txn

	// Commit proceeds with the rendering. The changes are propagated into
	// the destination network stack.
	Commit() error
}

// ContivRule is an n-tuple with the most basic policy rule definition that the
// destination network stack must support.
type ContivRule struct {
	// Action to perform when traffic matches.
	Action ActionType

	// L3
	SrcNetwork  *net.IPNet // empty = match all
	DestNetwork *net.IPNet // empty = match all

	// L4
	Protocol ProtocolType
	SrcPort  uint16 // 0 = match all
	DestPort uint16 // 0 = match all
}

// String converts Contiv Rule (pointer) into a human-readable string
// representation.
func (cr *ContivRule) String() string {
	const any = "ANY"
	srcNet := any
	dstNet := any
	if len(cr.SrcNetwork.IP) > 0 {
		srcNet = cr.SrcNetwork.String()
	}
	if len(cr.DestNetwork.IP) > 0 {
		dstNet = cr.DestNetwork.String()
	}
	srcPort := any
	dstPort := any
	if cr.SrcPort != 0 {
		srcPort = strconv.Itoa(int(cr.SrcPort))
	}
	if cr.DestPort != 0 {
		dstPort = strconv.Itoa(int(cr.DestPort))
	}
	return fmt.Sprintf("Rule <%s %s[%s:%s] -> %s[%s:%s]>",
		cr.Action, srcNet, cr.Protocol, srcPort, dstNet, cr.Protocol, dstPort)
}

// Copy creates a deep copy of the Contiv rule.
func (cr *ContivRule) Copy() *ContivRule {
	crCopy := &ContivRule{}
	*(crCopy) = *cr
	return crCopy
}

// Compare returns -1, 0, 1 if this<cr2 or this==cr2 or this>cr2, respectively.
// Contiv rules have a total order defined on them.
// It holds that if cr matches subset of the traffic matched by cr2, then cr<cr2.
func (cr *ContivRule) Compare(cr2 *ContivRule) int {
	srcIPOrder := utils.CompareIPNets(cr.SrcNetwork, cr2.SrcNetwork)
	if srcIPOrder != 0 {
		return srcIPOrder
	}
	destIPOrder := utils.CompareIPNets(cr.DestNetwork, cr2.DestNetwork)
	if destIPOrder != 0 {
		return destIPOrder
	}
	protocolOrder := utils.CompareInts(int(cr.Protocol), int(cr2.Protocol))
	if protocolOrder != 0 {
		return protocolOrder
	}
	if cr.Protocol != ANY {
		srcPortOrder := utils.ComparePorts(cr.SrcPort, cr2.SrcPort)
		if srcPortOrder != 0 {
			return srcPortOrder
		}
		dstPortOrder := utils.ComparePorts(cr.DestPort, cr2.DestPort)
		if dstPortOrder != 0 {
			return dstPortOrder
		}
	}
	return utils.CompareInts(int(cr.Action), int(cr2.Action))
}

// ActionType is either DENY or PERMIT.
type ActionType int

const (
	// ActionDeny tells the policy engine to block the matching traffic.
	ActionDeny ActionType = iota

	// ActionPermit tells the policy engine to block the matching traffic.
	ActionPermit
)

// String converts ActionType into a human-readable string.
func (at ActionType) String() string {
	switch at {
	case ActionDeny:
		return "DENY"
	case ActionPermit:
		return "PERMIT"
	}
	return "INVALID"
}

// ProtocolType is either TCP or UDP or OTHER.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota

	// UDP protocol.
	UDP

	// OTHER is some NON-UDP, NON-TCP traffic (used ONLY in unit tests).
	OTHER

	// ANY L4 protocol or even pure L3 traffic (port numbers are ignored).
	ANY
)

// String converts ProtocolType into a human-readable string.
func (at ProtocolType) String() string {
	switch at {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case OTHER:
		return "OTHER"
	case ANY:
		return "ANY"
	}
	return "INVALID"
}
