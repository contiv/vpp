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
	Render(pod podmodel.ID, podIP *net.IPNet /* one host subnet */, ingress []*ContivRule, egress []*ContivRule) Txn

	// Commit proceeds with the rendering. The changes are propagated into
	// the destination network stack.
	Commit() error
}

// ContivRule is an n-tuple with the most basic policy rule definition that the
// destination network stack must support.
type ContivRule struct {
	// ID uniquely identifies the rule within the list of ingress or egress
	// rules.
	ID string

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
	return fmt.Sprintf("Rule %s <%s %s[%s:%s] -> %s[%s:%s]>",
		cr.ID, cr.Action, srcNet, cr.Protocol, srcPort, dstNet, cr.Protocol, dstPort)
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

// ProtocolType is either TCP or UDP.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota

	// UDP protocol.
	UDP
)

// String converts ProtocolType into a human-readable string.
func (at ProtocolType) String() string {
	switch at {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	}
	return "INVALID"
}
