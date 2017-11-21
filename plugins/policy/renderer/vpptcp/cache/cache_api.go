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

package cache

import (
	"bytes"
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// SessionRuleCacheAPI defines API of a cache used to store VPP Session rules.
// The cache allows renderer to easily calculate the minimal set of changes
// that need to be applied in a given transaction.
// The cache furthermore converts the Contiv's own per-interface ingress/egress
// rules into the equivalent VPP Session rules distributed among the global table
// and per-namespace local tables.
type SessionRuleCacheAPI interface {
	// NewTxn starts a new transaction. The changes are reflected in the cache
	// only after Commit() is called.
	// If <resync> is enabled, the supplied configuration will completely
	// replace the existing one, otherwise namespaces not mentioned
	// in the transaction are left unchanged.
	NewTxn(resync bool) Txn

	// LookupByNamespace returns Contiv rules assigned to a given namespace.
	LookupByNamespace(nsIndex uint32) (ingress, egress []*renderer.ContivRule)

	// AllNamespaces returns the set of indexes of all known VPP session
	// namespaces (already updated configuration).
	AllNamespaces() []uint32
}

// Txn defines API of SessionRuleCache transaction.
type Txn interface {
	// Update changes the list of Contiv rules for a given session namespace.
	// The change is applied into the cache during the commit.
	// Run Changes() before Commit() to learn the set of pending updates (merged
	// to a minimal diff).
	Update(nsIndex uint32, ipAddr *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule)

	// Changes calculates a minimalistic set of changes, represented as Session
	// rules, prepared in the transaction up to this point.
	// Must be run before Commit().
	Changes() (added, removed []*SessionRule, err error)

	// Commit applies the changes into the underlying cache.
	Commit()
}

// SessionRule defines and groups the fields of a VPP session rule.
type SessionRule struct {
	TransportProto uint8
	IsIP4          uint8
	LclIP          [16]byte
	LclPlen        uint8
	RmtIP          [16]byte
	RmtPlen        uint8
	LclPort        uint16
	RmtPort        uint16
	ActionIndex    uint32
	AppnsIndex     uint32
	Scope          uint8
	Tag            [64]byte
}

const (
	// RuleScopeGlobal is a constant used to set the global scope for a session rule.
	RuleScopeGlobal = 1

	// RuleScopeLocal is a constant used to set the local scope for a session rule.
	RuleScopeLocal = 2

	// RuleScopeBoth is a constant used to set both the local and the global scope
	// for a session rule.
	RuleScopeBoth = 3

	// RuleActionDoNothing is a constant used to set DO-NOTHING action for a session
	// rule.
	RuleActionDoNothing = ^uint32(0)

	// RuleActionDeny is a constant used to set DENY action for a session rule.
	RuleActionDeny = ^uint32(0) - 1

	// RuleActionAllow is a constant used to set ALLOW action for a session rule.
	RuleActionAllow = ^uint32(0) - 2

	// RuleProtoTCP is a constant used to set TCP protocol for a session rule.
	RuleProtoTCP = 0

	// RuleProtoUDP is a constant used to set UDP protocol for a session rule.
	RuleProtoUDP = 1
)

// String converts Session Rule into a human-readable string representation.
func (sr *SessionRule) String() string {
	var scope string
	var action string
	var l4Proto string

	switch sr.Scope {
	case 0:
		scope = "global"
	case RuleScopeGlobal:
		scope = "global"
	case RuleScopeLocal:
		scope = "local"
	case RuleScopeBoth:
		scope = "both"
	default:
		scope = "invalid"
	}

	switch sr.ActionIndex {
	case RuleActionDoNothing:
		action = "do-nothing"
	case RuleActionAllow:
		action = "allow"
	case RuleActionDeny:
		action = "deny"
	default:
		action = fmt.Sprintf("fwd->%d", sr.ActionIndex)
	}

	ipBits := net.IPv4len * 8
	if sr.IsIP4 == 0 {
		ipBits = net.IPv6len * 8
	}

	lcl := &net.IPNet{}
	lcl.IP = make([]byte, ipBits/8)
	copy(lcl.IP, sr.LclIP[:])
	lcl.Mask = net.CIDRMask(int(sr.LclPlen), ipBits)

	rmt := &net.IPNet{}
	rmt.IP = make([]byte, ipBits/8)
	copy(rmt.IP, sr.RmtIP[:])
	rmt.Mask = net.CIDRMask(int(sr.RmtPlen), ipBits)

	switch sr.TransportProto {
	case RuleProtoTCP:
		l4Proto = "TCP"
	case RuleProtoUDP:
		l4Proto = "UDP"
	default:
		l4Proto = "invalid"
	}

	tagLen := bytes.IndexByte(sr.Tag[:], 0)
	tag := string(sr.Tag[:tagLen])

	return fmt.Sprintf("Rule <ns:%d scope:%s action:%s lcl:%s[%s:%d] rmt:%s:[%s:%d] tag:%s>",
		sr.AppnsIndex, scope, action, lcl.String(), l4Proto, sr.LclPort, rmt.String(), l4Proto,
		sr.RmtPort, tag)
}

// Compare returns -1, 0, 1 if this<sr2 or this==sr2 or this>sr2, respectively.
// Session rules have a total order defined on them.
func (sr *SessionRule) Compare(sr2 *SessionRule, compareTag bool) int {
	nsOrder := utils.CompareInts(int(sr.AppnsIndex), int(sr2.AppnsIndex))
	if nsOrder != 0 {
		return nsOrder
	}
	scopeOrder := utils.CompareInts(int(sr.Scope), int(sr2.Scope))
	if scopeOrder != 0 {
		return scopeOrder
	}
	actionOrder := utils.CompareInts(int(sr.ActionIndex), int(sr2.ActionIndex))
	if actionOrder != 0 {
		return actionOrder
	}
	ipVerOrder := utils.CompareInts(int(sr.IsIP4), int(sr2.IsIP4))
	if ipVerOrder != 0 {
		return ipVerOrder
	}
	lclOrder := utils.CompareIPNetsBytes(sr.LclPlen, sr.LclIP, sr2.LclPlen, sr2.LclIP)
	if lclOrder != 0 {
		return lclOrder
	}
	rmtOrder := utils.CompareIPNetsBytes(sr.RmtPlen, sr.RmtIP, sr2.RmtPlen, sr2.RmtIP)
	if rmtOrder != 0 {
		return rmtOrder
	}
	protocolOrder := utils.CompareInts(int(sr.TransportProto), int(sr2.TransportProto))
	if protocolOrder != 0 {
		return protocolOrder
	}
	lclPortOrder := utils.CompareInts(int(sr.LclPort), int(sr2.LclPort))
	if lclPortOrder != 0 {
		return lclPortOrder
	}
	rmtPortOrder := utils.CompareInts(int(sr.RmtPort), int(sr2.RmtPort))
	if rmtPortOrder != 0 {
		return rmtPortOrder
	}
	if compareTag {
		return bytes.Compare(sr.Tag[:], sr2.Tag[:])
	}
	return 0
}

// Copy creates a deep copy of the Session rule.
func (sr *SessionRule) Copy() *SessionRule {
	srCopy := &SessionRule{}
	*(srCopy) = *sr
	return srCopy
}
