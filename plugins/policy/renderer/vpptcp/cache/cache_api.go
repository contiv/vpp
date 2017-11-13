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
)

// SessionRuleCacheAPI defines API of a cache used to store VPP Session rules.
// The cache allows renderer to easily calculate the minimal set of changes
// that need to be applied in a given transaction.
type SessionRuleCacheAPI interface {
	// NewTxn starts a new transaction. The changes are reflected in the cache
	// only after Commit() is called.
	// If <resync> is enabled, the supplied configuration will completely
	// replace the existing one, otherwise namespaces not mentioned
	// in the transaction are left unchanged.
	NewTxn(resync bool) Txn

	// LookupByNamespace returns rules assigned to a given namespace.
	LookupByNamespace(nsIndex int) (ingress, egress SessionRuleList)

	// AllNamespaces returns set of indexes of all known VPP session namespaces
	// (already updated configuration).
	AllNamespaces() []int
}

// Txn defines API of SessionRuleCache transaction.
type Txn interface {
	// Update changes the list of rules for a given session namespace.
	// The change is applied into the cache during commit.
	// Run Changes() before Commit() to learn the set of pending updates (merged
	// to minimal diff).
	Update(nsIndex int, ingress SessionRuleList, egress SessionRuleList)

	// Changes calculates a minimalistic set of changes prepared in the
	// transaction up to this point.
	// Must be run before Commit().
	Changes() (added, removed []*SessionRule)

	// Commit applies the changes into the underlying cache.
	Commit()
}

// SessionRule defines and groups the fields of a VPP session rule.
type SessionRule struct {
	TransportProto uint8
	IsIP4          uint8
	LclIP          []byte
	LclPlen        uint8
	RmtIP          []byte
	RmtPlen        uint8
	LclPort        uint16
	RmtPort        uint16
	ActionIndex    uint32
	AppnsIndex     uint32
	Scope          uint8
	Tag            []byte
}

// SessionRuleList is an ordered array of Session rules.
// API:
//  Insert(rule)
//  Diff(ruleList) -> (added, removed []*SessionRule)
// Use NewSessionRuleList(capacity) to initialize a new list.
type SessionRuleList []*SessionRule

// String converts Session Rule into a human-readable string representation.
func (sr *SessionRule) String() string {
	var scope string
	var action string

	switch sr.Scope {
	case 0:
		scope = "global"
	case 1:
		scope = "global"
	case 2:
		scope = "local"
	case 3:
		scope = "both"
	default:
		scope = "invalid"
	}

	switch sr.ActionIndex {
	case ^uint32(0):
		action = "allow"
	case ^uint32(0) - 1:
		action = "deny"
	default:
		action = fmt.Sprintf("fwd->%d", sr.ActionIndex)
	}

	ipBits := net.IPv4len * 8
	if sr.IsIP4 == 0 {
		ipBits = net.IPv6len * 8
	}

	lcl := &net.IPNet{}
	lcl.IP = sr.LclIP
	lcl.Mask = net.CIDRMask(int(sr.LclPlen), ipBits)

	rmt := &net.IPNet{}
	rmt.IP = sr.RmtIP
	rmt.Mask = net.CIDRMask(int(sr.RmtPlen), ipBits)

	l4Proto := "TCP"
	if sr.TransportProto == 1 {
		l4Proto = "UDP"
	}

	tagLen := bytes.IndexByte(sr.Tag, 0)
	tag := string(sr.Tag[:tagLen])

	return fmt.Sprintf("Rule <ns:%d scope:%s action:%s lcl:%s[%s:%d] rmt:%s:[%s:%d] tag:%s>",
		sr.AppnsIndex, scope, action, lcl.String(), l4Proto, sr.LclPort, rmt.String(), l4Proto,
		sr.RmtPort, tag)
}
