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
	"sort"

	"github.com/ligato/cn-infra/logging"
)

// SessionRuleCache implements SessionRuleCacheAPI.
type SessionRuleCache struct {
	Deps

	config   map[uint32]NamespaceConfig // namespace index -> namespace config
	dumpClbk func() (SessionRuleList, error)
}

// Deps lists dependencies of SessionRuleCache.
type Deps struct {
	Log logging.Logger
}

// SessionRuleCacheTxn represents a single transaction of SessionRuleCache.
type SessionRuleCacheTxn struct {
	cache  *SessionRuleCache
	resync bool

	// lists with changes from the transaction
	config map[uint32]NamespaceConfig
}

// NamespaceConfig stores both ingress and egress rules associated with a VPP
// session namespace.
type NamespaceConfig struct {
	ingress SessionRuleList
	egress  SessionRuleList
}

// NewSessionRuleList is a constructor for SessionRuleList.
func NewSessionRuleList(capacity int, rules ...*SessionRule) SessionRuleList {
	var list SessionRuleList
	if capacity > 0 {
		list = make(SessionRuleList, 0, capacity)
	} else {
		list = make(SessionRuleList, 0, len(rules))
	}
	for _, rule := range rules {
		list = list.Insert(rule)
	}
	return list
}

// Init initializes the SessionRule Cache.
// <dumpClbk> is a callback that the cache will use to dump currently
// installed session rules in VPP.
func (src *SessionRuleCache) Init(dumpClbk func() (SessionRuleList, error)) error {
	src.config = make(map[uint32]NamespaceConfig)
	src.dumpClbk = dumpClbk
	return nil
}

// NewTxn starts a new transaction. The changes are reflected in the cache
// only after Commit() is called.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one, otherwise namespaces not mentioned
// in the transaction are left unchanged.
func (src *SessionRuleCache) NewTxn(resync bool) Txn {
	return &SessionRuleCacheTxn{
		cache:  src,
		resync: resync,
		config: make(map[uint32]NamespaceConfig),
	}
}

// LookupByNamespace returns rules assigned to a given namespace.
func (src *SessionRuleCache) LookupByNamespace(nsIndex uint32) (ingress, egress SessionRuleList) {
	nsConfig, exists := src.config[nsIndex]
	if !exists {
		return nil, nil
	}
	return nsConfig.ingress, nsConfig.egress
}

// AllNamespaces returns set of indexes of all known VPP session namespaces
// (already updated configuration).
func (src *SessionRuleCache) AllNamespaces() (namespaces []uint32) {
	for nsIndex := range src.config {
		namespaces = append(namespaces, nsIndex)
	}
	return namespaces
}

// Update changes the list of rules for a given session namespace.
// The change is applied into the cache during commit.
// Run Changes() before Commit() to learn the set of pending updates (merged
// to minimal diff).
func (srct *SessionRuleCacheTxn) Update(nsIndex uint32, ingress SessionRuleList, egress SessionRuleList) {
	srct.cache.Log.WithFields(logging.Fields{
		"nsIndex": nsIndex,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("SessionRuleCacheTxn Update()")
	srct.config[nsIndex] = NamespaceConfig{ingress: ingress, egress: egress}
}

// Changes calculates a minimalistic set of changes prepared in the
// transaction up to this point.
// Must be run before Commit().
func (srct *SessionRuleCacheTxn) Changes() (added, removed []*SessionRule, err error) {
	if srct.resync {
		// Handle RESYNC
		// Put all rules to be configured into one big list.
		newRulesLen := 0
		for _, nsConfig := range srct.config {
			newRulesLen += len(nsConfig.ingress) + len(nsConfig.egress)
		}
		newRules := NewSessionRuleList(newRulesLen)
		for _, nsConfig := range srct.config {
			newRules = newRules.Insert(nsConfig.ingress...)
			newRules = newRules.Insert(nsConfig.egress...)
		}
		// Get the list of rules currently installed in VPP.
		currentRules, err := srct.cache.dumpClbk()
		if err != nil {
			return nil, nil, err
		}
		srct.cache.Log.WithFields(logging.Fields{
			"currentRules": currentRules,
			"newRules":     newRules,
		}).Debug("RESYNC rules Diff")
		// Compare.
		added, removed = newRules.Diff(currentRules)
	} else {
		// Handle Config change.
		for nsIndex := range srct.config {
			oldConfig, hasOldConfig := srct.cache.config[nsIndex]
			if hasOldConfig {
				nsInAdded, nsInRemoved := srct.config[nsIndex].ingress.Diff(oldConfig.ingress)
				nsEgAdded, nsEgRemoved := srct.config[nsIndex].egress.Diff(oldConfig.egress)
				added = append(added, nsInAdded...)
				added = append(added, nsEgAdded...)
				removed = append(removed, nsInRemoved...)
				removed = append(removed, nsEgRemoved...)
			} else {
				added = append(added, srct.config[nsIndex].ingress...)
				added = append(added, srct.config[nsIndex].egress...)
			}
		}
	}

	srct.cache.Log.WithFields(logging.Fields{
		"added":   added,
		"removed": removed,
	}).Debug("SessionRuleCacheTxn Changes()")
	return added, removed, nil
}

// Commit applies the changes into the underlying cache.
func (srct *SessionRuleCacheTxn) Commit() {
	if srct.resync == true {
		srct.cache.config = srct.config
	} else {
		for nsIndex, nsConfig := range srct.config {
			srct.cache.config[nsIndex] = nsConfig
		}
	}
}

func (srl SessionRuleList) lookupIdxByRule(rule *SessionRule) int {
	return sort.Search(len(srl),
		func(i int) bool {
			return rule.Compare(srl[i]) <= 0
		})
}

// Insert SessionRule(s) into the list.
func (srl SessionRuleList) Insert(rules ...*SessionRule) SessionRuleList {
	newSrl := srl
	for _, rule := range rules {
		newSrl = newSrl.insert(rule)
	}
	return newSrl
}

func (srl SessionRuleList) insert(rule *SessionRule) SessionRuleList {
	newSrl := srl
	// Insert the rule at the right index to keep the order
	idx := srl.lookupIdxByRule(rule)
	if idx < len(srl) &&
		rule.Compare(srl[idx]) == 0 {
		/* already added */
		return newSrl
	}
	/* just increase the size by one */
	newSrl = append(srl, nil)
	if idx < len(srl) {
		copy(newSrl[idx+1:], newSrl[idx:])
	}
	newSrl[idx] = rule
	return newSrl
}

// Diff returns the difference between this list and <srl2>.
// Added/Removed is from this list point of view.
func (srl SessionRuleList) Diff(srl2 SessionRuleList) (added, removed []*SessionRule) {
	added = []*SessionRule{}
	removed = []*SessionRule{}
	idx1 := 0
	idx2 := 0
	for idx1 < len(srl) && idx2 < len(srl2) {
		if idx1 < len(srl) {
			if idx2 < len(srl2) {
				order := srl[idx1].Compare(srl2[idx2])
				switch order {
				case 0:
					idx1++
					idx2++
				case -1:
					added = append(added, srl[idx1])
					idx1++
				case 1:
					removed = append(removed, srl2[idx2])
					idx2++
				}
			} else {
				added = append(added, srl[idx1])
				idx1++
			}
		} else {
			removed = append(removed, srl2[idx2])
			idx2++
		}
	}
	return added, removed
}

// compareInts is a comparison function for two integers.
func compareInts(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// compareIPNets returns an integer comparing two IP network addresses
// lexicographically.
func compareIPNets(aPrefixLen uint8, aIP [16]byte, bPrefixLen uint8, bIP [16]byte) int {
	prefixOrder := compareInts(int(aPrefixLen), int(bPrefixLen))
	if prefixOrder != 0 {
		return prefixOrder
	}
	return bytes.Compare(aIP[:], bIP[:])
}

// compareSessionRules returns an integer comparing two Session rules lexicographically.
func compareSessionRules(a, b *SessionRule) int {
	nsOrder := compareInts(int(a.AppnsIndex), int(b.AppnsIndex))
	if nsOrder != 0 {
		return nsOrder
	}
	scopeOrder := compareInts(int(a.Scope), int(b.Scope))
	if scopeOrder != 0 {
		return scopeOrder
	}
	actionOrder := compareInts(int(a.ActionIndex), int(b.ActionIndex))
	if actionOrder != 0 {
		return actionOrder
	}
	ipVerOrder := compareInts(int(a.IsIP4), int(b.IsIP4))
	if ipVerOrder != 0 {
		return ipVerOrder
	}
	lclOrder := compareIPNets(a.LclPlen, a.LclIP, b.LclPlen, b.LclIP)
	if lclOrder != 0 {
		return lclOrder
	}
	rmtOrder := compareIPNets(a.RmtPlen, a.RmtIP, b.RmtPlen, b.RmtIP)
	if rmtOrder != 0 {
		return rmtOrder
	}
	protocolOrder := compareInts(int(a.TransportProto), int(b.TransportProto))
	if protocolOrder != 0 {
		return protocolOrder
	}
	lclPortOrder := compareInts(int(a.LclPort), int(b.LclPort))
	if lclPortOrder != 0 {
		return lclPortOrder
	}
	rmtPortOrder := compareInts(int(a.RmtPort), int(b.RmtPort))
	if rmtPortOrder != 0 {
		return rmtPortOrder
	}
	return bytes.Compare(a.Tag[:], b.Tag[:])
}
