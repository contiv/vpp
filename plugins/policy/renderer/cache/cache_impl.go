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
	"net"
	"sort"

	"strconv"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
)

// ContivRuleCache implements ContivRuleCacheAPI.
type ContivRuleCache struct {
	Deps

	ingress *ContivRuleLists
	egress  *ContivRuleLists

	interfaces InterfaceSet

	lastListID uint64
}

// Deps lists dependencies of ContivRuleCache.
type Deps struct {
	Log logging.Logger
}

// ContivRuleCacheTxn represents a single transaction of ContivRuleCache.
type ContivRuleCacheTxn struct {
	cache  *ContivRuleCache
	resync bool

	// lists with changes from the transaction
	ingress *ContivRuleLists
	egress  *ContivRuleLists

	interfaces InterfaceSet
}

// ContivRuleLists is an ordered list of Contiv Rule lists with efficient lookups
// (all logarithmic).
//
// API:
//  Insert(ruleList)
//  Remove(ruleList)
//  RemoveByIdx(idx)
//  RemoveByPredicate(func(ruleList) -> bool)
//  LookupByID(ID) -> ruleList
//  LookupByRules() -> ruleList
//  LookupByInterface(ifName) -> ruleList
//  AssignInterface(ruleList, ifName)
//  UnassignInterface(ruleList/nil, ifName)
type ContivRuleLists struct {
	ruleLists   []*ContivRuleList          /* ordered by rules */
	numItems    int                        /* actual number of lists, the rest are nils */
	byID        map[string]*ContivRuleList /* search by rule list ID */
	byInterface map[string]*ContivRuleList /* search by assigned interface */
}

// NewContivRuleCache is a constructor for ContivRuleCache.
func NewContivRuleCache() *ContivRuleCache {
	return &ContivRuleCache{
		ingress:    NewContivRuleLists(false),
		egress:     NewContivRuleLists(false),
		interfaces: NewInterfaceSet(),
	}
}

// NewContivRuleLists is a constructor for ContivRuleLists.
func NewContivRuleLists(dummy bool) *ContivRuleLists {
	capacity := 0
	if !dummy {
		capacity = 100
	}
	return &ContivRuleLists{
		ruleLists:   make([]*ContivRuleList, 0, capacity),
		byID:        make(map[string]*ContivRuleList),
		byInterface: make(map[string]*ContivRuleList),
	}
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. If <resync> is enabled, the supplied configuration will completely
// replace the existing one, otherwise interfaces not mentioned in the transaction
// are left unchanged.
func (crc *ContivRuleCache) NewTxn(resync bool) Txn {
	return &ContivRuleCacheTxn{
		cache:      crc,
		resync:     resync,
		ingress:    NewContivRuleLists(false),
		egress:     NewContivRuleLists(false),
		interfaces: NewInterfaceSet(),
	}
}

// LookupByInterface returns rules assigned to a given interface grouped
// into lists by the traffic direction. Interfaces with equal ingress and/or
// egress configuration will share the same lists (same IDs).
func (crc *ContivRuleCache) LookupByInterface(ifName string) (ingress, egress *ContivRuleList) {
	ingress = crc.ingress.LookupByInterface(ifName)
	egress = crc.egress.LookupByInterface(ifName)
	return ingress, egress
}

// AllInterfaces returns a set of all known interfaces (already updated
// configuration).
func (crc *ContivRuleCache) AllInterfaces() InterfaceSet {
	return crc.interfaces
}

// Generator for ContivRuleList IDs.
func (crc *ContivRuleCache) generateContivRuleListID(prefix string) string {
	crc.lastListID++
	return prefix + strconv.FormatUint(crc.lastListID, 10)
}

// Update changes the list of ingress and egress rules for a given interface.
// The change is applied into the cache during commit.
// Run Changes() before Commit() to learn the set of pending updates (merged
// to minimal diff).
func (crct *ContivRuleCacheTxn) Update(ifName string, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) error {
	crct.interfaces.Add(ifName)
	if crct.resync == true {
		crct.updateInterface(ifName, ingress, "ingress", crct.ingress, NewContivRuleLists(true))
		crct.updateInterface(ifName, egress, "egress", crct.egress, NewContivRuleLists(true))
	} else {
		crct.updateInterface(ifName, ingress, "ingress", crct.ingress, crct.cache.ingress)
		crct.updateInterface(ifName, egress, "egress", crct.egress, crct.cache.egress)
	}
	return nil
}

// updateInterface changes the list of ingress or egress rules for a given interface.
func (crct *ContivRuleCacheTxn) updateInterface(ifName string, rules []*renderer.ContivRule, category string,
	head *ContivRuleLists, base *ContivRuleLists) {
	// Add orig list into the head if is not already there
	origRuleList := base.LookupByInterface(ifName)
	if origRuleList != nil && head.LookupByID(origRuleList.ID) == nil {
		// create a copy in the head (only shallow copy of rules)
		updatedOrigRuleList := &ContivRuleList{
			ID:         origRuleList.ID,
			Rules:      origRuleList.Rules,
			Interfaces: origRuleList.Interfaces.Copy(),
			Private:    origRuleList.Private,
		}
		head.Insert(updatedOrigRuleList)
	}
	// check if the ruleList was already created inside the transaction
	ruleList := head.LookupByRules(rules)
	if ruleList != nil {
		head.AssignInterface(ruleList, ifName)
		return
	}
	// check if the ruleList exists in the cache (but not in the head)
	ruleList = base.LookupByRules(rules)
	if ruleList != nil {
		if _, assigned := ruleList.Interfaces[ifName]; assigned {
			/* nothing to change */
			return
		}
		// create a copy in the head with added interface (only shallow copy of rules)
		updatedRuleList := &ContivRuleList{
			ID:         ruleList.ID,
			Rules:      ruleList.Rules,
			Interfaces: ruleList.Interfaces.Copy(),
			Private:    ruleList.Private,
		}
		updatedRuleList.Interfaces.Add(ifName)
		head.Insert(updatedRuleList)
		return
	}
	// create a new RuleList
	newRuleList := &ContivRuleList{
		ID:         crct.cache.generateContivRuleListID(category),
		Rules:      rules,
		Interfaces: NewInterfaceSet(ifName),
		Private:    nil,
	}
	head.Insert(newRuleList)
}

// Changes calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (crct *ContivRuleCacheTxn) Changes() (ingress, egress []*TxnChange) {
	if crct.resync == true {
		ingress = crct.getChanges(crct.ingress, NewContivRuleLists(true))
		egress = crct.getChanges(crct.egress, NewContivRuleLists(true))
	} else {
		ingress = crct.getChanges(crct.ingress, crct.cache.ingress)
		egress = crct.getChanges(crct.egress, crct.cache.egress)
	}
	return ingress, egress
}

// getChanges calculates a minimalistic set of changes prepared in the transaction
// for ingress or egress.
func (crct *ContivRuleCacheTxn) getChanges(head *ContivRuleLists, base *ContivRuleLists) []*TxnChange {
	changes := []*TxnChange{}
	for _, ruleList := range head.ruleLists {
		origRuleList := base.LookupByID(ruleList.ID)
		if len(ruleList.Interfaces) == 0 && origRuleList == nil {
			// added and removed in the same transaction => skip
			continue
		}
		change := &TxnChange{
			List: ruleList,
		}
		if origRuleList != nil {
			change.PreviousInterfaces = origRuleList.Interfaces.Copy()
		} else {
			change.PreviousInterfaces = NewInterfaceSet()
		}
		changes = append(changes, change)
	}
	return changes
}

// Commit applies the changes into the underlying cache.
func (crct *ContivRuleCacheTxn) Commit() error {
	if crct.resync == true {
		// Remove unused lists.
		unused := func(ruleList *ContivRuleList) bool {
			return len(ruleList.Interfaces) == 0
		}
		crct.ingress.RemoveByPredicate(unused)
		crct.egress.RemoveByPredicate(unused)
		// Just replace the cache content with the changes from the transaction.
		crct.cache.ingress = crct.ingress
		crct.cache.egress = crct.egress
	} else {
		// Apply differences.
		crct.commit(crct.ingress, crct.cache.ingress)
		crct.commit(crct.egress, crct.cache.egress)
	}
	crct.cache.interfaces.Join(crct.interfaces)
	return nil
}

// Commit applies the changes into the underlying cache for ingress or egress.
func (crct *ContivRuleCacheTxn) commit(head *ContivRuleLists, base *ContivRuleLists) {
	for _, ruleList := range head.ruleLists {
		origRuleList := base.LookupByID(ruleList.ID)
		if origRuleList != nil {
			if len(ruleList.Interfaces) == 0 {
				// RuleList removed in the transaction.
				base.Remove(ruleList)
			} else {
				// Update interfaces.
				for iface := range origRuleList.Interfaces {
					if !ruleList.Interfaces.Has(iface) {
						base.UnassignInterface(origRuleList, iface)
					}
				}
				for iface := range ruleList.Interfaces {
					if !origRuleList.Interfaces.Has(iface) {
						base.AssignInterface(origRuleList, iface)
					}
				}
				// Copy Private which may have been changed by the cache user.
				origRuleList.Private = ruleList.Private
			}
		} else {
			if len(ruleList.Interfaces) != 0 {
				// New RuleList created in the transaction.
				base.Insert(ruleList)
			}
		}
	}
}

func (crl *ContivRuleLists) lookupIdxByRules(rules []*renderer.ContivRule) int {
	return sort.Search(crl.numItems,
		func(i int) bool {
			return compareRuleLists(rules, crl.ruleLists[i].Rules) < 0
		})
}

// Insert ContivRuleList into the list.
func (crl *ContivRuleLists) Insert(ruleList *ContivRuleList) bool {
	// Insert the list at the right index to keep the order
	listIdx := crl.lookupIdxByRules(ruleList.Rules)
	if listIdx < crl.numItems &&
		compareRuleLists(ruleList.Rules, crl.ruleLists[listIdx].Rules) == 0 {
		/* already added */
		return false
	}
	if crl.numItems == len(crl.ruleLists) {
		/* just increase the size by one */
		crl.ruleLists = append(crl.ruleLists, nil)
	}
	if listIdx < crl.numItems {
		copy(crl.ruleLists[listIdx+1:], crl.ruleLists[listIdx:])
	}
	crl.ruleLists[listIdx] = ruleList
	crl.numItems++
	crl.byID[ruleList.ID] = ruleList
	for iface := range ruleList.Interfaces {
		crl.UnassignInterface(nil, iface)
		crl.byInterface[iface] = ruleList
	}
	return true
}

// Remove ContivRuleList from the list.
func (crl *ContivRuleLists) Remove(ruleList *ContivRuleList) bool {
	for listIdx, ruleList2 := range crl.ruleLists {
		if ruleList2 == ruleList {
			return crl.RemoveByIdx(listIdx)
		}
	}
	return false
}

// Remove ContivRuleList from the list.
func (crl *ContivRuleLists) RemoveByIdx(idx int) bool {
	if idx < crl.numItems {
		ruleList := crl.ruleLists[idx]
		if (idx < crl.numItems-1) && (crl.numItems > 1) {
			copy(crl.ruleLists[idx:], crl.ruleLists[idx+1:])
		}
		crl.numItems--
		crl.ruleLists[crl.numItems] = nil
		delete(crl.byID, ruleList.ID)
		for iface := range ruleList.Interfaces {
			delete(crl.byInterface, iface)
		}
		return true
	}
	return false
}

// RemoveByPredicate removes ContivRuleLists that satisfy a given predicate.
func (crl *ContivRuleLists) RemoveByPredicate(predicate func(ruleList *ContivRuleList) bool) int {
	listIdx := 0
	count := 0
	for listIdx < crl.numItems {
		if predicate(crl.ruleLists[listIdx]) == true {
			crl.RemoveByIdx(listIdx)
			count++
		} else {
			listIdx++
		}
	}
	return count
}

// AssignInterface assigns interface into a list.
func (crl *ContivRuleLists) AssignInterface(ruleList *ContivRuleList, ifName string) {
	crl.UnassignInterface(nil, ifName)
	ruleList.Interfaces.Add(ifName)
	crl.byInterface[ifName] = ruleList
}

// UnassignInterface removes previous assignment of an interface into a list.
// <ruleList> may be nil to match any list.
func (crl *ContivRuleLists) UnassignInterface(ruleList *ContivRuleList, ifName string) {
	if list, assigned := crl.byInterface[ifName]; assigned {
		if ruleList == nil || ruleList == list {
			list.Interfaces.Remove(ifName)
			delete(crl.byInterface, ifName)
		}
	}
}

// LookupByID searches for ContivRuleList by ID.
func (crl *ContivRuleLists) LookupByID(id string) *ContivRuleList {
	list, exists := crl.byID[id]
	if exists {
		return list
	}
	return nil
}

// LookupByRules searches for ContivRuleList by rules.
func (crl *ContivRuleLists) LookupByRules(rules []*renderer.ContivRule) *ContivRuleList {
	listIdx := crl.lookupIdxByRules(rules)
	if listIdx < len(crl.ruleLists) &&
		compareRuleLists(rules, crl.ruleLists[listIdx].Rules) == 0 {
		return crl.ruleLists[listIdx]
	}
	return nil
}

// LookupByInterface searches for ContivRuleList by an assigned interface.
func (crl *ContivRuleLists) LookupByInterface(ifname string) *ContivRuleList {
	list, exists := crl.byInterface[ifname]
	if exists {
		return list
	}
	return nil
}

// NewInterfaceSet creates InterfaceSet with given items.
func NewInterfaceSet(ifNames ...string) InterfaceSet {
	set := make(InterfaceSet)
	for _, ifName := range ifNames {
		set.Add(ifName)
	}
	return set
}

// Copy returns deep copy of the set.
func (set InterfaceSet) Copy() InterfaceSet {
	copy := NewInterfaceSet()
	copy.Join(set)
	return copy
}

// Has returns true if the set contains given interface name.
func (set InterfaceSet) Has(ifName string) bool {
	_, has := set[ifName]
	return has
}

// Add adds new interface into the set.
func (set InterfaceSet) Add(ifName string) {
	set[ifName] = struct{}{}
}

// Remove removes interface name from the set if it is there.
func (set InterfaceSet) Remove(ifName string) bool {
	if _, exists := set[ifName]; exists {
		delete(set, ifName)
		return true
	}
	return false
}

// Join merges <set2> into this set.
func (set InterfaceSet) Join(set2 InterfaceSet) {
	for ifName := range set2 {
		set.Add(ifName)
	}
}

// compareIpNets returns an integer comparing two IP network addresses
// lexicographically.
func compareIpNets(a, b *net.IPNet) int {
	ipOrder := bytes.Compare(a.IP, b.IP)
	if ipOrder == 0 {
		return bytes.Compare(a.Mask, b.Mask)
	}
	return ipOrder
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

// compareRules returns an integer comparing two Contiv rules lexicographically.
func compareRules(a, b *renderer.ContivRule) int {
	if a.ID < b.ID {
		return -1
	}
	if a.ID > b.ID {
		return 1
	}
	actionOrder := compareInts(int(a.Action), int(b.Action))
	if actionOrder != 0 {
		return actionOrder
	}
	srcIPOrder := compareIpNets(a.SrcNetwork, b.SrcNetwork)
	if srcIPOrder != 0 {
		return srcIPOrder
	}
	destIPOrder := compareIpNets(a.DestNetwork, b.DestNetwork)
	if destIPOrder != 0 {
		return destIPOrder
	}
	protocolOrder := compareInts(int(a.Protocol), int(b.Protocol))
	if protocolOrder != 0 {
		return protocolOrder
	}
	srcPortOrder := compareInts(int(a.SrcPort), int(b.SrcPort))
	if srcPortOrder != 0 {
		return srcPortOrder
	}
	return compareInts(int(a.DestPort), int(b.DestPort))
}

// compareRuleLists returns an integer comparing two lists of Contiv rules
// lexicographically.
func compareRuleLists(a, b []*renderer.ContivRule) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	lenOrder := compareInts(len(a), len(b))
	if lenOrder != 0 {
		return lenOrder
	}
	for i := range a {
		ruleOrder := compareRules(a[i], b[i])
		if ruleOrder != 0 {
			return ruleOrder
		}
	}
	return 0
}
