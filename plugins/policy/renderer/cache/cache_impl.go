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
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/policy/renderer"
)

// ContivRuleCache implements ContivRuleCacheAPI.
type ContivRuleCache struct {
	Deps

	ingress *ContivRuleLists
	egress  *ContivRuleLists

	interfaces InterfaceSet // a set of updated interfaces

	allocatedListIDs map[TrafficDirection]AllocatedIDs // ingress / egress -> used IDs
}

// Deps lists dependencies of ContivRuleCache.
type Deps struct {
	Log logging.Logger
}

// ContivRuleCacheTxn represents a single transaction of ContivRuleCache.
type ContivRuleCacheTxn struct {
	cache *ContivRuleCache

	// lists with changes from the transaction
	ingress *ContivRuleLists
	egress  *ContivRuleLists

	interfaces InterfaceSet
}

// ContivRuleLists is an ordered list of Contiv Rule lists with efficient
// operations (apart from Remove() and RemoveByPredicate() all with logarithmic
// or constant complexity).
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
	Log         logging.Logger
	ruleLists   []*ContivRuleList          /* ordered by rules */
	numItems    int                        /* actual number of lists, the rest are nils */
	byID        map[string]*ContivRuleList /* search by rule list ID */
	byInterface map[string]*ContivRuleList /* search by assigned interface */
}

// TrafficDirection is one of: Ingress, Egress.
type TrafficDirection int

const (
	// Ingress.
	Ingress TrafficDirection = iota

	// Egress.
	Egress
)

// String converts TrafficDirection into a human-readable string.
func (td TrafficDirection) String() string {
	switch td {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	}
	return "INVALID"
}

// AllocatedIDs represents a set of all allocated IDs.
type AllocatedIDs map[string]struct{}

// NewContivRuleLists is a constructor for ContivRuleLists.
func NewContivRuleLists(logger logging.Logger) *ContivRuleLists {
	return &ContivRuleLists{
		Log:         logger,
		ruleLists:   make([]*ContivRuleList, 0, 100),
		byID:        make(map[string]*ContivRuleList),
		byInterface: make(map[string]*ContivRuleList),
	}
}

// Init initializes the ContivRule Cache.
func (crc *ContivRuleCache) Init() error {
	crc.interfaces = NewInterfaceSet()
	crc.allocatedListIDs = make(map[TrafficDirection]AllocatedIDs)
	crc.ingress = NewContivRuleLists(crc.Log)
	crc.egress = NewContivRuleLists(crc.Log)
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called.
func (crc *ContivRuleCache) NewTxn() Txn {
	return &ContivRuleCacheTxn{
		cache:      crc,
		ingress:    NewContivRuleLists(crc.Log),
		egress:     NewContivRuleLists(crc.Log),
		interfaces: NewInterfaceSet(),
	}
}

// Resync completely replaces the existing cache content with the supplied
// data.
func (crc *ContivRuleCache) Resync(ingress, egress []*ContivRuleList) error {
	// Possible errors.
	invalidIdPrefixFmt := "invalid ContivRuleList ID prefix: %s"
	duplicateIdFmt := "duplicate ContivRuleList ID: %s"
	duplicateFmt := "duplicate ContivRuleList: %s"

	// Re-synchronize outside of the cache first.
	// In-progress failure should not affect the cache content.
	interfaces := NewInterfaceSet()
	allocatedListIDs := make(map[TrafficDirection]AllocatedIDs)
	ingressLists := NewContivRuleLists(crc.Log)
	egressLists := NewContivRuleLists(crc.Log)
	//  -> Ingress
	for _, list := range ingress {
		if len(list.Interfaces) == 0 {
			// Skip unused lists.
			continue
		}
		if !strings.HasPrefix(list.ID, Ingress.String()+"-") {
			return fmt.Errorf(invalidIdPrefixFmt, list.ID)
		}
		idSuffix := strings.TrimPrefix(list.ID, Ingress.String()+"-")
		_, duplicity := allocatedListIDs[Ingress][idSuffix]
		if duplicity {
			return fmt.Errorf(duplicateIdFmt, list.ID)
		}
		allocatedListIDs[Ingress][idSuffix] = struct{}{}
		if !ingressLists.Insert(list) {
			return fmt.Errorf(duplicateFmt, list.ID)
		}
		interfaces.Join(list.Interfaces)
	}
	//  -> Egress
	for _, list := range egress {
		if len(list.Interfaces) == 0 {
			// Skip unused lists.
			continue
		}
		if !strings.HasPrefix(list.ID, Egress.String()+"-") {
			return fmt.Errorf(invalidIdPrefixFmt, list.ID)
		}
		idSuffix := strings.TrimPrefix(list.ID, Egress.String()+"-")
		_, duplicity := allocatedListIDs[Egress][idSuffix]
		if duplicity {
			return fmt.Errorf(duplicateIdFmt, list.ID)
		}
		allocatedListIDs[Egress][idSuffix] = struct{}{}
		if !egressLists.Insert(list) {
			return fmt.Errorf(duplicateFmt, list.ID)
		}
		interfaces.Join(list.Interfaces)
	}

	// Replace the cache content.
	crc.interfaces = interfaces
	crc.allocatedListIDs = allocatedListIDs
	crc.ingress = ingressLists
	crc.egress = egressLists
	return nil
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
func (crc *ContivRuleCache) generateListID(direction TrafficDirection) string {
	var suffix string
	if _, exists := crc.allocatedListIDs[direction]; !exists {
		crc.allocatedListIDs[direction] = make(AllocatedIDs)
	}
	for {
		// Generate random suffix, 10 characters long.
		b := make([]byte, 5)
		rand.Read(b)
		suffix := fmt.Sprintf("%X", b)
		if _, exists := crc.allocatedListIDs[direction][suffix]; !exists {
			break
		}
	}
	return direction.String() + "-" + suffix
}

// Update changes the list of ingress and egress rules for a given interface.
// The change is applied into the cache during commit.
// Run Changes() before Commit() to learn the set of pending updates (merged
// to minimal diff).
func (crct *ContivRuleCacheTxn) Update(ifName string, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) error {
	crct.cache.Log.WithFields(logging.Fields{
		"ifName":  ifName,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("ContivRuleCacheTxn Update()")
	crct.interfaces.Add(ifName)
	crct.updateInterface(ifName, ingress, Ingress, crct.ingress, crct.cache.ingress)
	crct.updateInterface(ifName, egress, Egress, crct.egress, crct.cache.egress)
	return nil
}

// updateInterface changes the list of ingress or egress rules for a given interface.
func (crct *ContivRuleCacheTxn) updateInterface(ifName string, rules []*renderer.ContivRule, direction TrafficDirection,
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
		crct.cache.Log.WithFields(logging.Fields{
			"direction": direction,
			"ListID":    origRuleList.ID,
		}).Debug("Created a shallow copy for the transaction")
	}
	// check if the ruleList was already created inside the transaction
	ruleList := head.LookupByRules(rules)
	if ruleList != nil {
		head.AssignInterface(ruleList, ifName)
		crct.cache.Log.WithFields(logging.Fields{
			"direction": direction,
			"ifName":    ifName,
			"ListID":    ruleList.ID,
		}).Debug("Found matching rule list in the transaction")
		return
	}
	// check if the ruleList exists in the cache (but not in the head)
	ruleList = base.LookupByRules(rules)
	if ruleList != nil {
		if _, assigned := ruleList.Interfaces[ifName]; assigned {
			crct.cache.Log.WithFields(logging.Fields{
				"direction": direction,
				"ifName":    ifName,
				"ListID":    ruleList.ID,
			}).Debug("Nothing to update")
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
		crct.cache.Log.WithFields(logging.Fields{
			"direction": direction,
			"ListID":    ruleList.ID,
			"ifName":    ifName,
		}).Debug("Created a shallow copy for the transaction with added interface")
		return
	}
	// create a new RuleList
	newRuleList := &ContivRuleList{
		ID:         crct.cache.generateListID(direction),
		Rules:      rules,
		Interfaces: NewInterfaceSet(ifName),
		Private:    nil,
	}
	head.Insert(newRuleList)
	crct.cache.Log.WithFields(logging.Fields{
		"direction": direction,
		"ListID":    newRuleList.ID,
		"ifName":    ifName,
	}).Debug("Created a new ContivRuleList")
}

// Changes calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (crct *ContivRuleCacheTxn) Changes() (ingress, egress []*TxnChange) {
	ingress = crct.getChanges(crct.ingress, crct.cache.ingress)
	egress = crct.getChanges(crct.egress, crct.cache.egress)
	crct.cache.Log.WithFields(logging.Fields{
		"ingress": ingress,
		"egress":  egress,
	}).Debug("ContivRuleCacheTxn Changes()")
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
		if origRuleList != nil && ruleList.Interfaces.Equals(origRuleList.Interfaces) {
			// nothing has really changed for this list
			continue
		}
		change := &TxnChange{
			List: ruleList,
		}
		if origRuleList != nil {
			change.PreviousInterfaces = origRuleList.Interfaces
		} else {
			change.PreviousInterfaces = NewInterfaceSet()
		}
		changes = append(changes, change)
	}
	return changes
}

// AllInterfaces returns set of all interfaces included in the transaction.
func (crct *ContivRuleCacheTxn) AllInterfaces() InterfaceSet {
	return crct.interfaces
}

// Commit applies the changes into the underlying cache.
func (crct *ContivRuleCacheTxn) Commit() error {
	// Apply differences.
	crct.commit(crct.ingress, crct.cache.ingress)
	crct.commit(crct.egress, crct.cache.egress)
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
				crct.cache.Log.WithFields(logging.Fields{
					"ListID": ruleList.ID,
				}).Debug("ContivRuleList removed in the transaction")
			} else if !ruleList.Interfaces.Equals(origRuleList.Interfaces) {
				crct.cache.Log.WithFields(logging.Fields{
					"ListID":         ruleList.ID,
					"origInterfaces": origRuleList.Interfaces,
					"newInterfaces":  ruleList.Interfaces,
				}).Debug("ContivRuleList changed in the transaction")
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
				crct.cache.Log.WithFields(logging.Fields{
					"ListID": ruleList.ID,
				}).Debug("New ContivRuleList created in the transaction")
			}
		}
	}
}

func (crls *ContivRuleLists) lookupIdxByRules(rules []*renderer.ContivRule) int {
	return sort.Search(crls.numItems,
		func(i int) bool {
			return compareRuleLists(rules, crls.ruleLists[i].Rules) <= 0
		})
}

// Insert ContivRuleList into the list.
func (crls *ContivRuleLists) Insert(ruleList *ContivRuleList) bool {
	// Insert the list at the right index to keep the order
	listIdx := crls.lookupIdxByRules(ruleList.Rules)
	if listIdx < crls.numItems &&
		compareRuleLists(ruleList.Rules, crls.ruleLists[listIdx].Rules) == 0 {
		/* already added */
		return false
	}
	if crls.numItems == len(crls.ruleLists) {
		/* just increase the size by one */
		crls.ruleLists = append(crls.ruleLists, nil)
	}
	if listIdx < crls.numItems {
		copy(crls.ruleLists[listIdx+1:], crls.ruleLists[listIdx:])
	}
	crls.ruleLists[listIdx] = ruleList
	crls.numItems++
	crls.byID[ruleList.ID] = ruleList
	for iface := range ruleList.Interfaces {
		crls.UnassignInterface(nil, iface)
		crls.byInterface[iface] = ruleList
	}
	return true
}

// Remove ContivRuleList from the list.
func (crls *ContivRuleLists) Remove(ruleList *ContivRuleList) bool {
	for listIdx, ruleList2 := range crls.ruleLists {
		if ruleList2 == ruleList {
			return crls.RemoveByIdx(listIdx)
		}
	}
	return false
}

// RemoveByIdx removes ContivRuleList under a given index from the list.
func (crls *ContivRuleLists) RemoveByIdx(idx int) bool {
	if idx < crls.numItems {
		ruleList := crls.ruleLists[idx]
		if idx < crls.numItems-1 {
			copy(crls.ruleLists[idx:], crls.ruleLists[idx+1:])
		}
		crls.numItems--
		crls.ruleLists[crls.numItems] = nil
		delete(crls.byID, ruleList.ID)
		for iface := range ruleList.Interfaces {
			delete(crls.byInterface, iface)
		}
		return true
	}
	return false
}

// RemoveByPredicate removes ContivRuleLists that satisfy a given predicate.
func (crls *ContivRuleLists) RemoveByPredicate(predicate func(ruleList *ContivRuleList) bool) int {
	listIdx := 0
	count := 0
	for listIdx < crls.numItems {
		if predicate(crls.ruleLists[listIdx]) == true {
			crls.RemoveByIdx(listIdx)
			count++
		} else {
			listIdx++
		}
	}
	return count
}

// AssignInterface assigns interface into a list.
func (crls *ContivRuleLists) AssignInterface(ruleList *ContivRuleList, ifName string) {
	crls.UnassignInterface(nil, ifName)
	ruleList.Interfaces.Add(ifName)
	crls.byInterface[ifName] = ruleList
}

// UnassignInterface removes previous assignment of an interface from a list.
// <ruleList> may be nil to match any list.
func (crls *ContivRuleLists) UnassignInterface(ruleList *ContivRuleList, ifName string) {
	if ruleList != nil {
		ruleList.Interfaces.Remove(ifName)
	}
	if list, assigned := crls.byInterface[ifName]; assigned {
		if ruleList == nil || ruleList == list {
			list.Interfaces.Remove(ifName)
			delete(crls.byInterface, ifName)
		}
	}
}

// LookupByID searches for ContivRuleList by ID.
func (crls *ContivRuleLists) LookupByID(id string) *ContivRuleList {
	list, exists := crls.byID[id]
	if exists {
		return list
	}
	return nil
}

// LookupByRules searches for ContivRuleList by rules.
func (crls *ContivRuleLists) LookupByRules(rules []*renderer.ContivRule) *ContivRuleList {
	listIdx := crls.lookupIdxByRules(rules)
	if listIdx < crls.numItems &&
		compareRuleLists(rules, crls.ruleLists[listIdx].Rules) == 0 {
		return crls.ruleLists[listIdx]
	}
	return nil
}

// LookupByInterface searches for ContivRuleList by an assigned interface.
func (crls *ContivRuleLists) LookupByInterface(ifname string) *ContivRuleList {
	list, exists := crls.byInterface[ifname]
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

// Equals compares two sets for equality.
func (set InterfaceSet) Equals(set2 InterfaceSet) bool {
	if len(set) != len(set2) {
		return false
	}
	for ifName := range set {
		if !set2.Has(ifName) {
			return false
		}
	}
	return true
}

// String returns a human-readable string representation of the set.
func (set InterfaceSet) String() string {
	str := "{"
	count := 0
	for ifName := range set {
		count++
		str += ifName
		if count < len(set) {
			str += ", "
		}
	}
	str += "}"
	return str
}

// compareIPNets returns an integer comparing two IP network addresses
// lexicographically.
func compareIPNets(a, b *net.IPNet) int {
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
	srcIPOrder := compareIPNets(a.SrcNetwork, b.SrcNetwork)
	if srcIPOrder != 0 {
		return srcIPOrder
	}
	destIPOrder := compareIPNets(a.DestNetwork, b.DestNetwork)
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
