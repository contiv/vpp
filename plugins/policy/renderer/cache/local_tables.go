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
	"sort"

	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// LocalTables is an ordered list of all cached local tables.
// It has efficient operations: apart from Remove() and RemoveByPredicate(),
// all with logarithmic or constant complexity.
//
// API:
//  Insert(table)
//  Remove(table)
//  RemoveByIdx(idx)
//  RemoveByPredicate(func(table) -> bool)
//  LookupByID(ID) -> table
//  LookupByRules() -> table
//  LookupByPod(pod) -> table
//  AssignPod(table, podID)
//  UnassignPod(table/nil=all, podID)
//  GetIsolatedPods() -> pods
type LocalTables struct {
	Log       logging.Logger
	tables    []*ContivRuleTable               /* ordered by rules */
	numTables int                              /* actual number of tables, the rest are nils */
	byID      map[string]*ContivRuleTable      /* search by table ID */
	byPod     map[podmodel.ID]*ContivRuleTable /* search local table associated to a given pod */
}

// NewLocalTables is a constructor for LocalTables.
func NewLocalTables(logger logging.Logger) *LocalTables {
	return &LocalTables{
		Log:    logger,
		tables: make([]*ContivRuleTable, 0, 100),
		byID:   make(map[string]*ContivRuleTable),
		byPod:  make(map[podmodel.ID]*ContivRuleTable),
	}
}

// Insert local table into the list.
func (lts *LocalTables) Insert(table *ContivRuleTable) bool {
	_, alreadyAdded := lts.byID[table.ID]
	if alreadyAdded {
		return false
	}

	// Insert the table at the right index to keep the order.
	tableIdx := lts.lookupIdxByRules(table.Rules)
	if lts.numTables == len(lts.tables) {
		/* just increase the size by one */
		lts.tables = append(lts.tables, nil)
	}
	if tableIdx < lts.numTables {
		copy(lts.tables[tableIdx+1:], lts.tables[tableIdx:])
	}
	lts.tables[tableIdx] = table
	lts.numTables++
	lts.byID[table.ID] = table
	for pod := range table.Pods {
		lts.UnassignPod(nil, pod)
		lts.byPod[pod] = table
	}
	return true
}

// Remove local table from the list (by pointer).
func (lts *LocalTables) Remove(table *ContivRuleTable) bool {
	for i := 0; i < lts.numTables; i++ {
		if table == lts.tables[i] {
			return lts.RemoveByIdx(i)
		}
	}
	return false
}

// RemoveByIdx removes local table under a given index from the list.
// Returns *true* if the index is valid and the table was removed.
func (lts *LocalTables) RemoveByIdx(idx int) bool {
	if idx < lts.numTables {
		table := lts.tables[idx]
		if idx < lts.numTables-1 {
			copy(lts.tables[idx:], lts.tables[idx+1:])
		}
		lts.numTables--
		lts.tables[lts.numTables] = nil
		delete(lts.byID, table.ID)
		for pod := range table.Pods {
			delete(lts.byPod, pod)
		}
		return true
	}
	return false
}

// RemoveByPredicate removes all local tables that satisfy a given predicate.
// Number of removed tables is returned.
func (lts *LocalTables) RemoveByPredicate(predicate func(table *ContivRuleTable) bool) int {
	tableIdx := 0
	count := 0
	for tableIdx < lts.numTables {
		if predicate(lts.tables[tableIdx]) == true {
			lts.RemoveByIdx(tableIdx)
			count++
		} else {
			tableIdx++
		}
	}
	return count
}

// AssignPod creates association between the pod and the table.
func (lts *LocalTables) AssignPod(table *ContivRuleTable, podID podmodel.ID) {
	lts.UnassignPod(nil, podID)
	table.Pods.Add(podID)
	lts.byPod[podID] = table
}

// UnassignPod removes association between the pod and the table.
// <table> may be nil to match any local table.
func (lts *LocalTables) UnassignPod(table *ContivRuleTable, podID podmodel.ID) {
	if table != nil {
		table.Pods.Remove(podID)
	}
	if table2, assigned := lts.byPod[podID]; assigned {
		if table == nil || table == table2 {
			table2.Pods.Remove(podID)
			delete(lts.byPod, podID)
		}
	}
}

// LookupByID searches for table by ID.
func (lts *LocalTables) LookupByID(id string) *ContivRuleTable {
	table, exists := lts.byID[id]
	if exists {
		return table
	}
	return nil
}

// LookupByRules searches for table by rules.
// If there are multiple tables with this list of rules, the one with the smallest
// index in the list of tables is returned.
func (lts *LocalTables) LookupByRules(rules []*renderer.ContivRule) *ContivRuleTable {
	tableIdx := lts.lookupIdxByRules(rules)
	if tableIdx < lts.numTables &&
		compareRuleLists(rules, lts.tables[tableIdx].Rules) == 0 {
		return lts.tables[tableIdx]
	}
	return nil
}

// LookupByPod searches for table by an assigned pod.
func (lts *LocalTables) LookupByPod(podID podmodel.ID) *ContivRuleTable {
	table, exists := lts.byPod[podID]
	if exists {
		return table
	}
	return nil
}

// GetIsolatedPods returns the set of IDs of all pods that have a (non-empty) local table assigned.
// The term "isolated" is borrowed from K8s, pods become isolated by having
// a NetworkPolicy that selects them.
func (lts *LocalTables) GetIsolatedPods() PodSet {
	pods := NewPodSet()
	for podID, table := range lts.byPod {
		if table.NumOfRules > 0 {
			pods.Add(podID)
		}
	}
	return pods
}

// lookupIdxByRules returns index in the list of local tables, where a table
// with given rules is/should be to respect the order.
func (lts *LocalTables) lookupIdxByRules(rules []*renderer.ContivRule) int {
	return sort.Search(lts.numTables,
		func(i int) bool {
			return compareRuleLists(rules, lts.tables[i].Rules) <= 0
		})
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
	lenOrder := utils.CompareInts(len(a), len(b))
	if lenOrder != 0 {
		return lenOrder
	}
	for i := range a {
		ruleOrder := a[i].Compare(b[i])
		if ruleOrder != 0 {
			return ruleOrder
		}
	}
	return 0
}
