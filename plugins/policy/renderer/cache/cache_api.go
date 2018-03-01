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
	"fmt"
	"net"
	"sort"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// GlobalTableID is the ID of the global table.
const GlobalTableID = "NODE-GLOBAL"

// RendererCacheAPI defines API of a cache used to store Contiv rules.
// The cache allows renderer to easily calculate the minimal set of changes
// that need to be applied in a given transaction.
//
// The rules are grouped into the tables (ContivRuleTable) and the configuration
// is represented as a list of local tables, applied on the ingress
// or the egress side of pods, and a single global table, applied on the interfaces
// connecting the node with the rest of the cluster.
// The list of local tables is minimalistic in the sense that pods with the same
// set of rules will share the same local table. Whether shared tables are installed
// in one instance or as separate copies for each associated pod is up to the renderer
// (usually determined by the capabilities of the destination network stack).
//
// All tables match only one side of the traffic - either ingress or egress, depending
// on the cache orientation as selected in the Init method. The cache combines
// the received ingress and egress Contiv rules into the single chosen direction
// in a way that maintains the original semantic (the global table is introduced
// to accomplish the task).
// For IngressOrientation, the local table rules have source IP address and port
// always ANYADDR/ANYPORT.
// For EgressOrientation, the local table rules have destination IP address and port
// always ANYADDR/ANYPORT.
type RendererCacheAPI interface {
	View

	// Init initializes the cache.
	// The caller selects the orientation of the traffic at which the rules are applied
	// in the destination network stack.
	Init(orientation Orientation)

	// Flush completely wipes out the cache content.
	Flush()

	// NewTxn starts a new transaction. The changes are reflected in the cache
	// only after Commit() is called.
	NewTxn() Txn

	// Resync completely replaces the existing cache content with the supplied
	// data.
	// The configuration cannot be fully reconstructed however, only the set
	// of all tracked pods. Do not use GetPodConfig() immediately after Resync(),
	// instead follow the resync with a transaction that updates the configuration
	// of still present pods and removes the rest (Cache.GetAllPods() \ Txn.GetUpdatedPods()).
	Resync(tables []*ContivRuleTable) error
}

// View allows to read the cache content
type View interface {
	// GetPodConfig returns the current configuration of a given pod
	// (as passed through the Txn.Update() method).
	// Method returns nil if the given pod is not tracked by the cache.
	GetPodConfig(pod podmodel.ID) *PodConfig

	// GetAllPods returns the set of all pods currently tracked by the cache.
	GetAllPods() PodSet

	// GetIsolatedPods returns the set of IDs of all pods that have a local table assigned.
	// The term "isolated" is borrowed from K8s, pods become isolated by having
	// a NetworkPolicy that selects them.
	GetIsolatedPods() PodSet

	// GetLocalTableByPod returns the local table assigned to a given pod.
	// Returns nil if the pod has no table assigned (non-isolated).
	GetLocalTableByPod(pod podmodel.ID) *ContivRuleTable

	// GetGlobalTable returns the global table.
	// The function never returns nil but may return table with empty set of rules
	// (meaning ALLOW-ALL).
	GetGlobalTable() *ContivRuleTable
}

// Orientation is either "IngressOrientation" or "EgressOrientation".
// It is selected during the cache initialization to specify whether the rule
// matching algorithm in the destination network stack runs against the ingress
// or the egress traffic (from the vswitch point of view).
type Orientation int

const (
	// IngressOrientation means that rules are applied on the traffic *arriving*
	// from the interfaces into the vswitch.
	IngressOrientation Orientation = iota

	// EgressOrientation means that rules are applied on the traffic *leaving*
	// the vswitch through the interfaces.
	EgressOrientation
)

// Txn defines API of RendererCache transaction.
type Txn interface {
	// View allows to view the cache as it will look like if the transaction
	// is committed without any additional changes.
	// Should be used only before Commit() (afterwards use View from the cache itself).
	View

	// Update changes the configuration of Contiv rules for a given pod.
	// The change is applied into the cache during the commit.
	// Run GetChanges() before Commit() to learn the set of pending updates (merged
	// to a minimal diff).
	// If *podConfig.removed* is true, the pod will be removed from the cache
	// when the transaction is committed.
	Update(pod podmodel.ID, podConfig *PodConfig)

	// GetUpdatedPods returns the set of all pods included in the transaction.
	GetUpdatedPods() PodSet

	// GetRemovedPods returns the set of all pods that will be removed by the transaction.
	GetRemovedPods() PodSet

	// GetChanges calculates a minimalistic set of changes prepared in the
	// transaction up to this point.
	// Changes are presented from the tables point of view (i.e. what tables have been
	// changed, created, removed).
	// Alternatively, GetLocalTableByPod() and GetGlobalTable() from View
	// interface can be used to get the updated configuration from the pods point of view.
	// GetChanges() must be run before Commit().
	GetChanges() (changes []*TxnChange)

	// Commit applies the changes into the underlying cache.
	Commit() error
}

// PodConfig encapsulates pod configuration (passed through RendererCacheTxn.Update()).
type PodConfig struct {
	PodIP   *net.IPNet
	Ingress []*renderer.ContivRule
	Egress  []*renderer.ContivRule
	Removed bool /* false can only be inside the transaction; removed pods are no longer tracked by the cache */
}

// TxnChange represents change in the RendererCache to be performed
// by a transaction.
type TxnChange struct {
	// Table that has been been affected by the transaction.
	// Possible changes:
	//   - new table
	//   - removed table
	//   - changed assignment of pods for a local table
	//   - change in the set of rules for the global table
	Table *ContivRuleTable

	// Set of pods previously assigned to the table.
	// Empty for the global table or a newly added local table.
	PreviousPods PodSet
}

// String converts TxnChange (pointer) into a human-readable string
// representation.
func (tch *TxnChange) String() string {
	return fmt.Sprintf("Change <table: %s, prevPods: %s>",
		tch.Table, tch.PreviousPods)
}

// ContivRuleTable is a table consisting of Contiv Rules, ordered such that if
// rule *r1* matches subset of the traffic matched by *r2*, then r1 precedes r2
// in the list. It is the order at which the rules should by applied by the rule
// matching algorithm in the destination network stack (otherwise the more specific
// rules could be overshadowed and never matched).
// There are two types of tables distinguished:
//   1. Local table: should be applied to match against traffic leaving (IngressOrientation)
//                   or entering (EgressOrientation) a selected subset of pods.
//                   Every pod has at most one local table installed at any given time.
//                   For local table, the set of rules is immutable. Different content
//                   is treated as a new local table (and the original table may
//                   get unassigned from some or all originally associated pods).
//                   Local table has always at least one rule, otherwise it is simply
//                   not tracked and returned by the cache.
//   2. Global table: should be applied to match against traffic entering (IngressOrientation)
//                    or leaving (EgressOrientation) the node.
//                    There is always exactly one global table installed (per node).
//                    The global table may contain an empty set of rules (meaning ALLOW-ALL).
type ContivRuleTable struct {
	// ID is randomly generated by the cache to uniquely identify the table among
	// all tables. IDs of tables supplied to RendererCacheAPI.Resync() should also
	// satisfy the uniqueness or the operation will get rejected.
	// The exception is the global table which is (and should be) identified
	// as <GlobalTableID>.
	ID string

	// Type is used to differentiate the global table from the local ones.
	Type TableType

	// Set of all pods that have this table assigned.
	// Empty for the global table and a removed local table.
	Pods PodSet

	// Rules applied on the ingress or the egress side for one or multiple pods
	// (local) or globally for the node (global).
	// The rules are in the order such that if rule *r1* matches subset
	// of the traffic matched by *r2*, then r1 precedes r2 in the list.
	// It is the order at which the rules should by applied by the rule
	// matching algorithm in the destination network stack (otherwise the more
	// specific rules could be overshadowed and never matched).
	// First *NumOfRules* entries are filled with rules, the rest are nils.
	Rules []*renderer.ContivRule

	// NumOfRules is the number of rules inserted in the table (remaining entries
	// in *Rules* are nils).
	NumOfRules int

	// Private can be used by renderer to store the configuration of the table
	// in the format used by the destination network stack.
	Private interface{}
}

// NewContivRuleTable is a constructor for ContivRuleTable.
func NewContivRuleTable(id string) *ContivRuleTable {
	tableType := Local
	if id == GlobalTableID {
		tableType = Global
	}
	return &ContivRuleTable{
		ID:    id,
		Type:  tableType,
		Rules: []*renderer.ContivRule{},
		Pods:  NewPodSet(),
	}
}

// InsertRule inserts the rule into the table at the right order.
// Returns *true* if the rule was inserted, *false* if the same rule is already
// in the cache.
func (crt *ContivRuleTable) InsertRule(rule *renderer.ContivRule) bool {
	idx, inserted := crt.getRuleIndex(rule)
	if inserted {
		return false
	}
	if crt.NumOfRules == len(crt.Rules) {
		/* just increase the size by one */
		crt.Rules = append(crt.Rules, nil)
	}
	if idx < crt.NumOfRules {
		copy(crt.Rules[idx+1:], crt.Rules[idx:])
	}
	crt.Rules[idx] = rule
	crt.NumOfRules++
	return true
}

// RemoveRuleByIdx removes rule under a given index from the table.
// Returns *true* if the index is valid and the rule was removed.
func (crt *ContivRuleTable) RemoveRuleByIdx(idx int) bool {
	if idx < crt.NumOfRules {
		if idx < crt.NumOfRules-1 {
			copy(crt.Rules[idx:], crt.Rules[idx+1:])
		}
		crt.NumOfRules--
		crt.Rules[crt.NumOfRules] = nil
		return true
	}
	return false
}

// RemoveByPredicate removes all rules from the table that satisfy a given predicate.
// Number of removed rules is returned.
func (crt *ContivRuleTable) RemoveByPredicate(predicate func(rule *renderer.ContivRule) bool) int {
	ruleIdx := 0
	count := 0
	for ruleIdx < crt.NumOfRules {
		if predicate(crt.Rules[ruleIdx]) == true {
			crt.RemoveRuleByIdx(ruleIdx)
			count++
		} else {
			ruleIdx++
		}
	}
	return count
}

// HasRule returns true if the given rule is included in the table.
func (crt *ContivRuleTable) HasRule(rule *renderer.ContivRule) bool {
	_, inserted := crt.getRuleIndex(rule)
	return inserted
}

// DiffRules calculates diff in terms of rules between this and the other table.
func (crt *ContivRuleTable) DiffRules(crt2 *ContivRuleTable) (notIn2, notInThis []*renderer.ContivRule) {
	for i := 0; i < crt.NumOfRules; i++ {
		if !crt2.HasRule(crt.Rules[i]) {
			notIn2 = append(notIn2, crt.Rules[i])
		}
	}
	for i := 0; i < crt2.NumOfRules; i++ {
		if !crt.HasRule(crt2.Rules[i]) {
			notInThis = append(notInThis, crt2.Rules[i])
		}
	}
	return notIn2, notInThis
}

// getRuleIndex returns the index for the given rule that respects the order
// and a flag to tell whether the rule is already inserted.
func (crt *ContivRuleTable) getRuleIndex(rule *renderer.ContivRule) (idx int, inserted bool) {
	idx = sort.Search(crt.NumOfRules,
		func(i int) bool {
			return rule.Compare(crt.Rules[i]) <= 0
		})
	if idx < crt.NumOfRules && rule.Compare(crt.Rules[idx]) == 0 {
		return idx, true
	}
	return idx, false
}

// String converts ContivRuleTable (pointer) into a human-readable string
// representation.
func (crt *ContivRuleTable) String() string {
	return fmt.Sprintf("Rule Table %s <type: %s, rules: %v, pods: %s>",
		crt.ID, crt.Type, crt.Rules[:crt.NumOfRules], crt.Pods)
}

// TableType is either "Local" or "Global".
type TableType int

const (
	// Local table is applied to match against traffic leaving (IngressOrientation)
	// or entering (EgressOrientation) a selected subset of pods.
	// Every pod has at most one local table installed at any given time.
	Local TableType = iota

	// Global table is applied to match against traffic entering (IngressOrientation)
	// or leaving (EgressOrientation) the node. There is always exactly one global
	// table installed (per node).
	Global
)

// String converts TableType into a human-readable string.
func (tt TableType) String() string {
	switch tt {
	case Local:
		return "Local"
	case Global:
		return "Global"
	}
	return "INVALID"
}

// PodSet is a set of pods.
type PodSet map[podmodel.ID]struct{}

// NewPodSet is a constructor for PodSet
func NewPodSet(podIDs ...podmodel.ID) PodSet {
	pods := make(PodSet)
	for _, podID := range podIDs {
		pods.Add(podID)
	}
	return pods
}

// Copy returns deep copy of the set.
func (set PodSet) Copy() PodSet {
	copy := NewPodSet()
	copy.Join(set)
	return copy
}

// Has returns true if the set contains given pod ID.
func (set PodSet) Has(podID podmodel.ID) bool {
	_, has := set[podID]
	return has
}

// Add adds new pod ID into the set.
func (set PodSet) Add(podID podmodel.ID) {
	set[podID] = struct{}{}
}

// Remove removes pod ID from the set if it is there.
func (set PodSet) Remove(podID podmodel.ID) bool {
	if _, exists := set[podID]; exists {
		delete(set, podID)
		return true
	}
	return false
}

// Join merges <set2> into this set.
func (set PodSet) Join(set2 PodSet) PodSet {
	for podID := range set2 {
		set.Add(podID)
	}
	return set
}

// Equals compares two sets for equality.
func (set PodSet) Equals(set2 PodSet) bool {
	if len(set) != len(set2) {
		return false
	}
	for podID := range set {
		if !set2.Has(podID) {
			return false
		}
	}
	return true
}

// String returns a human-readable string representation of the set.
func (set PodSet) String() string {
	str := "{"
	count := 0
	for podID := range set {
		count++
		str += podID.String()
		if count < len(set) {
			str += ", "
		}
	}
	str += "}"
	return str
}
