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

package cache

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// RendererCache implements RendererCacheAPI.
type RendererCache struct {
	Deps

	// tables
	localTables       *LocalTables
	globalTable       *ContivRuleTable
	allocatedTableIDs AllocatedIDs

	// last received pod configuration
	config Config
}

// Deps lists dependencies of RendererCache.
type Deps struct {
	Log logging.Logger
}

// RendererCacheTxn represents a single transaction of RendererCache.
type RendererCacheTxn struct {
	cache *RendererCache

	// tables with changes from the transaction.
	localTables *LocalTables
	globalTable *ContivRuleTable

	// updated pod configuration
	config Config
}

// PodConfig encapsulates pod config (as received through RendererCacheTxn.Update()).
type PodConfig struct {
	podIP   *net.IPNet
	ingress []*renderer.ContivRule
	egress  []*renderer.ContivRule
}

// Config is used to store snapshot of the configuration as received through
// RendererCacheTxn.Update().
type Config map[podmodel.ID]PodConfig

// AllocatedIDs represents a set of all allocated IDs.
type AllocatedIDs map[string]struct{}

/*********************************** CACHE ***********************************/

// Init initializes the cache.
// The caller selects the orientation of the traffic at which the rules are applied
// in the destination network stack.
func (rc *RendererCache) Init(orientation CacheOrientation) error {
	rc.localTables = NewLocalTables(rc.Log)
	rc.globalTable = NewContivRuleTable(GlobalTableID)
	rc.allocatedTableIDs = make(AllocatedIDs)
	rc.config = make(Config)
	return nil
}

// NewTxn starts a new transaction. The changes are reflected in the cache
// only after Commit() is called.
func (rc *RendererCache) NewTxn() Txn {
	return &RendererCacheTxn{
		cache:       rc,
		localTables: NewLocalTables(rc.Log),
		globalTable: nil,
		config:      make(Config),
	}
}

// Resync completely replaces the existing cache content with the supplied
// data.
func (rc *RendererCache) Resync(tables []*ContivRuleTable) error {

	// Re-synchronize outside of the cache first.
	// In-progress failure should not affect the cache content.
	allocatedTableIDs := make(AllocatedIDs)
	localTables := NewLocalTables(rc.Log)
	globalTable := NewContivRuleTable(GlobalTableID)

	// Build the list of local tables.
	for _, table := range tables {
		if table == nil {
			continue
		}
		if table.Type == Global {
			globalTable = table
			continue
		}
		if len(table.Pods) == 0 {
			// Skip unused local tables.
			continue
		}
		_, duplicity := allocatedTableIDs[table.ID]
		if duplicity {
			return fmt.Errorf("duplicate ContivRuleTable ID: %s", table.ID)
		}
		allocatedTableIDs[table.ID] = struct{}{}
		localTables.Insert(table)
	}

	// Replace the cache content.
	rc.allocatedTableIDs = allocatedTableIDs
	rc.localTables = localTables
	rc.globalTable = globalTable
	return nil
}

// GetPodConfig returns the current configuration of a given pod
// (as passed through the Txn.Update() method the last time).
func (rc *RendererCache) GetPodConfig(pod podmodel.ID) (podIP *net.IPNet, ingress, egress []*renderer.ContivRule) {
	config, hasConfig := rc.config[pod]
	if !hasConfig {
		return nil, ingress, egress
	}
	return config.podIP, config.ingress, config.egress
}

// IsolatedPods returns the set of IDs of all pods that have a local table assigned.
// The term "isolated" is borrowed from K8s, pods become isolated by having
// a NetworkPolicy that selects them.
func (rc *RendererCache) IsolatedPods() PodSet {
	return rc.localTables.IsolatedPods()
}

// GetLocalTableByPod returns the local table assigned to a given pod.
// Returns nil if the pod has no table assigned (non-isolated).
func (rc *RendererCache) GetLocalTableByPod(pod podmodel.ID) *ContivRuleTable {
	table := rc.localTables.LookupByPod(pod)
	if table != nil && table.NumOfRules == 0 {
		table = nil /* do not return empty table */
	}
	return table
}

// GetGlobalTable returns the global table.
// The function never returns nil but may return table with empty set of rules
// (meaning ALLOW-ALL).
func (rc *RendererCache) GetGlobalTable() *ContivRuleTable {
	return rc.globalTable
}

/************************************ TXN ************************************/

func (rct *RendererCacheTxn) Update(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) {
	rct.config[pod] = PodConfig{podIP: podIP, ingress: ingress, egress: egress}

	/* TODO: refresh local tables + global table in the transaction */
}

// UpdatedPods returns the set of all pods included in the transaction.
func (rct *RendererCacheTxn) UpdatedPods() PodSet {
	updated := NewPodSet()
	for pod := range rct.config {
		updated.Add(pod)
	}
	return updated
}

// Changes calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (rct *RendererCacheTxn) Changes() (changes []*TxnChange) {
	// Get changes related to local tables.
	for i := 0; i < rct.localTables.numTables; i++ {
		txnTable := rct.localTables.tables[i]
		origTable := rct.cache.localTables.LookupByID(txnTable.ID)
		if txnTable.NumOfRules == 0 {
			// skip empty local tables
			continue
		}
		if len(txnTable.Pods) == 0 && origTable == nil {
			// added and removed in the same transaction => skip
			continue
		}
		if origTable != nil && txnTable.Pods.Equals(origTable.Pods) {
			// nothing has really changed for this table
			continue
		}
		change := &TxnChange{
			Table: txnTable,
		}
		if origTable != nil {
			change.PreviousPods = origTable.Pods.Copy()
		} else {
			change.PreviousPods = NewPodSet()
		}
		changes = append(changes, change)
	}

	// Check if the global table has changed.
	if rct.globalTable != nil &&
		compareRuleLists(
			rct.globalTable.Rules[:rct.globalTable.NumOfRules],
			rct.cache.globalTable.Rules[:rct.cache.globalTable.NumOfRules]) != 0 {

		change := &TxnChange{
			Table: rct.globalTable,
		}
		changes = append(changes, change)
	}

	return changes
}

// Commit applies the changes into the underlying cache.
func (rct *RendererCacheTxn) Commit() error {
	// Commit local tables.
	for i := 0; i < rct.localTables.numTables; i++ {
		txnTable := rct.localTables.tables[i]
		origTable := rct.cache.localTables.LookupByID(txnTable.ID)

		if origTable != nil {
			if len(txnTable.Pods) == 0 {
				// Local table removed in the transaction.
				rct.cache.localTables.Remove(txnTable)
				rct.cache.Log.WithFields(logging.Fields{
					"table": txnTable,
				}).Debug("Local table was removed in the transaction")
			} else if !txnTable.Pods.Equals(origTable.Pods) {
				rct.cache.Log.WithFields(logging.Fields{
					"table":    txnTable,
					"origPods": origTable.Pods,
					"newPods":  txnTable.Pods,
				}).Debug("Local table was re-assigned to different set of pods in the transaction")
				// Update interfaces.
				for pod := range origTable.Pods {
					if !txnTable.Pods.Has(pod) {
						rct.cache.localTables.UnassignPod(origTable, pod)
					}
				}
				for pod := range txnTable.Pods {
					if !origTable.Pods.Has(pod) {
						rct.cache.localTables.AssignPod(origTable, pod)
					}
				}
				// Copy Private which may have been changed by the cache user.
				origTable.Private = txnTable.Private
			}
		} else {
			if len(txnTable.Pods) != 0 {
				// New local table created in the transaction.
				rct.cache.localTables.Insert(txnTable)
				rct.cache.Log.WithFields(logging.Fields{
					"table": txnTable,
				}).Debug("New local table was created in the transaction")
			}
		}
	}

	// Commit global table.
	if rct.globalTable != nil {
		rct.cache.globalTable = rct.globalTable
	}
	return nil
}

// GetPodConfig returns the configuration of a given pod pending in the transaction
// (applied after the commit).
func (rct *RendererCacheTxn) GetPodConfig(pod podmodel.ID) (podIP *net.IPNet, ingress, egress []*renderer.ContivRule) {
	config, hasConfig := rct.config[pod]
	if !hasConfig {
		return nil, ingress, egress
	}
	return config.podIP, config.ingress, config.egress
}

// IsolatedPods returns the set of IDs of pods that will have a local table assigned
// if the transaction is committed without any additional changes.
func (rct *RendererCacheTxn) IsolatedPods() PodSet {
	isolated := rct.localTables.IsolatedPods()
	// Add isolated pods that are without changes in the transaction.
	for pod := range rct.cache.IsolatedPods() {
		if rct.localTables.LookupByPod(pod) == nil {
			isolated.Add(pod)
		}
	}
	return isolated
}

// GetLocalTableByPod returns the local table that will be assigned to a given pod
// if the transaction is committed without any additional changes.
// Returns nil if the pod will be non-isolated.
func (rct *RendererCacheTxn) GetLocalTableByPod(pod podmodel.ID) *ContivRuleTable {
	table := rct.localTables.LookupByPod(pod)
	if table != nil && table.NumOfRules == 0 {
		return nil /* do not return empty table */
	}
	if table != nil {
		return table
	}
	// table == nil => no change in the transaction
	return rct.cache.GetLocalTableByPod(pod)
}

// GetGlobalTable returns the global table that will be installed if the transaction
// is committed without any additional changes
func (rct *RendererCacheTxn) GetGlobalTable() *ContivRuleTable {
	if rct.globalTable != nil {
		return rct.globalTable
	}
	// globalTable == nil => no change in the transaction
	return rct.cache.globalTable
}

// Generator for ContivRuleTable IDs.
func (rct *RendererCacheTxn) generateListID() string {
	var id string
	for {
		// Generate random suffix, 10 characters long.
		b := make([]byte, 5)
		rand.Read(b)
		id = fmt.Sprintf("%X", b)
		if _, exists := rct.cache.allocatedTableIDs[id]; !exists {
			rct.cache.allocatedTableIDs[id] = struct{}{}
			break
		}
	}
	return id
}
