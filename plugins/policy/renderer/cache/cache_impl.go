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

	// configuration
	orientation Orientation

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
	localTables    *LocalTables
	globalTable    *ContivRuleTable
	upToDateTables bool

	// updated pod configuration
	config Config
}

// Config is used to store snapshot of the configuration as received through
// RendererCacheTxn.Update().
type Config map[podmodel.ID]*PodConfig

// AllocatedIDs represents a set of all allocated IDs.
type AllocatedIDs map[string]struct{}

/*********************************** CACHE ***********************************/

// Init initializes the cache.
// The caller selects the orientation of the traffic at which the rules are applied
// in the destination network stack.
func (rc *RendererCache) Init(orientation Orientation) {
	rc.orientation = orientation
	rc.Flush()
}

// Flush completely wipes out the cache content.
func (rc *RendererCache) Flush() {
	rc.localTables = NewLocalTables(rc.Log)
	rc.globalTable = NewContivRuleTable(GlobalTableID)
	rc.allocatedTableIDs = make(AllocatedIDs)
	rc.config = make(Config)
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
	config := make(Config)
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
		// The configuration cannot be reconstructed, but at least the set of all pods
		// can be.
		for podID := range table.Pods {
			_, multipleTables := config[podID]
			if multipleTables {
				return fmt.Errorf("pod assigned to multiple local tables: %s", podID)
			}
			config[podID] = &PodConfig{}
		}
	}

	// Replace the cache content.
	rc.allocatedTableIDs = allocatedTableIDs
	rc.localTables = localTables
	rc.globalTable = globalTable
	rc.config = config
	return nil
}

// GetPodConfig returns the current configuration of a given pod
// (as passed through the Txn.Update() method).
// Method returns nil if the given pod is not tracked by the cache.
func (rc *RendererCache) GetPodConfig(pod podmodel.ID) *PodConfig {
	config, hasConfig := rc.config[pod]
	if !hasConfig {
		return nil
	}
	return config
}

// GetAllPods returns the set of all pods currently tracked by the cache.
func (rc *RendererCache) GetAllPods() PodSet {
	pods := NewPodSet()
	for podID := range rc.config {
		pods.Add(podID)
	}
	return pods
}

// GetIsolatedPods returns the set of IDs of all pods that have a local table assigned.
// The term "isolated" is borrowed from K8s, pods become isolated by having
// a NetworkPolicy that selects them.
func (rc *RendererCache) GetIsolatedPods() PodSet {
	return rc.localTables.GetIsolatedPods()
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

// Update changes the configuration of Contiv rules for a given pod.
func (rct *RendererCacheTxn) Update(pod podmodel.ID, podConfig *PodConfig) {
	rct.config[pod] = podConfig
	rct.upToDateTables = false
}

// GetUpdatedPods returns the set of all pods included in the transaction.
func (rct *RendererCacheTxn) GetUpdatedPods() PodSet {
	updated := NewPodSet()
	for pod := range rct.config {
		updated.Add(pod)
	}
	return updated
}

// GetRemovedPods returns the set of all pods that will be removed by the transaction.
func (rct *RendererCacheTxn) GetRemovedPods() PodSet {
	removed := NewPodSet()
	for pod, podCfg := range rct.config {
		if podCfg.Removed {
			removed.Add(pod)
		}
	}
	return removed
}

// GetChanges calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (rct *RendererCacheTxn) GetChanges() (changes []*TxnChange) {
	if !rct.upToDateTables {
		rct.refreshTables()
	}
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
	if !rct.upToDateTables {
		rct.refreshTables()
	}
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
	if rct.globalTable != nil &&
		compareRuleLists(
			rct.globalTable.Rules[:rct.globalTable.NumOfRules],
			rct.cache.globalTable.Rules[:rct.cache.globalTable.NumOfRules]) != 0 {
		rct.cache.globalTable = rct.globalTable
	}

	// Commit configuration.
	for podID, podCfg := range rct.config {
		if podCfg.Removed {
			if _, exists := rct.cache.config[podID]; exists {
				delete(rct.cache.config, podID)
			}
			rct.cache.localTables.UnassignPod(nil, podID)
		} else {
			rct.cache.config[podID] = podCfg
		}
	}
	return nil
}

// GetPodConfig returns the configuration of a given pod either pending in the transaction
// or taken from the cache if the pod was not updated.
func (rct *RendererCacheTxn) GetPodConfig(pod podmodel.ID) *PodConfig {
	config, hasConfig := rct.config[pod]
	if !hasConfig {
		return rct.cache.GetPodConfig(pod)
	}
	return config
}

// GetAllPods returns the set of all pods that will have configuration tracked by the cache if the
// transaction is committed without any additional changes.
func (rct *RendererCacheTxn) GetAllPods() PodSet {
	pods := rct.cache.GetAllPods()
	for podID, podCfg := range rct.config {
		if !podCfg.Removed {
			pods.Add(podID)
		} else {
			pods.Remove(podID)
		}
	}
	return pods
}

// GetIsolatedPods returns the set of IDs of pods that will have a local table assigned
// if the transaction is committed without any additional changes.
func (rct *RendererCacheTxn) GetIsolatedPods() PodSet {
	if !rct.upToDateTables {
		rct.refreshTables()
	}
	isolated := rct.localTables.GetIsolatedPods()
	// Add isolated pods that are without changes in the transaction.
	for pod := range rct.cache.GetIsolatedPods() {
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
	if !rct.upToDateTables {
		rct.refreshTables()
	}
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
	if !rct.upToDateTables {
		rct.refreshTables()
	}
	if rct.globalTable != nil {
		return rct.globalTable
	}
	// globalTable == nil => no change in the transaction
	return rct.cache.globalTable
}

// refreshTables re-calculates local tables as well as the global one to reflect
// all the changes included in the transaction up to this point.
func (rct *RendererCacheTxn) refreshTables() {
	// First refresh local tables of all pods (including the to-be-removed ones).
	for podID := range rct.GetAllPods().Join(rct.GetRemovedPods()) {
		podCfg := rct.GetPodConfig(podID)
		newTable := rct.buildLocalTable(podID, podCfg)

		// Add pod's original table into the transaction if is not already there.
		origTable := rct.cache.localTables.LookupByPod(podID)
		if origTable != nil && rct.localTables.LookupByID(origTable.ID) == nil {
			// Create a copy in the transaction (only shallow copy of rules).
			updatedTable := &ContivRuleTable{
				ID:         origTable.ID,
				Type:       origTable.Type,
				Rules:      origTable.Rules,
				NumOfRules: origTable.NumOfRules,
				Pods:       origTable.Pods.Copy(),
				Private:    origTable.Private,
			}
			rct.localTables.Insert(updatedTable)
		}

		// Check if the table was already created inside the transaction.
		txnTable := rct.localTables.LookupByRules(newTable.Rules[:newTable.NumOfRules])
		if txnTable != nil {
			rct.localTables.AssignPod(txnTable, podID)
			// Throw away the local table that was just built.
			delete(rct.cache.allocatedTableIDs, newTable.ID)
			continue
		}

		// Check if the table exists in the cache but not in the transaction.
		cacheTable := rct.cache.localTables.LookupByRules(newTable.Rules[:newTable.NumOfRules])
		if cacheTable != nil {
			// Create a copy in the transaction with added pod (only shallow copy of rules).
			updatedTable := &ContivRuleTable{
				ID:         cacheTable.ID,
				Type:       cacheTable.Type,
				Rules:      cacheTable.Rules,
				NumOfRules: cacheTable.NumOfRules,
				Pods:       cacheTable.Pods.Copy(),
				Private:    cacheTable.Private,
			}
			updatedTable.Pods.Add(podID)
			rct.localTables.Insert(updatedTable)
			// Throw away the local table that was just built.
			delete(rct.cache.allocatedTableIDs, newTable.ID)
			continue
		}

		// Add the newly created local table.
		rct.localTables.Insert(newTable)
	}

	// Finally rebuild the global table.
	rct.rebuildGlobalTable()

	rct.upToDateTables = true
	rct.cache.Log.WithFields(logging.Fields{
		"local":  rct.localTables,
		"global": rct.globalTable,
	}).Debug("tables in transaction were refreshed")
}

// buildLocalTable builds the local table corresponding to the given pod
// for the current state of the transaction.
func (rct *RendererCacheTxn) buildLocalTable(dstPodID podmodel.ID, dstPodCfg *PodConfig) *ContivRuleTable {
	table := NewContivRuleTable(rct.generateTableID())
	table.Pods.Add(dstPodID)
	if dstPodCfg.Removed {
		// For removed pod return empty table.
		return table
	}

	// Just copy the rules that already have the desired cache orientation.
	var rules []*renderer.ContivRule
	if rct.cache.orientation == EgressOrientation {
		rules = dstPodCfg.Egress
	} else {
		rules = dstPodCfg.Ingress
	}
	for _, rule := range rules {
		table.InsertRule(rule.Copy())
	}

	// Combine rules with the opposite direction of every pod on the node.
	for srcPodID := range rct.GetAllPods() {
		srcPodCfg := rct.GetPodConfig(srcPodID)
		rct.installLocalRules(table, dstPodCfg, srcPodCfg)
	}

	return table
}

// installLocalRules takes rules of the source pod (srcPodCfg) with the opposite
// orientation wrt. the cache, and combines them with the rules in the local table (dstTable)
// belonging to the destination pod (dstPodCfg).
// The ingress with egress is combined such that the resulting rules all follow
// the cache orientation while the original semantic of policies between the source
// and the destination pod is maintained.
func (rct *RendererCacheTxn) installLocalRules(dstTable *ContivRuleTable, dstPodCfg *PodConfig, srcPodCfg *PodConfig) {
	// Determine the set of accessible ports from the source pod point of view.
	var srcTCP, srcUDP Ports
	if rct.cache.orientation == EgressOrientation {
		srcTCP, srcUDP = getAllowedIngressPorts(dstPodCfg.PodIP, srcPodCfg.Ingress)
	} else {
		srcTCP, srcUDP = getAllowedEgressPorts(dstPodCfg.PodIP, srcPodCfg.Egress)
	}

	// Determine the set of accessible ports from the destination pod point of view.
	var dstTCP, dstUDP Ports
	if rct.cache.orientation == EgressOrientation {
		dstTCP, dstUDP = getAllowedEgressPorts(srcPodCfg.PodIP, dstPodCfg.Egress)
	} else {
		dstTCP, dstUDP = getAllowedIngressPorts(srcPodCfg.PodIP, dstPodCfg.Ingress)
	}

	// Intersect TCP ports
	if !dstTCP.IsSubsetOf(srcTCP) {
		allowedTCP := dstTCP.Intersection(srcTCP) /* intersection is certainly not AnyPort */
		rct.installAllowedPorts(dstTable, srcPodCfg.PodIP, allowedTCP, renderer.TCP)
	}

	// Intersect UDP ports
	if !dstUDP.IsSubsetOf(srcUDP) {
		allowedUDP := dstUDP.Intersection(srcUDP) /* intersection is certainly not AnyPort */
		rct.installAllowedPorts(dstTable, srcPodCfg.PodIP, allowedUDP, renderer.UDP)
	}
}

// installAllowedPorts modifies the table content such that the source pod will
// be able to communicate with the table owner only on the selected allowed ports
// of a given protocol with the rest being blocked.
func (rct *RendererCacheTxn) installAllowedPorts(dstTable *ContivRuleTable, srcPodIP *net.IPNet, allowedPorts Ports, protocol renderer.ProtocolType) {
	// cleanup TCP rule subtree with the root node:
	// 	(egress orientation)  srcIP:0 -> 0/0:0
	// 	(ingress orientation) 0/0:0   -> srcIP:0
	dstTable.RemoveByPredicate(func(rule *renderer.ContivRule) bool {
		if rule.Protocol != protocol {
			return false
		}
		var ipAddr *net.IPNet
		if rct.cache.orientation == EgressOrientation {
			ipAddr = rule.SrcNetwork
		} else {
			ipAddr = rule.DestNetwork
		}
		if len(ipAddr.IP) == 0 {
			return false
		}
		ones, bits := ipAddr.Mask.Size()
		if ones != bits || !ipAddr.IP.Equal(srcPodIP.IP) {
			return false
		}
		return true
	})

	// Add explicit rule for each allowed port from the intersection
	// of ingress with egress.
	for port := range allowedPorts {
		newRule := &renderer.ContivRule{
			Action:      renderer.ActionPermit,
			SrcNetwork:  &net.IPNet{},
			DestNetwork: &net.IPNet{},
			SrcPort:     AnyPort,
			DestPort:    port,
			Protocol:    protocol,
		}
		if rct.cache.orientation == EgressOrientation {
			newRule.SrcNetwork = srcPodIP
		} else {
			newRule.DestNetwork = srcPodIP
		}
		dstTable.InsertRule(newRule)
	}

	// Add the "deny-the-rest" rule.
	newRule := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		SrcPort:     AnyPort,
		DestPort:    AnyPort,
		Protocol:    protocol,
	}
	if rct.cache.orientation == EgressOrientation {
		newRule.SrcNetwork = srcPodIP
	} else {
		newRule.DestNetwork = srcPodIP
	}
	dstTable.InsertRule(newRule)
}

// rebuildGlobalTable rebuilds the content of the global table for the current state
// of the transaction.
func (rct *RendererCacheTxn) rebuildGlobalTable() {
	rct.globalTable = NewContivRuleTable(GlobalTableID)

	// For every pod, take the deny-rules with the opposite orientation wrt. the cache
	// and install them into the global table.
	for podID := range rct.GetAllPods() {
		podCfg := rct.GetPodConfig(podID)
		rct.installGlobalRules(podCfg)
	}

	if rct.globalTable.NumOfRules > 0 {
		// Default action is to allow everything.
		ruleTCPAny := &renderer.ContivRule{
			Action:      renderer.ActionPermit,
			SrcNetwork:  &net.IPNet{},
			DestNetwork: &net.IPNet{},
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    0,
		}
		ruleUDPAny := &renderer.ContivRule{
			Action:      renderer.ActionPermit,
			SrcNetwork:  &net.IPNet{},
			DestNetwork: &net.IPNet{},
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    0,
		}
		rct.globalTable.InsertRule(ruleTCPAny)
		rct.globalTable.InsertRule(ruleUDPAny)
	}
}

// installGlobalRules takes the rules of the given pod with the opposite orientation
// wrt. the cache and installs them into the global table.
func (rct *RendererCacheTxn) installGlobalRules(podCfg *PodConfig) {
	var rules []*renderer.ContivRule
	if rct.cache.orientation == EgressOrientation {
		rules = podCfg.Ingress
	} else {
		rules = podCfg.Egress
	}
	for _, rule := range rules {
		ruleCopy := rule.Copy() /* do not change the original config */
		if rct.cache.orientation == EgressOrientation {
			ruleCopy.SrcNetwork = podCfg.PodIP
		} else {
			ruleCopy.DestNetwork = podCfg.PodIP
		}
		rct.globalTable.InsertRule(ruleCopy)
	}
}

// Generator for ContivRuleTable IDs.
func (rct *RendererCacheTxn) generateTableID() string {
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
