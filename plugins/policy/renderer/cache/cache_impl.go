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
	"net"

	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// RendererCache implements RendererCacheAPI.
type RendererCache struct {
	Deps
}

// Deps lists dependencies of RendererCache.
type Deps struct {
	Log logging.Logger
}

// RendererCacheTxn represents a single transaction of RendererCache.
type RendererCacheTxn struct {
	cache *RendererCache
}

/*********************************** CACHE ***********************************/

// Init initializes the cache.
// The caller selects the orientation of the traffic at which the rules are applied
// in the destination network stack.
func (rc *RendererCache) Init(orientation CacheOrientation) error {
	/* TODO */
	return nil
}

// NewTxn starts a new transaction. The changes are reflected in the cache
// only after Commit() is called.
func (rc *RendererCache) NewTxn() Txn {
	/* TODO */
	return nil
}

// Resync completely replaces the existing cache content with the supplied
// data.
func (rc *RendererCache) Resync(tables []*ContivRuleTable) error {
	/* TODO */
	return nil
}

// GetPodConfig returns the current configuration of a given pod
// (as passed through the Txn.Update() method).
func (rc *RendererCache) GetPodConfig(pod podmodel.ID) (podIP *net.IPNet, ingress, egress []*renderer.ContivRule) {
	/* TODO */
	return nil, nil, nil
}

// IsolatedPods returns the set of IDs of all pods that have a local table assigned.
// The term "isolated" is borrowed from K8s, pods become isolated by having
// a NetworkPolicy that selects them.
func (rc *RendererCache) IsolatedPods() PodSet {
	/* TODO */
	return nil
}

// GetLocalTableByPod returns the local table assigned to a given pod.
// Returns nil if the pod has no table assigned (non-isolated).
func (rc *RendererCache) GetLocalTableByPod(pod podmodel.ID) *ContivRuleTable {
	/* TODO */
	return nil
}

// GetGlobalTable returns the global table.
// The function never returns nil but may return table with empty set of rules
// (meaning ALLOW-ALL).
func (rc *RendererCache) GetGlobalTable() *ContivRuleTable {
	/* TODO */
	return nil
}

/************************************ TXN ************************************/

func (rct *RendererCacheTxn) Update(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) {
	/* TODO */
}

// UpdatedPods returns the set of all pods included in the transaction.
func (rct *RendererCacheTxn) UpdatedPods() PodSet {
	/* TODO */
	return nil
}

// Changes calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (rct *RendererCacheTxn) Changes() (changes []*TxnChange) {
	/* TODO */
	return nil
}

// Commit applies the changes into the underlying cache.
func (rct *RendererCacheTxn) Commit() error {
	/* TODO */
	return nil
}

// GetPodConfig returns the configuration of a given pod pending in the transaction
// (applied after the commit).
func (rct *RendererCacheTxn) GetPodConfig(pod podmodel.ID) (podIP *net.IPNet, ingress, egress []*renderer.ContivRule) {
	/* TODO */
	return nil, nil, nil
}

// IsolatedPods returns the set of IDs of pods that will have a local table assigned
// if the transaction is committed without any additional changes.
func (rct *RendererCacheTxn) IsolatedPods() PodSet {
	/* TODO */
	return nil
}

// GetLocalTableByPod returns the local table that will be assigned to a given pod
// if the transaction is committed without any additional changes.
// Returns nil if the pod will be non-isolated.
func (rct *RendererCacheTxn) GetLocalTableByPod(pod podmodel.ID) *ContivRuleTable {
	/* TODO */
	return nil
}

// GetGlobalTable returns the global table that will be installed if the transaction
// is committed without any additional changes
func (rct *RendererCacheTxn) GetGlobalTable() *ContivRuleTable {
	/* TODO */
	return nil
}
