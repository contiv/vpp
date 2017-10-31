package cache

import (
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
)

// ContivRuleCache implements ContivRuleCacheAPI.
type ContivRuleCache struct {
	Deps
}

// Deps lists dependencies of ContivRuleCache.
type Deps struct {
	Log logging.Logger
}

// ContivRuleCacheTxn represents a single transaction of ContivRuleCache.
type ContivRuleCacheTxn struct {
	resync bool
}

// Init initializes the ContivRule Cache.
func (crc *ContivRuleCache) Init() error {
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. If <resync> is enabled, the supplied configuration will completely
// replace the existing one, otherwise pods not mentioned in the transaction
// are left unchanged.
func (crc *ContivRuleCache) NewTxn(resync bool) Txn {
	return &ContivRuleCacheTxn{resync: resync}
}

// LookupByInterface returns rules assigned to a given interface grouped
// into lists by the traffic direction. Interfaces with equal ingress and/or
// egress configuration will share the same lists (same IDs).
func (crc *ContivRuleCache) LookupByInterface(ifName string) (ingress, egress *ContivRuleList) {
	return nil, nil
}

// Update changes the list of rules for a given interface.
// The change is applied into the cache during commit.
// Run Changes() before Commit() to learn the set of pending updates (merged
// to minimal diff).
func (crct *ContivRuleCacheTxn) Update(ifName string, ingress []renderer.ContivRule, egress []renderer.ContivRule) error {
	return nil
}

// Changes calculates a minimalistic set of changes prepared in the transaction
// up to this point.
// Must be run before Commit().
func (crct *ContivRuleCacheTxn) Changes() (ingress, egress []TxnChange) {
	return nil, nil
}

// Commit applies the changes into the underlying cache.
func (crct *ContivRuleCacheTxn) Commit() error {
	return nil
}
