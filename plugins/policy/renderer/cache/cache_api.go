package cache

import (
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// ContivRuleCacheAPI defines API of a cache used to store Contiv Rules.
// The cache allows renderer to easily calculate the minimal set of changes
// that need to be applied in a given transaction, provided that the target
// network stack supports incremental changes.
type ContivRuleCacheAPI interface {
	NewTxn(resync bool) Txn

	LookupByInterface(ifName string) (rules []*renderer.ContivRuleGroup)
	// TODO: more lookups as needed
}

type Txn interface {
	Update(ifName string, rules []*renderer.ContivRuleGroup) error

	// Changes calculates a minimalistic set of changes prepared in the transaction
	// up to this point. Must be run before Commit().
	Changes() (new, removed, updated []TxnChange)

	// Applies the changes into the underlying cache.
	Commit() error
}

// TxnChange represents change in the ContivRuleCache to be performed
// by a transaction.
type TxnChange struct {
	Group         *renderer.ContivRuleGroup
	OldInterfaces []string // empty for newly added group
	NewInterfaces []string // empty for removed group
}
