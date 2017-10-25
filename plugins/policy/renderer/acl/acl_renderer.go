package acl

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
)

// Renderer renders Contiv Rules into VPP ACLs.
// ACLs are installed into VPP by the aclplugin from vpp-agent.
// The configuration changes are transported into aclplugin via localclient.
type Renderer struct {
	Deps
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log   logging.Logger
	Cache cache.ContivRuleCacheAPI
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	cacheTxn cache.Txn
	resync   bool
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. Rollback is not yet supported however.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one. Otherwise, the change is performed incrementally,
// i.e. interfaces not mentioned in the transaction are left unaffected.
func (ar *Renderer) NewTxn(resync bool) *RendererTxn {
	return &RendererTxn{cacheTxn: ar.Cache.NewTxn(resync), resync: resync}
}

// Render applies the set of ingress & egress rules for a given VPP interface.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(ifName string, ingress []renderer.ContivRule, egress []renderer.ContivRule) *RendererTxn {
	art.cacheTxn.Update(ifName, ingress, egress)
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied as one transaction via the
// localclient.
func (art *RendererTxn) Commit() error {
	// ingress,egress := art.cacheTxn.Changes()
	// TODO: process and apply changes via localclient as one transaction
	// art.cacheTxn.Commit()
	return nil
}
