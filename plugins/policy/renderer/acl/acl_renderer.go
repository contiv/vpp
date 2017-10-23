package acl

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
)

type AclRenderer struct {
	AclRendererDeps
}

type AclRendererDeps struct {
	Log   logging.Logger
	Cache cache.ContivRuleCacheAPI
}

type AclRendererTxn struct {
	cacheTxn cache.Txn
}

func (ar *AclRenderer) NewTxn(resync bool) *AclRendererTxn {
	return &AclRendererTxn{cacheTxn: ar.Cache.NewTxn(resync)}
}

func (art *AclRendererTxn) Render(ifName string, rules []*renderer.ContivRuleGroup) *AclRendererTxn {
	art.cacheTxn.Update(ifName, rules)
	return art
}

func (art *AclRendererTxn) Commit() error {
	// new, removed, change := art.cacheTxn.Changes()
	// TODO: process changes
	// art.cacheTxn.Commit()
	return nil
}
