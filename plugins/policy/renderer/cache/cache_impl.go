package cache

import (
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
)

type ContivRuleCache struct {
}

type ContivRuleCacheDeps struct {
	Log logging.Logger
}

type ContivRuleCacheTxn struct {
	resync bool
}

func (crc *ContivRuleCache) NewTxn(resync bool) *ContivRuleCacheTxn {
	return &ContivRuleCacheTxn{resync: resync}
}

func (crc *ContivRuleCache) LookupByInterface(ifName string) (rules []*renderer.ContivRuleGroup) {
	return nil
}

func (crct *ContivRuleCacheTxn) Update(ifName string, rules []*renderer.ContivRuleGroup) error {
	return nil
}

func (crct *ContivRuleCacheTxn) Changes() (new, removed, updated []TxnChange) {
	return nil, nil, nil
}

func (crct *ContivRuleCacheTxn) Commit() error {
	return nil
}
