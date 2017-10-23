package configurator

import (
	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"

	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

type PolicyConfigurator struct {
	ConfiguratorDeps
}

type ConfiguratorDeps struct {
	Log   logging.Logger
	Cache cache.PolicyCacheAPI
}

type PolicyConfiguratorTxn struct {
	resync bool
}

func (pc *PolicyConfigurator) Init() error {
	return nil
}

func (pc *PolicyConfigurator) RegisterRenderer(label string, renderer renderer.PolicyRendererAPI) error {
	return nil
}

func (pc *PolicyConfigurator) RegisterDefaultRenderer(renderer renderer.PolicyRendererAPI) error {
	return nil
}

func (pc *PolicyConfigurator) Close() error {
	return nil
}

func (pc *PolicyConfigurator) NewTxn(resync bool) *PolicyConfiguratorTxn {
	return &PolicyConfiguratorTxn{resync: resync}
}

func (pct *PolicyConfiguratorTxn) Configure(pod podmodel.ID, policies []*ContivPolicy) *PolicyConfiguratorTxn {
	return pct
}

func (pct *PolicyConfiguratorTxn) Commit() error {
	return nil
}
