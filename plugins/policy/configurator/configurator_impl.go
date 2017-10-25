package configurator

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"

	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// PolicyConfigurator translates a set of Contiv Policies into ingress and
// egress lists of Contiv Rules (n-tuples with the most basic policy rule
// definition) and applies them into the target vswitch via registered
// renderers. Allows to register multiple renderers for different network stacks.
// For the best performance, creates a shortest possible sequence of rules
// that implement a given policy. Furthermore, to allow renderers share a list
// of ingress or egress rules between interfaces, the same set of policies
// always results in the same list of rules.
type PolicyConfigurator struct {
	Deps
}

// Deps lists dependencies of PolicyConfigurator.
type Deps struct {
	Log    logging.Logger
	Cache  cache.PolicyCacheAPI
	Contiv *contiv.Plugin /* for GetIfName() */
}

// PolicyConfiguratorTxn represents a single transaction of policy configurator.
type PolicyConfiguratorTxn struct {
	resync bool
}

// Init initializes policy configurator.
func (pc *PolicyConfigurator) Init() error {
	return nil
}

// RegisterRenderer registers renderer that will render rules for pods that
// contain a given <label> (they are expected to be in a separate network stack).
func (pc *PolicyConfigurator) RegisterRenderer(label string, renderer renderer.PolicyRendererAPI) error {
	return nil
}

// RegisterDefaultRenderer registers the renderer used for pods not included
// by any other registered renderer.
func (pc *PolicyConfigurator) RegisterDefaultRenderer(renderer renderer.PolicyRendererAPI) error {
	return nil
}

// Close deallocates resource held by the configurator.
func (pc *PolicyConfigurator) Close() error {
	return nil
}

// NewTxn starts a new transaction. The re-configuration executes only after
// Commit() is called. If <resync> is enabled, the supplied configuration will
// completely replace the existing one, otherwise pods not mentioned in the
// transaction are left unchanged.
func (pc *PolicyConfigurator) NewTxn(resync bool) *PolicyConfiguratorTxn {
	return &PolicyConfiguratorTxn{resync: resync}
}

// Configure applies the set of policies for a given pod. The existing policies
// are replaced. The order of policies is not important (it is a set).
func (pct *PolicyConfiguratorTxn) Configure(pod podmodel.ID, policies []*ContivPolicy) *PolicyConfiguratorTxn {
	return pct
}

// Commit proceeds with the reconfiguration.
func (pct *PolicyConfiguratorTxn) Commit() error {
	return nil
}
