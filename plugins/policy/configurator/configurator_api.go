package configurator

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// PolicyConfiguratorAPI defines the API of Policy Configurator.
// For a given pod, the configurator translates a list of Contiv Policies into
// Contiv Rules (n-tuples with the most basic policy rule definition) and applies
// them into the target vswitch via registered renderers.
// Allows to register multiple renderers for different network stacks.
// For the best performance, creates a shortest possible sequence of rules
// that implement a given policy. Rules passed downwards are also logically
// grouped (see godoc for ContivRuleGroup) to allow renderers further minimize
// the size of the applied configuration by sharing and re-ordering rules
// between interfaces (the level of available optimizations depends on what
// the target stack actually supports).
type PolicyConfiguratorAPI interface {
	// RegisterRenderer registers renderer that will render rules for pods
	// that contain a given <label> (they are expected to be in a different
	// network stack)
	RegisterRenderer(label string, renderer renderer.PolicyRendererAPI) error

	// RegisterDefaultRenderer registers the renderer used for pods not included
	// by any other registered renderer.
	RegisterDefaultRenderer(renderer renderer.PolicyRendererAPI) error

	// NewTxn starts a new transaction. The re-configuration executes only
	// after Commit() is called.
	// If <resync> is enabled, the supplied configuration will completely
	// replace the existing one, otherwise pods not mentioned in the transaction
	// are left unchanged.
	NewTxn(resync bool) Txn
}

type Txn interface {
	// Configure applies the set of policies for a given pod.
	// The existing policies are replaced.
	Configure(pod podmodel.ID, policies []*ContivPolicy) Txn
	Commit() error
}

// ContivPolicy is a less-abstract, free of indirect references representation
// of K8s Network Policy.
// It has expanded:
//   - namespaces
//   - port names
//   - label selectors
// IP network addresses are converted to net.IP.
// It is produced in this form and passed to Configurator by Policy Processor.
type ContivPolicy struct {
	ID      policymodel.ID
	Type    PolicyType
	Matches []Match
}

type Match struct {
	Type     MatchType

	// Layer 3: Pods and IPBlocks are ORed.
	Pods     []podmodel.ID
	IPBlocks []IPBlock

	// Layer 4
	Ports    []Port
}

type PolicyType int

const (
	POLICY_INGRESS PolicyType = iota
	POLICY_EGRESS
	POLICY_ALL
)

type MatchType int

const (
	MATCH_INGRESS MatchType = iota
	MATCH_EGRESS
)

type ProtocolType int

const (
	TCP ProtocolType = iota
	UDP
)

type Port struct {
	Protocol ProtocolType
	Number   int16
}

type IPBlock struct {
	Network net.IPNet
	Except  []net.IPNet
}
