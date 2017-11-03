package configurator

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// PolicyConfiguratorAPI defines the API of Policy Configurator.
// For a given pod, the configurator translates a set of Contiv Policies into
// ingress and egress lists of Contiv Rules (n-tuples with the most basic policy
// rule definition) and applies them into the target vswitch via registered
// renderers. Allows to register multiple renderers for different network stacks.
// For the best performance, creates a shortest possible sequence of rules
// that implement a given policy. Furthermore, to allow renderers share a list
// of ingress or egress rules between interfaces, the same set of policies
// always results in the same list of rules.
type PolicyConfiguratorAPI interface {
	// RegisterRenderer registers renderer that will render rules for pods
	// that contain a given <label> (they are expected to be in a separate
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

// Txn defines the API of PolicyConfigurator transaction.
type Txn interface {
	// Configure applies the set of policies for a given pod.
	// The existing policies are replaced.
	// The order of policies is not important (it is a set).
	Configure(pod podmodel.ID, policies []*ContivPolicy) Txn

	// Commit proceeds with the reconfiguration.
	Commit() error
}

// ContivPolicy is a less-abstract, free of indirect references representation
// of K8s Network Policy.
// It has:
//   - expanded namespaces
//   - translated port names
//   - evaluated label selectors
//   - IP network addresses converted to net.IP
// It is produced in this form and passed to Configurator by Policy Processor.
// Traffic matched by a Contiv policy should by ALLOWED. Traffic not matched
// by any policy from a **non-empty** set of policies assigned
// to the source/destination pod should be DENIED.
type ContivPolicy struct {
	// ID should uniquely identify policy across all namespaces.
	ID policymodel.ID

	// Type selects the rule types that the network policy relates to.
	Type PolicyType

	// Matches is an array of Match-es: predicates that select a subset of the
	// traffic to be ALLOWED.
	Matches []Match
}

// Match is a predicate that select a subset of the traffic.
type Match struct {
	// Type selects the direction of the traffic.
	Type MatchType

	// Layer 3: destinations (egress) / sources (ingress)
	// If both arrays are empty or nil, then this predicate matches all
	// sources(ingress) / destinations(egress).
	// If one or both arrays are non-empty, then this predicate applies
	// to a given traffic only if the traffic matches at least one item in
	// one of the lists.
	Pods     []podmodel.ID
	IPBlocks []IPBlock

	// Layer 4: destination ports
	// If the array is empty or nil, then this predicate matches all ports
	// (traffic not restricted by port).
	// If the array is non-empty, then this applies to a given traffic only
	// if the traffic matches at least one port in the list.
	Ports []Port
}

// PolicyType selects the rule types that the network policy relates to.
type PolicyType int

const (
	// PolicyIngress tells policy to apply to ingress only.
	PolicyIngress PolicyType = iota

	// PolicyEgress tells policy to apply to egress only.
	PolicyEgress

	// PolicyAll tells policy to apply to both traffic directions.
	PolicyAll
)

// MatchType selects the direction of the traffic to apply a Match to.
// The direction is from the Pod point of view!
type MatchType int

const (
	// MatchIngress matches ingress traffic.
	MatchIngress MatchType = iota

	// MatchEgress matches egress traffic.
	MatchEgress
)

// ProtocolType is either TCP or UDP.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota

	// UDP protocol.
	UDP
)

// Port represent a TCP or UDP port.
// Number=0 represents all ports for a given protocol.
type Port struct {
	Protocol ProtocolType
	Number   uint16
}

// IPBlock selects a particular CIDR with possible exceptions.
type IPBlock struct {
	Network net.IPNet
	Except  []net.IPNet
}
