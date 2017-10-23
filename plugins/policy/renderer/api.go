package renderer

import "net"

// PolicyRendererAPI defines the API of Policy Renderer.
// Policy Renderer implements rendering of Contiv rules for a specific network
// stack. How the rules are actually installed is up to the implementation.
// The interface is used to plug the renderer into the layer above,
// which is Policy Configurator.
type PolicyRendererAPI interface {
	// NewTxn starts a new transaction. The rendering should execute only after
	// Commit() is called. Ideally, the transaction should support rollback
	// to recover from an in-progress fail.
	// If <resync> is enabled, the supplied configuration should completely
	// replace the existing one. Otherwise, perform the changes incrementally,
	// i.e. interfaces not mentioned in the transaction should remain untouched.
	NewTxn(resync bool) Txn
}

type Txn interface {
	// Render applies the set of rules for a given interface. The existing rules
	// are replaced. ContivRuleCache can be used to calculate the minimal diff.
	Render(ifName string, rules []*ContivRuleGroup) Txn

	// Commit proceeds with the rendering. The changes are propagated into
	// the destination network stack.
	Commit() error
}

// ContivRuleGroup logically groups a list of Contiv Rules. Rules of the same
// group are logically related: they are created and removed together and often
// shared between interfaces. If the destination network stack supports it,
// the renderer may install them as one higher-level policy with multiple rules
// and minimize the size of the configuration.
// The order of rules inside a group must be preserved.
// Furthermore, rules of higher priority group must precede those from lower
// priority groups. However, the order between groups of the same priority can
// be arbitrary.
type ContivRuleGroup struct {
	// ID is unique for a pod. Typically it is the policy ID from which the rules
	// where generated. But there are also some special groups for "ip-blocks"
	// and deny-all rules.
	ID       string

	// Priority is used to order rules between groups.
	// Lower the number higher the priority is.
	// Rules of higher priority group must precede those from lower priority
	// groups.
	Priority int

	// Rules is a list of rules in the group.
	// The order of rules inside a group must be preserved.
	Rules    []ContivRule
}

// ContivRule is an n-tuple with the most basic policy rule definition that the
// destination network stack must support.
type ContivRule struct {
	ID          string
	Type        RuleType
	Action      ActionType
	SrcNetwork  net.IPNet
	DestNetwork net.IPNet
	Protocol    ProtocolType
	SrcPort     int16
	DstPort     int16
}

type RuleType int

const (
	RULE_INGRESS RuleType = iota
	RULE_EGRESS
)

type ActionType int

const (
	ACTION_DENY ActionType = iota
	ACTION_PERMIT
)

type ProtocolType int

const (
	TCP ProtocolType = iota
	UDP
)

