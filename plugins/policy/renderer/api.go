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
	// i.e. interfaces not mentioned in the transaction should remain unaffected.
	NewTxn(resync bool) Txn
}

// Txn defines API of PolicyRenderer transaction.
type Txn interface {
	// Render applies the set of ingress & egress rules for a given interface.
	// The existing rules are replaced.
	// ContivRuleCache can be used to calculate the minimal diff and find
	// interfaces with equivalent ingress and/or egress configuration.
	Render(ifName string, ingress []ContivRule, egress []ContivRule) Txn

	// Commit proceeds with the rendering. The changes are propagated into
	// the destination network stack.
	Commit() error
}

// ContivRule is an n-tuple with the most basic policy rule definition that the
// destination network stack must support.
type ContivRule struct {
	// ID uniquely identifies the rule within the list of ingress or egress
	// rules.
	ID string

	// Action to perform when traffic matches.
	Action ActionType

	// L3
	SrcNetwork  net.IPNet // empty/nil = match all
	DestNetwork net.IPNet // empty/nil = match all

	// L4
	Protocol ProtocolType
	SrcPort  int16 // 0 = match all
	DstPort  int16 // 0 = match all
}

// ActionType is either DENY or PERMIT.
type ActionType int

const (
	// ActionDeny tells the policy engine to block the matching traffic.
	ActionDeny ActionType = iota

	// ActionPermit tells the policy engine to block the matching traffic.
	ActionPermit
)

// ProtocolType is either TCP or UDP.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota

	// UDP protocol.
	UDP
)
