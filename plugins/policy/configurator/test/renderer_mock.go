package test

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
)

// TrafficDirection is one of: INGRESS, EGRESS.
type TrafficDirection int

const (
	// IngressTraffic is the traffic direction from a pod to the vswitch.
	IngressTraffic TrafficDirection = iota

	// EgressTraffic is the traffic direction from the vswitch to a pod.
	EgressTraffic
)

// TrafficAction is one of DENIED, ALLOWED, UNMATCHED, INVALID.
type TrafficAction int

const (
	// DeniedTraffic is returned by the mock renderer when the traffic is blocked.
	DeniedTraffic TrafficAction = iota

	// AllowedTraffic is returned by the mock renderer when the traffic is not blocked.
	AllowedTraffic

	// UnmatchedTraffic is returned by the mock renderer when the traffic is not
	// matched by any rule.
	UnmatchedTraffic

	// InvalidTraffic is returned by the mock renderer when the traffic went
	// through an interface not handled by the renderer.
	InvalidTraffic
)

// MockRenderer is a mock implementation of the PolicyRenderer that allows
// to simulate a traffic and test what the outcome would be with the rendered
// configuration.
type MockRenderer struct {
	Log    logging.Logger
	config map[string]*InterfaceConfig // interface name -> config
}

// MockRendererTxn is a mock implementation for the renderer's transaction.
type MockRendererTxn struct {
	Log      logging.Logger
	renderer *MockRenderer
	resync   bool
	config   map[string]*InterfaceConfig // interface name -> config
}

// InterfaceConfig stores configuration for a single interface.
type InterfaceConfig struct {
	ingress []*renderer.ContivRule
	egress  []*renderer.ContivRule
}

// NewMockRenderer is a constructor for MockRenderer.
func NewMockRenderer(log logging.Logger) *MockRenderer {
	return &MockRenderer{
		Log:    log,
		config: make(map[string]*InterfaceConfig),
	}
}

// NewTxn creates a new mock transaction.
func (mr *MockRenderer) NewTxn(resync bool) renderer.Txn {
	return &MockRendererTxn{
		Log:      mr.Log,
		renderer: mr,
		resync:   resync,
		config:   make(map[string]*InterfaceConfig),
	}
}

// AddInterface tells that the given interface belongs under this renderer.
func (mr *MockRenderer) AddInterface(ifName string) {
	mr.config[ifName] = &InterfaceConfig{
		ingress: []*renderer.ContivRule{},
		egress:  []*renderer.ContivRule{},
	}
}

// HasInterface allows to test what has been set with AddInterface.
func (mr *MockRenderer) HasInterface(ifName string) bool {
	_, has := mr.config[ifName]
	return has
}

// TestTraffic allows to simulate a traffic and test what the outcome would
// be with the rendered configuration.
// The direction is from the vswitch point of view!
func (mr *MockRenderer) TestTraffic(ifName string, direction TrafficDirection, srcIP *net.IP,
	destIP *net.IP, protocol renderer.ProtocolType, srcPort uint16, destPort uint16) TrafficAction {

	config, hasInterface := mr.config[ifName]
	if !hasInterface {
		return InvalidTraffic
	}

	var rules []*renderer.ContivRule
	if direction == IngressTraffic {
		rules = config.ingress
	} else {
		rules = config.egress
	}

	for _, rule := range rules {
		if len(rule.SrcNetwork.IP) > 0 && !rule.SrcNetwork.Contains(*srcIP) {
			continue
		}
		if len(rule.DestNetwork.IP) > 0 && !rule.DestNetwork.Contains(*destIP) {
			continue
		}
		if rule.Protocol != protocol {
			continue
		}
		if rule.SrcPort != 0 && rule.SrcPort != srcPort {
			continue
		}
		if rule.DestPort != 0 && rule.DestPort != destPort {
			continue
		}
		// Match!
		if rule.Action == renderer.ActionPermit {
			return AllowedTraffic
		}
		return DeniedTraffic
	}
	return UnmatchedTraffic
}

// Render just stores config to be rendered.
func (mrt *MockRendererTxn) Render(ifName string, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) renderer.Txn {
	mrt.Log.WithFields(logging.Fields{
		"ifName":  ifName,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("Mock RendererTxn Render()")
	mrt.config[ifName] = &InterfaceConfig{ingress: ingress, egress: egress}
	return mrt
}

// Commit runs mock rendering. The configuration is just stored in-memory.
func (mrt *MockRendererTxn) Commit() error {
	for ifName := range mrt.config {
		if !mrt.renderer.HasInterface(ifName) {
			return fmt.Errorf("unhandled interface: %s", ifName)
		}
	}
	if mrt.resync {
		mrt.renderer.config = mrt.config
	} else {
		for ifName, config := range mrt.config {
			mrt.renderer.config[ifName] = config
		}
	}
	return nil
}
