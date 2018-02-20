package renderer

import (
	"net"

	"sync"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
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
)

// MockRenderer is a mock implementation of the PolicyRenderer that allows
// to simulate a traffic and test what the outcome would be with the rendered
// configuration.
type MockRenderer struct {
	lock   sync.Mutex
	name   string
	Log    logging.Logger
	config map[podmodel.ID]*PodConfig // Pod ID -> config
}

// MockRendererTxn is a mock implementation for the renderer's transaction.
type MockRendererTxn struct {
	Log      logging.Logger
	renderer *MockRenderer
	resync   bool
	config   map[podmodel.ID]*PodConfig // Pod ID -> config
}

// PodConfig stores configuration for a single pod.
type PodConfig struct {
	ip      *net.IPNet
	ingress []*renderer.ContivRule
	egress  []*renderer.ContivRule
}

// NewMockRenderer is a constructor for MockRenderer.
func NewMockRenderer(name string, log logging.Logger) *MockRenderer {
	return &MockRenderer{
		name:   name,
		Log:    log,
		config: make(map[podmodel.ID]*PodConfig),
	}
}

// NewTxn creates a new mock transaction.
func (mr *MockRenderer) NewTxn(resync bool) renderer.Txn {
	return &MockRendererTxn{
		Log:      mr.Log,
		renderer: mr,
		resync:   resync,
		config:   make(map[podmodel.ID]*PodConfig),
	}
}

// GetPodIP returns the pod IP + masklen as provided by the configurator.
func (mr *MockRenderer) GetPodIP(pod podmodel.ID) (ip string, masklen int) {
	mr.Log.WithFields(logging.Fields{
		"renderer": mr.name,
	}).Debug("Mock RendererTxn GetPodIP()")

	mr.lock.Lock()
	defer mr.lock.Unlock()
	config, hasInterface := mr.config[pod]
	if !hasInterface {
		return "", 0
	}
	if config.ip == nil {
		return "", 0
	}
	masklen, _ = config.ip.Mask.Size()
	return config.ip.IP.String(), masklen
}

// TestTraffic allows to simulate a traffic and test what the outcome would
// be with the rendered configuration.
// The direction is from the vswitch point of view!
func (mr *MockRenderer) TestTraffic(pod podmodel.ID, direction TrafficDirection, srcIP *net.IP,
	destIP *net.IP, protocol renderer.ProtocolType, srcPort uint16, destPort uint16) TrafficAction {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	config, hasInterface := mr.config[pod]
	if !hasInterface {
		return UnmatchedTraffic
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
func (mrt *MockRendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule, removed bool) renderer.Txn {
	mrt.Log.WithFields(logging.Fields{
		"renderer": mrt.renderer.name,
		"pod":      pod,
		"IP":       podIP,
		"ingress":  ingress,
		"egress":   egress,
		"removed":  removed,
	}).Debug("Mock RendererTxn Render()")
	if removed {
		if _, hasPod := mrt.config[pod]; hasPod {
			delete(mrt.config, pod)
		}
	} else {
		mrt.config[pod] = &PodConfig{ip: podIP, ingress: ingress, egress: egress}
	}
	return mrt
}

// Commit runs mock rendering. The configuration is just stored in-memory.
func (mrt *MockRendererTxn) Commit() error {
	mrt.Log.WithFields(logging.Fields{
		"renderer": mrt.renderer.name,
	}).Debug("Mock RendererTxn Commit()")

	mrt.renderer.lock.Lock()
	defer mrt.renderer.lock.Unlock()
	if mrt.resync {
		mrt.renderer.config = mrt.config
	} else {
		for ifName, config := range mrt.config {
			mrt.renderer.config[ifName] = config
		}
	}
	return nil
}
