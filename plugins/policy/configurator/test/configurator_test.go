package test

import (
	"net"
	"testing"

	"github.com/onsi/gomega"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	. "github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

func parseIP(ip string) *net.IP {
	netIP := net.ParseIP(ip)
	return &netIP
}

func TestSinglePolicySinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicySinglePod")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod1IfName = "afpacket1"
		pod1IP     = "192.168.1.1"
		pod2IP     = "192.168.1.2"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				Pods: []podmodel.ID{
					pod2,
				},
				Ports: []Port{
					{Protocol: TCP, Number: 80},
					{Protocol: TCP, Number: 443},
				},
			},
		},
	}
	pod1Policies := []*ContivPolicy{policy1}

	// Initialize mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)

	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	rendererA := NewMockRenderer()
	rendererB := NewMockRenderer()

	rendererDefault := NewMockRenderer()
	rendererDefault.AddInterface(pod1IfName)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:    logger,
			Contiv: contiv,
			Cache:  cache,
		},
	}
	configurator.Init()

	// Register renderers.
	err := configurator.RegisterDefaultRenderer(rendererDefault)
	gomega.Expect(err).To(gomega.BeNil())
	err = configurator.RegisterRenderer(podmodel.Pod_Label{Key: "stack", Value: "A"}, rendererA)
	gomega.Expect(err).To(gomega.BeNil())
	err = configurator.RegisterRenderer(podmodel.Pod_Label{Key: "stack", Value: "B"}, rendererB)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test with fake traffic.

	// Allowed by policy1.
	action := rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = rendererDefault.TestTraffic(pod1IfName, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), renderer.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}
