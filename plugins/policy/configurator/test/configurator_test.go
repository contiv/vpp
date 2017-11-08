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

func parseIPNet(addr string) net.IPNet {
	_, network, err := net.ParseCIDR(addr)
	gomega.Expect(err).To(gomega.BeNil())
	return *network
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

	rendererA := NewMockRenderer(logger)
	rendererB := NewMockRenderer(logger)

	rendererDefault := NewMockRenderer(logger)
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

	// Blocked by policy1 - TCP:80 not allowed.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyWithIPBlockSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyWithIPBlockSinglePod")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod1IfName = "afpacket1"
		pod1IP     = "192.168.1.1"
		pod2IP     = "192.168.2.1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("192.168.2.0/24"),
						Except: []net.IPNet{
							parseIPNet("192.168.2.4/30"),
						},
					},
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

	rendererA := NewMockRenderer(logger)
	rendererB := NewMockRenderer(logger)

	rendererDefault := NewMockRenderer(logger)
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

	// Allowed by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("192.168.2.20"), parseIP(pod1IP), renderer.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = rendererDefault.TestTraffic(pod1IfName, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), renderer.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - ip from the except range.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("192.168.2.5"), parseIP(pod1IP), renderer.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyMultiplePods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyMultiplePods")

	// Prepare input data.
	const (
		namespace1 = "namespace1"
		namespace2 = "namespace2"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod3Name   = "pod3"
		pod1IfName = "afpacket1"
		pod2IfName = "afpacket1"
		pod1IP     = "192.168.1.1"
		pod2IP     = "192.168.2.1"
		pod3IP     = "192.168.3.1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace1}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace1}
	pod3 := podmodel.ID{Name: pod3Name, Namespace: namespace2}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace1},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.0.0.0/8"),
						Except: []net.IPNet{
							parseIPNet("10.1.0.0/16"),
							parseIPNet("10.2.0.0/16"),
							parseIPNet("10.3.0.0/16"),
						},
					},
				},
				Pods: []podmodel.ID{
					pod3,
				},
				Ports: []Port{
					{Protocol: TCP, Number: 8000},
					{Protocol: UDP, Number: 8000},
				},
			},
		},
	}
	policies := []*ContivPolicy{policy1}

	// Initialize mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)
	contiv.SetPodIfName(pod2, pod2IfName)

	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)
	cache.AddPodConfig(pod3, pod3IP)

	rendererA := NewMockRenderer(logger)
	rendererB := NewMockRenderer(logger)

	rendererDefault := NewMockRenderer(logger)
	rendererDefault.AddInterface(pod1IfName)
	rendererDefault.AddInterface(pod2IfName)

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

	txn.Configure(pod1, policies)
	txn.Configure(pod2, policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test with fake traffic.

	// Allowed by policy1.
	action := rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), renderer.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), renderer.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1 - inside the IP block.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod1IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod2IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = rendererDefault.TestTraffic(pod1IfName, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), renderer.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, IngressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), renderer.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - ip in the "except" range.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.1.10.10"), parseIP(pod1IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, EgressTraffic,
		parseIP("10.1.10.10"), parseIP(pod2IP), renderer.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - port not matched.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), renderer.UDP, 123, 8001)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = rendererDefault.TestTraffic(pod2IfName, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), renderer.UDP, 123, 8001)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyWithNestedIPBlocksSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyWithNestedIPBlocksSinglePod")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod1IfName = "afpacket1"
		pod1IP     = "192.168.1.1"
		pod2IP     = "192.168.2.1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.10.0.0/16"),
						Except: []net.IPNet{
							parseIPNet("10.10.10.0/24"),
						},
					},
				},
				Ports: []Port{
					{Protocol: TCP, Number: 0},
				},
			},
			{
				Type: MatchIngress,
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.0.0.0/8"),
					},
				},
				Ports: []Port{
					{Protocol: TCP, Number: 80},
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

	rendererA := NewMockRenderer(logger)
	rendererB := NewMockRenderer(logger)

	rendererDefault := NewMockRenderer(logger)
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
		parseIP("10.0.0.1"), parseIP(pod1IP), renderer.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - port not matched.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.0.0.1"), parseIP(pod1IP), renderer.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Allowed by policy1.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.10.0.1"), parseIP(pod1IP), renderer.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - IP from the except range.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.10.10.1"), parseIP(pod1IP), renderer.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Allowed by policy1 - IP is not in the except range by the port number.
	action = rendererDefault.TestTraffic(pod1IfName, EgressTraffic,
		parseIP("10.10.10.1"), parseIP(pod1IP), renderer.TCP, 789, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
}
