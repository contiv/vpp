/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package configurator

import (
	"net"
	"testing"

	"github.com/onsi/gomega"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	. "github.com/contiv/vpp/mock/policycache"
	. "github.com/contiv/vpp/mock/renderer"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	rendererAPI "github.com/contiv/vpp/plugins/policy/renderer"
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
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicySinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.1.2"
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyWithIPBlockSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyWithIPBlockSinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.2.1"
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("192.168.2.20"), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - ip from the except range.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("192.168.2.5"), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyMultiplePods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyMultiplePods")

	// Prepare input data.
	const (
		namespace1 = "namespace1"
		namespace2 = "namespace2"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod3Name   = "pod3"
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)
	cache.AddPodConfig(pod3, pod3IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register renderers.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, policies)
	txn.Configure(pod2, policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))
	ip, masklen = renderer.GetPodIP(pod2)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod2IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1 - inside the IP block.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod1IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = renderer.TestTraffic(pod2, IngressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - ip in the "except" range.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.1.10.10"), parseIP(pod1IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP("10.1.10.10"), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - port not matched.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.UDP, 123, 8001)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.UDP, 123, 8001)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicyWithNestedIPBlocksSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicyWithNestedIPBlocksSinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.2.1"
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register renderers.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.0.0.1"), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - port not matched.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.0.0.1"), parseIP(pod1IP), rendererAPI.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.0.1"), parseIP(pod1IP), rendererAPI.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - IP from the except range.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.10.1"), parseIP(pod1IP), rendererAPI.TCP, 789, 81)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Allowed by policy1 - IP is not in the except range by the port number.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.10.1"), parseIP(pod1IP), rendererAPI.TCP, 789, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
}

func TestSingleEgressPolicySinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressPolicySinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.1.2"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyEgress,
		Matches: []Match{
			{
				Type: MatchEgress,
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSingleEgressPolicyWithIPBlockSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressPolicyWithIPBlockSinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.2.1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyEgress,
		Matches: []Match{
			{
				Type: MatchEgress,
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP("192.168.2.20"), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - ip from the except range.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP("192.168.2.5"), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSingleBothWaysPolicySinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleBothWaysPolicySinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.1.2"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace},
		Type: PolicyAll,
		Matches: []Match{
			{
				Type: MatchIngress,
				Pods: []podmodel.ID{
					pod2,
				},
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.5.0.0/16"),
						Except: []net.IPNet{
							parseIPNet("10.5.1.0/24"),
							parseIPNet("10.5.2.0/24"),
							parseIPNet("10.5.3.0/24"),
						},
					},
				},
				Ports: []Port{
					{Protocol: UDP, Number: 333},
					{Protocol: UDP, Number: 777},
					{Protocol: TCP, Number: 0}, /* any */
				},
			},
			{
				Type: MatchEgress,
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 456, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.6.7"), parseIP(pod1IP), rendererAPI.UDP, 456, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 5000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 6000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.6.7"), parseIP(pod1IP), rendererAPI.TCP, 456, 6000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - destination 192.168.1.5 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP("192.168.1.5"), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - source 192.168.1.5 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("192.168.2.5"), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP:444 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 444)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - source 10.5.1.1 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.1.1"), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestSinglePolicySinglePodMultipleRenderers(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePolicySinglePodMultipleRenderers")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.1.2"
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
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer1 := NewMockRenderer("A", logger)
	renderer2 := NewMockRenderer("B", logger)
	renderer3 := NewMockRenderer("C", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(true)

	// Register multiple renderers.
	err := configurator.RegisterRenderer(renderer1)
	gomega.Expect(err).To(gomega.BeNil())
	err = configurator.RegisterRenderer(renderer2)
	gomega.Expect(err).To(gomega.BeNil())
	err = configurator.RegisterRenderer(renderer3)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer1.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))
	ip, masklen = renderer2.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))
	ip, masklen = renderer3.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Renderer 1

	// Allowed by policy1.
	action := renderer1.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer1.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer1.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer1.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer1.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Renderer 2

	// Allowed by policy1.
	action = renderer2.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer2.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer2.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer2.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer2.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Renderer 3

	// Allowed by policy1.
	action = renderer3.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer3.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer3.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 456)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer3.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer3.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestMultiplePoliciesSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultiplePoliciesSinglePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod2Name  = "pod2"
		pod1IP    = "192.168.1.1"
		pod2IP    = "192.168.1.2"
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
					{Protocol: UDP, Number: 333},
					{Protocol: UDP, Number: 777},
					{Protocol: TCP, Number: 0}, /* any */
				},
			},
		},
	}

	policy2 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy2", Namespace: namespace},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.5.0.0/16"),
						Except: []net.IPNet{
							parseIPNet("10.5.1.0/24"),
							parseIPNet("10.5.2.0/24"),
							parseIPNet("10.5.3.0/24"),
						},
					},
				},
				Ports: []Port{
					{Protocol: UDP, Number: 333},
					{Protocol: UDP, Number: 888},
				},
			},
		},
	}

	policy3 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy3", Namespace: namespace},
		Type: PolicyEgress,
		Matches: []Match{
			{
				Type: MatchEgress,
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

	pod1Policies := []*ContivPolicy{policy1, policy2, policy3}

	// Initialize mocks.
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register one renderer.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, pod1Policies)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 80)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 456, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.6.7"), parseIP(pod1IP), rendererAPI.UDP, 456, 888)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 5000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Allowed by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 456, 6000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1 - TCP:100 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 789, 100)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - destination 192.168.1.5 not allowed.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP("192.168.1.5"), rendererAPI.TCP, 456, 443)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - source 192.168.1.5 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("192.168.2.5"), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP:444 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 444)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - source 10.5.1.1 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.1.1"), parseIP(pod1IP), rendererAPI.UDP, 123, 333)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - UDP:777 not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.6.7"), parseIP(pod1IP), rendererAPI.UDP, 123, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy1 - TCP not allowed.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.5.6.7"), parseIP(pod1IP), rendererAPI.TCP, 456, 6000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}

func TestMultiplePodsSpecialCases(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultiplePodsSpecialCases")

	// Prepare input data.
	const (
		namespace1 = "namespace1"
		namespace2 = "namespace2"
		pod1Name   = "pod1"
		pod2Name   = "pod2"
		pod3Name   = "pod3"
		pod1IP     = "192.168.1.1"
		pod2IP     = "192.168.2.1"
		pod3IP     = "192.168.3.1"
		pod4Name   = "pod4" /* pod4 is not created and thus has not IP address */

	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace1}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace1}
	pod3 := podmodel.ID{Name: pod3Name, Namespace: namespace2}
	pod4 := podmodel.ID{Name: pod4Name, Namespace: namespace2}

	// empty set of peers but non-empty set of ports
	policy1 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy1", Namespace: namespace1},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				Ports: []Port{
					{Protocol: TCP, Number: 8000},
					{Protocol: UDP, Number: 8000},
				},
			},
		},
	}

	// empty set of peers and empty set of ports
	policy2 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy2", Namespace: namespace1},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
			},
		},
	}

	// non empty set of peers but empty set of ports
	policy3 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy3", Namespace: namespace1},
		Type: PolicyEgress,
		Matches: []Match{
			{
				Type: MatchEgress,
				Pods: []podmodel.ID{
					pod2,
					pod1,
				},
				IPBlocks: []IPBlock{
					{
						Network: parseIPNet("10.5.0.0/16"),
						Except: []net.IPNet{
							parseIPNet("10.5.1.0/24"),
							parseIPNet("10.5.2.0/24"),
							parseIPNet("10.5.3.0/24"),
						},
					},
				},
			},
		},
	}

	// allowed access from pod which, however, does not exist atm
	policy4 := &ContivPolicy{
		ID:   policymodel.ID{Name: "policy4", Namespace: namespace1},
		Type: PolicyIngress,
		Matches: []Match{
			{
				Type: MatchIngress,
				Pods: []podmodel.ID{
					pod4,
				},
			},
		},
	}

	policiesPod1 := []*ContivPolicy{policy1}
	policiesPod2 := []*ContivPolicy{policy2}
	policiesPod3 := []*ContivPolicy{policy3, policy4}

	// Initialize mocks.
	cache := NewMockPolicyCache()
	cache.AddPodConfig(pod1, pod1IP)
	cache.AddPodConfig(pod2, pod2IP)
	cache.AddPodConfig(pod3, pod3IP)

	renderer := NewMockRenderer("A", logger)

	// Initialize configurator.
	configurator := &PolicyConfigurator{
		Deps: Deps{
			Log:   logger,
			Cache: cache,
		},
	}
	configurator.Init(false)

	// Register renderers.
	err := configurator.RegisterRenderer(renderer)
	gomega.Expect(err).To(gomega.BeNil())

	// Run single transaction.
	txn := configurator.NewTxn(false)

	txn.Configure(pod1, policiesPod1)
	txn.Configure(pod2, policiesPod2)
	txn.Configure(pod3, policiesPod3)

	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Test IP address provided by the configurator.
	ip, masklen := renderer.GetPodIP(pod1)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod1IP))
	ip, masklen = renderer.GetPodIP(pod2)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod2IP))
	ip, masklen = renderer.GetPodIP(pod3)
	gomega.Expect(masklen).To(gomega.BeEquivalentTo(net.IPv4len * 8))
	gomega.Expect(ip).To(gomega.BeEquivalentTo(pod3IP))

	// Test with fake traffic.

	// Allowed by policy1.
	action := renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod1IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy1.
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.TCP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod1, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod1IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = renderer.TestTraffic(pod1, IngressTraffic,
		parseIP(pod1IP), parseIP("10.10.10.10"), rendererAPI.TCP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Allowed by policy2.
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod2IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.TCP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP(pod1IP), parseIP(pod2IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod2, EgressTraffic,
		parseIP("10.10.10.10"), parseIP(pod2IP), rendererAPI.UDP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Not covered by any policy.
	action = renderer.TestTraffic(pod2, IngressTraffic,
		parseIP(pod2IP), parseIP(pod1IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = renderer.TestTraffic(pod2, IngressTraffic,
		parseIP(pod2IP), parseIP(pod3IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))
	action = renderer.TestTraffic(pod2, IngressTraffic,
		parseIP(pod2IP), parseIP("10.10.10.10"), rendererAPI.TCP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(UnmatchedTraffic))

	// Allowed by policy3.
	action = renderer.TestTraffic(pod3, IngressTraffic,
		parseIP(pod3IP), parseIP(pod2IP), rendererAPI.TCP, 123, 555)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod3, IngressTraffic,
		parseIP(pod3IP), parseIP(pod1IP), rendererAPI.UDP, 123, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))
	action = renderer.TestTraffic(pod3, IngressTraffic,
		parseIP(pod3IP), parseIP("10.5.10.10"), rendererAPI.UDP, 123, 3215)
	gomega.Expect(action).To(gomega.BeEquivalentTo(AllowedTraffic))

	// Blocked by policy3.
	action = renderer.TestTraffic(pod3, IngressTraffic,
		parseIP(pod3IP), parseIP("10.5.1.10"), rendererAPI.UDP, 123, 3215)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod3, IngressTraffic,
		parseIP(pod3IP), parseIP("78.78.78.10"), rendererAPI.TCP, 123, 777)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))

	// Blocked by policy4.
	action = renderer.TestTraffic(pod3, EgressTraffic,
		parseIP(pod1IP), parseIP(pod3IP), rendererAPI.TCP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod3, EgressTraffic,
		parseIP(pod2IP), parseIP(pod3IP), rendererAPI.UDP, 123, 8000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
	action = renderer.TestTraffic(pod3, EgressTraffic,
		parseIP("10.5.10.10"), parseIP(pod3IP), rendererAPI.TCP, 123, 9000)
	gomega.Expect(action).To(gomega.BeEquivalentTo(DeniedTraffic))
}
