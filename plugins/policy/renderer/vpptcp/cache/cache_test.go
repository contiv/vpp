// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/onsi/gomega"

	"github.com/contiv/vpp/plugins/policy/renderer"
	. "github.com/contiv/vpp/plugins/policy/utils"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"
)

const tagPrefix = "cache-tests-"

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func newContivRule(ID string, action renderer.ActionType, src *net.IPNet, dst *net.IPNet,
	proto renderer.ProtocolType, port uint16) *renderer.ContivRule {

	rule := &renderer.ContivRule{
		ID:          ID,
		Action:      action,
		SrcNetwork:  src,
		DestNetwork: dst,
		Protocol:    proto,
		SrcPort:     0,
		DestPort:    port,
	}
	return rule
}

func checkSessionRule(list []*SessionRule, scope string, nsIndex uint32,
	lclIP string, lclPort uint16, rmtIP string, rmtPort uint16, proto string, action string) {

	// Construct SessionRule.
	rule := SessionRule{
		LclPort:    lclPort,
		RmtPort:    rmtPort,
		AppnsIndex: nsIndex,
	}

	// Parse scope
	switch scope {
	case "LOCAL":
		rule.Scope = RuleScopeLocal
	case "GLOBAL":
		rule.Scope = RuleScopeGlobal
	}

	// Parse transport protocol.
	var transportProto uint8
	switch proto {
	case "TCP":
		transportProto = RuleProtoTCP
	case "UDP":
		transportProto = RuleProtoUDP
	}
	rule.TransportProto = transportProto

	// Parse action.
	var actionIndex uint32
	switch action {
	case "ALLOW":
		actionIndex = RuleActionAllow
	case "DENY":
		actionIndex = RuleActionDeny
	}
	rule.ActionIndex = actionIndex

	// Parse IP addresses.
	isIPv4 := uint8(0)
	if lclIP != "" {
		var lclIPNet *net.IPNet
		if !strings.Contains(lclIP, "/") {
			lclIPNet = GetOneHostSubnet(lclIP)
		} else {
			lclIPNet = ipNetwork(lclIP)
		}
		if lclIPNet.IP.To4() != nil {
			isIPv4 = 1
			copy(rule.LclIP[:], lclIPNet.IP.To4())
		} else {
			copy(rule.LclIP[:], lclIPNet.IP.To16())
		}
		lclPlen, _ := lclIPNet.Mask.Size()
		rule.LclPlen = uint8(lclPlen)
	}
	if rmtIP != "" {
		var rmtIPNet *net.IPNet
		if !strings.Contains(rmtIP, "/") {
			rmtIPNet = GetOneHostSubnet(rmtIP)
		} else {
			rmtIPNet = ipNetwork(rmtIP)
		}
		if rmtIPNet.IP.To4() != nil {
			isIPv4 = 1
			copy(rule.RmtIP[:], rmtIPNet.IP.To4())
		} else {
			copy(rule.RmtIP[:], rmtIPNet.IP.To16())
		}
		rmtPlen, _ := rmtIPNet.Mask.Size()
		rule.RmtPlen = uint8(rmtPlen)
	}
	if lclIP == "" && rmtIP == "" {
		isIPv4 = 1
	}
	rule.IsIP4 = isIPv4

	// Search for the rule.
	found := false
	for _, rule2 := range list {
		if rule.Compare(rule2, false) == 0 {
			gomega.Expect(found).To(gomega.BeFalse())
			/* check tag prefix */
			tagLen := bytes.IndexByte(rule2.Tag[:], 0)
			tag := string(rule2.Tag[:tagLen])
			gomega.Expect(strings.HasPrefix(tag, tagPrefix)).To(gomega.BeTrue())
			found = true
		}
	}
	gomega.Expect(found).To(gomega.BeTrue())
}

func checkContivRules(a, b []*renderer.ContivRule) {
	if a == nil && b == nil {
		return
	}
	gomega.Expect(a).ToNot(gomega.BeNil())
	gomega.Expect(b).ToNot(gomega.BeNil())
	gomega.Expect(len(a)).To(gomega.BeEquivalentTo(len(b)))

	for _, ruleA := range a {
		found := false
		for _, ruleB := range b {
			if ruleA.Compare(ruleB) == 0 {
				gomega.Expect(found).To(gomega.BeFalse())
				found = true
			}
		}
		gomega.Expect(found).To(gomega.BeTrue())
	}
}

func checkNamespaces(cache *SessionRuleCache, namespaces ...int) {
	allNs := cache.AllNamespaces()
	gomega.Expect(len(allNs)).To(gomega.BeEquivalentTo(len(namespaces)))

	for _, ns := range namespaces {
		found := false
		for _, ns2 := range allNs {
			if ns == int(ns2) {
				found = true
				break
			}
		}
		gomega.Expect(found).To(gomega.BeTrue())
	}
}

func TestSingleIngressRuleSingleNs(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleSingleNs")

	// Prepare input data.
	const (
		nsIndex = 10
		podIP   = "192.168.2.1"
	)

	rule := newContivRule("allow-http", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.0/24"), renderer.TCP, 80)

	ingress := []*renderer.ContivRule{rule}
	egress := []*renderer.ContivRule{}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return []*SessionRule{}, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for one namespace
	txn.Update(nsIndex, GetOneHostSubnet(podIP), ingress, egress)
	checkNamespaces(ruleCache) // not yet committed
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(0))
	checkSessionRule(added, "LOCAL", nsIndex, "", 0, "192.168.1.0/24", 80, "TCP", "ALLOW")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkContivRules(cacheIngress, ingress)
	checkContivRules(cacheEgress, egress)
}

func TestSingleEgressRuleSingleNs(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleSingleNs")

	// Prepare input data.
	const (
		nsIndex = 10
		podIP   = "192.168.2.1"
	)

	rule := newContivRule("allow-http", renderer.ActionPermit, ipNetwork("192.168.1.0/24"), &net.IPNet{}, renderer.TCP, 80)

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return []*SessionRule{}, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for one namespace
	txn.Update(nsIndex, GetOneHostSubnet(podIP), ingress, egress)
	checkNamespaces(ruleCache) // not yet commited
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(0))
	checkSessionRule(added, "GLOBAL", 0, podIP, 80, "192.168.1.0/24", 0, "TCP", "ALLOW")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkContivRules(cacheIngress, ingress)
	checkContivRules(cacheEgress, egress)
}

func TestMultipleRulesSingleNsWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesSingleNsWithDataChange")

	// Prepare input data.
	const (
		nsIndex = 10
		podIP   = "192.168.2.1"
	)

	inRule1 := newContivRule("allow-http", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.0/24"), renderer.TCP, 80)
	inRule2 := newContivRule("allow-ssh", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.2.0/24"), renderer.TCP, 22)
	egRule1 := newContivRule("allow-UDP:777", renderer.ActionPermit, ipNetwork("192.168.3.1/32"), &net.IPNet{}, renderer.UDP, 777)
	egRule2 := newContivRule("deny-all-TCP", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule3 := newContivRule("deny-all-UDP", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)

	ingress := []*renderer.ContivRule{inRule1, inRule2}
	egress := []*renderer.ContivRule{egRule1, egRule2, egRule3}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return []*SessionRule{}, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for one namespace
	txn.Update(nsIndex, GetOneHostSubnet(podIP), ingress, egress)
	checkNamespaces(ruleCache) // not yet commited
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(5))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(0))
	checkSessionRule(added, "LOCAL", nsIndex, "", 0, "192.168.1.0/24", 80, "TCP", "ALLOW")
	checkSessionRule(added, "LOCAL", nsIndex, "", 0, "192.168.2.0/24", 22, "TCP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, podIP, 777, "192.168.3.1/32", 0, "UDP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, podIP, 0, "", 0, "TCP", "DENY")
	checkSessionRule(added, "GLOBAL", 0, podIP, 0, "", 0, "UDP", "DENY")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkContivRules(cacheIngress, ingress)
	checkContivRules(cacheEgress, egress)

	// Run second transaction with a config change.
	txn = ruleCache.NewTxn(false)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Updated config.
	inRule3 := newContivRule("deny-all-TCP", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule4 := newContivRule("allow-all-TCP", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)

	ingress2 := []*renderer.ContivRule{inRule3}
	egress2 := []*renderer.ContivRule{egRule1, egRule3, egRule4}

	// Change config for one namespace
	txn.Update(nsIndex, GetOneHostSubnet(podIP), ingress2, egress2)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(3))
	checkSessionRule(added, "LOCAL", nsIndex, "", 0, "", 0, "TCP", "DENY")
	checkSessionRule(added, "GLOBAL", 0, podIP, 0, "", 0, "TCP", "ALLOW")
	checkSessionRule(removed, "LOCAL", nsIndex, "", 0, "192.168.1.0/24", 80, "TCP", "ALLOW")
	checkSessionRule(removed, "LOCAL", nsIndex, "", 0, "192.168.2.0/24", 22, "TCP", "ALLOW")
	checkSessionRule(removed, "GLOBAL", 0, podIP, 0, "", 0, "TCP", "DENY")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(10)
	checkContivRules(cacheIngress, ingress2)
	checkContivRules(cacheEgress, egress2)
}

func TestMultipleRulesMultipleNsWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultipleNsWithDataChange")

	// Prepare input data.
	const (
		nsIndex1 = 10
		pod1IP   = "192.168.1.1"
		nsIndex2 = 15
		pod2IP   = "192.168.2.40"
	)

	// - Pod1 rules
	//   - ingress
	inRule11 := newContivRule("allow-all-TCP-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule12 := newContivRule("allow-all-UDP-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	//   - egress
	egRule11 := newContivRule("allow-all-UDP-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.0/26"), &net.IPNet{}, renderer.UDP, 0)
	egRule12 := newContivRule("allow-TCP80-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.40/32"), &net.IPNet{}, renderer.TCP, 80)
	egRule13 := newContivRule("allow-TCP22-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.40/32"), &net.IPNet{}, renderer.TCP, 22)
	egRule14 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule15 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	// - Pod2 rules
	//   - ingress
	inRule21 := newContivRule("allow-TCP80-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 80)
	inRule22 := newContivRule("allow-TCP8080-pod1", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.1/32"), renderer.TCP, 8080)
	inRule23 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule24 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	//   - egress
	egRule21 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule22 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	egRule23 := newContivRule("allow-UDP100-not-for-pod1", renderer.ActionPermit, ipNetwork("192.168.2.0/24"), &net.IPNet{}, renderer.UDP, 100)
	egRule24 := newContivRule("allow-TCP200-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.0/24"), &net.IPNet{}, renderer.TCP, 200)
	egRule25 := newContivRule("allow-TCP400-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.1/32"), &net.IPNet{}, renderer.TCP, 400)

	ingressPod1 := []*renderer.ContivRule{inRule11, inRule12}
	egressPod1 := []*renderer.ContivRule{egRule11, egRule12, egRule13, egRule14, egRule15}

	ingressPod2 := []*renderer.ContivRule{inRule21, inRule22, inRule23, inRule24}
	egressPod2 := []*renderer.ContivRule{egRule21, egRule22, egRule23, egRule24, egRule25}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return []*SessionRule{}, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for two namespaces
	txn.Update(nsIndex1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1)
	txn.Update(nsIndex2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2)
	checkNamespaces(ruleCache) // not yet commited
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(21))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(0))
	// - Pod1
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 200, "TCP", "ALLOW") /* combined */
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 400, "TCP", "ALLOW") /* combined */
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "TCP", "DENY")    /* combined */
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "UDP", "DENY")    /* combined */
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "ALLOW")
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "", 0, "UDP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod1IP, 0, "192.168.2.0/26", 0, "UDP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod1IP, 80, "192.168.2.40/32", 0, "TCP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod1IP, 22, "192.168.2.40/32", 0, "TCP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod1IP, 0, "", 0, "TCP", "DENY")
	checkSessionRule(added, "GLOBAL", 0, pod1IP, 0, "", 0, "UDP", "DENY")
	// - Pod2
	/* allow-TCP8080-pod1 removed */
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 80, "TCP", "ALLOW") /* combined */
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 0, "TCP", "DENY")   /* combined */
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "", 80, "TCP", "ALLOW")
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "", 0, "TCP", "DENY")
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "", 0, "UDP", "DENY")
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 100, "192.168.2.0/24", 0, "UDP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 200, "192.168.1.0/24", 0, "TCP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 400, "192.168.1.1/32", 0, "TCP", "ALLOW")
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 0, "", 0, "TCP", "DENY")
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 0, "", 0, "UDP", "DENY")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10, 15)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(nsIndex1)
	checkContivRules(cacheIngress, ingressPod1)
	checkContivRules(cacheEgress, egressPod1)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(nsIndex2)
	checkContivRules(cacheIngress, ingressPod2)
	checkContivRules(cacheEgress, egressPod2)

	// Run second transaction with a config change.
	txn = ruleCache.NewTxn(false)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Updated config.
	inRule13 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule25 := newContivRule("allow-all-UDP-for-pod1", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.1/32"), renderer.UDP, 0)
	egRule26 := newContivRule("allow-UDP100-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.0/24"), &net.IPNet{}, renderer.UDP, 100)

	ingressPod1 = []*renderer.ContivRule{inRule12, inRule13}
	egressPod1 = []*renderer.ContivRule{egRule12, egRule13, egRule14, egRule15}

	ingressPod2 = []*renderer.ContivRule{inRule21, inRule22, inRule23, inRule24, inRule25}
	egressPod2 = []*renderer.ContivRule{egRule21, egRule22, egRule24, egRule25, egRule26}

	// Change config for both namespaces
	txn.Update(nsIndex1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1)
	txn.Update(nsIndex2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added)).To(gomega.BeEquivalentTo(4))
	gomega.Expect(len(removed)).To(gomega.BeEquivalentTo(6))
	// - Pod1
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 100, "UDP", "ALLOW") /* combined */
	checkSessionRule(added, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "DENY")
	checkSessionRule(removed, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 200, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 400, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "TCP", "DENY")    /* combined */
	checkSessionRule(removed, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "ALLOW")
	checkSessionRule(removed, "GLOBAL", 0, pod1IP, 0, "192.168.2.0/26", 0, "UDP", "ALLOW")
	// - Pod2
	checkSessionRule(added, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 0, "UDP", "DENY") /* combined */
	checkSessionRule(added, "GLOBAL", 0, pod2IP, 100, "192.168.1.0/24", 0, "UDP", "ALLOW")
	checkSessionRule(removed, "GLOBAL", 0, pod2IP, 100, "192.168.2.0/24", 0, "UDP", "ALLOW")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, nsIndex1, nsIndex2)

	// Verify cache content.
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(nsIndex1)
	checkContivRules(cacheIngress, ingressPod1)
	checkContivRules(cacheEgress, egressPod1)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(nsIndex2)
	checkContivRules(cacheIngress, ingressPod2)
	checkContivRules(cacheEgress, egressPod2)
}

func TestMultipleRulesMultipleNsWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultipleNsWithResync")

	// Prepare input data.
	const (
		nsIndex1 = 10
		pod1IP   = "192.168.1.1"
		nsIndex2 = 15
		pod2IP   = "192.168.2.40"
	)

	// - Pod1 rules
	//   - ingress
	inRule11 := newContivRule("allow-all-TCP-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule12 := newContivRule("allow-all-UDP-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	//   - egress
	egRule11 := newContivRule("allow-all-UDP-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.0/26"), &net.IPNet{}, renderer.UDP, 0)
	egRule12 := newContivRule("allow-TCP80-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.40/32"), &net.IPNet{}, renderer.TCP, 80)
	egRule13 := newContivRule("allow-TCP22-for-pod2", renderer.ActionPermit, ipNetwork("192.168.2.40/32"), &net.IPNet{}, renderer.TCP, 22)
	egRule14 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule15 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	// - Pod2 rules
	//   - ingress
	inRule21 := newContivRule("allow-TCP80-all", renderer.ActionPermit, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 80)
	inRule22 := newContivRule("allow-TCP8080-pod1", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.1/32"), renderer.TCP, 8080)
	inRule23 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule24 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	//   - egress
	egRule21 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	egRule22 := newContivRule("deny-all-UDP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.UDP, 0)
	egRule23 := newContivRule("allow-UDP100-not-for-pod1", renderer.ActionPermit, ipNetwork("192.168.2.0/24"), &net.IPNet{}, renderer.UDP, 100)
	egRule24 := newContivRule("allow-TCP200-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.0/24"), &net.IPNet{}, renderer.TCP, 200)
	egRule25 := newContivRule("allow-TCP400-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.1/32"), &net.IPNet{}, renderer.TCP, 400)

	ingressPod1 := []*renderer.ContivRule{inRule11, inRule12}
	egressPod1 := []*renderer.ContivRule{egRule11, egRule12, egRule13, egRule14, egRule15}

	ingressPod2 := []*renderer.ContivRule{inRule21, inRule22, inRule23, inRule24}
	egressPod2 := []*renderer.ContivRule{egRule21, egRule22, egRule23, egRule24, egRule25}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return []*SessionRule{}, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run single transaction to get an initial dump.
	txn := ruleCache.NewTxn(false)
	txn.Update(nsIndex1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1)
	txn.Update(nsIndex2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2)
	added, _, _ := txn.Changes()
	txn.Commit()

	// Simulate cache restart.
	ruleCache = &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() ([]*SessionRule, error) { return added, nil }, tagPrefix)
	checkNamespaces(ruleCache)

	// Run RESYNC transaction with a changed config.
	txn = ruleCache.NewTxn(true)
	added2, removed2, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added2)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(len(removed2)).To(gomega.BeEquivalentTo(21))
	// - Pod1
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 200, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 400, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "TCP", "DENY")    /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "UDP", "DENY")    /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "", 0, "UDP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 0, "192.168.2.0/26", 0, "UDP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 80, "192.168.2.40/32", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 22, "192.168.2.40/32", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 0, "", 0, "TCP", "DENY")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 0, "", 0, "UDP", "DENY")
	// - Pod2
	checkSessionRule(removed2, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 80, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 0, "TCP", "DENY")   /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex2, "", 0, "", 80, "TCP", "ALLOW")
	checkSessionRule(removed2, "LOCAL", nsIndex2, "", 0, "", 0, "TCP", "DENY")
	checkSessionRule(removed2, "LOCAL", nsIndex2, "", 0, "", 0, "UDP", "DENY")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 100, "192.168.2.0/24", 0, "UDP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 200, "192.168.1.0/24", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 400, "192.168.1.1/32", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 0, "", 0, "TCP", "DENY")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 0, "", 0, "UDP", "DENY")

	// Updated config.
	inRule13 := newContivRule("deny-all-TCP-all", renderer.ActionDeny, &net.IPNet{}, &net.IPNet{}, renderer.TCP, 0)
	inRule25 := newContivRule("allow-all-UDP-for-pod1", renderer.ActionPermit, &net.IPNet{}, ipNetwork("192.168.1.1/32"), renderer.UDP, 0)
	egRule26 := newContivRule("allow-UDP100-for-pod1", renderer.ActionPermit, ipNetwork("192.168.1.0/24"), &net.IPNet{}, renderer.UDP, 100)

	ingressPod1 = []*renderer.ContivRule{inRule12, inRule13}
	egressPod1 = []*renderer.ContivRule{egRule12, egRule13, egRule14, egRule15}

	ingressPod2 = []*renderer.ContivRule{inRule21, inRule22, inRule23, inRule24, inRule25}
	egressPod2 = []*renderer.ContivRule{egRule21, egRule22, egRule24, egRule25, egRule26}

	// Change config for both namespaces
	txn.Update(nsIndex1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1)
	txn.Update(nsIndex2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2)
	added2, removed2, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(added2)).To(gomega.BeEquivalentTo(4))
	gomega.Expect(len(removed2)).To(gomega.BeEquivalentTo(6))
	// - Pod1
	checkSessionRule(added2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 100, "UDP", "ALLOW") /* combined */
	checkSessionRule(added2, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "DENY")
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 200, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 400, "TCP", "ALLOW") /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "192.168.2.40/32", 0, "TCP", "DENY")    /* combined */
	checkSessionRule(removed2, "LOCAL", nsIndex1, "", 0, "", 0, "TCP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod1IP, 0, "192.168.2.0/26", 0, "UDP", "ALLOW")
	// - Pod2
	checkSessionRule(added2, "LOCAL", nsIndex2, "", 0, "192.168.1.1/32", 0, "UDP", "DENY") /* combined */
	checkSessionRule(added2, "GLOBAL", 0, pod2IP, 100, "192.168.1.0/24", 0, "UDP", "ALLOW")
	checkSessionRule(removed2, "GLOBAL", 0, pod2IP, 100, "192.168.2.0/24", 0, "UDP", "ALLOW")

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, nsIndex1, nsIndex2)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(nsIndex1)
	checkContivRules(cacheIngress, ingressPod1)
	checkContivRules(cacheEgress, egressPod1)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(nsIndex2)
	checkContivRules(cacheIngress, ingressPod2)
	checkContivRules(cacheEgress, egressPod2)
}
