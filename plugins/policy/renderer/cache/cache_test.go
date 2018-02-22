/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

package cache

import (
	"fmt"
	"github.com/onsi/gomega"
	"net"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	. "github.com/contiv/vpp/plugins/policy/utils"
)

const (
	namespace = "default"
)

var (
	podIDs = []podmodel.ID{
		{Name: "pod1", Namespace: namespace},
		{Name: "pod2", Namespace: namespace},
		{Name: "pod3", Namespace: namespace},
		{Name: "pod4", Namespace: namespace},
		{Name: "pod5", Namespace: namespace},
	}
	podIPs = []string{
		"10.10.1.1",
		"10.10.1.2",
		"10.10.2.1",
		"10.10.2.2",
		"10.10.2.5",
	}

	// aliases
	pod1   = podIDs[0]
	pod2   = podIDs[1]
	pod3   = podIDs[2]
	pod1IP = podIPs[0]
	pod2IP = podIPs[1]
	pod3IP = podIPs[2]

	// shortcuts
	EmptyPodSet = NewPodSet()
	EmptyRules  = []*renderer.ContivRule{}
)

// Input data for test set1:
type TestSet1And2 struct {
	rule *renderer.ContivRule
}

var ts1 = TestSet1And2{
	rule: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	},
}

// Input data for test set2:
var ts2 = TestSet1And2{
	rule: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("192.168.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	},
}

// Input data for test set3:
type TestSet3And4 struct {
	rule1, rule2, rule3, rule4 *renderer.ContivRule
}

var ts3 = TestSet3And4{
	rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.10.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	},
	rule2: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.10.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	},
	rule3: denyAllTCP(),
	rule4: denyAllUDP(),
}

// Input data for test set4:
var ts4 = TestSet3And4{
	rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.10.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	},
	rule2: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.10.0.0/16"),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	},
	rule3: denyAllTCP(),
	rule4: denyAllUDP(),
}

// Input data for test set5:
type TestSet5 struct {
	pod1Ingress, pod1Egress []*renderer.ContivRule
	pod3Ingress, pod3Egress []*renderer.ContivRule
}

var ts5 = TestSet5{
	pod1Ingress: []*renderer.ContivRule{
		{ // Txn2
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork(""),
			DestNetwork: ipNetwork("10.10.0.0/16"),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    80,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork(""),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    161,
		},
		denyAllTCP(),
		denyAllUDP(),
	},
	pod1Egress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork("10.0.0.0/8"),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    53,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork("192.168.0.0/16"),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    514,
		},
		denyAllTCP(), // Txn2
		denyAllUDP(), // Txn2
	},
	pod3Ingress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork(""),
			DestNetwork: ipNetwork("10.10.1.1/32"),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    0,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork(""),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    22,
		},
		denyAllTCP(),
		denyAllUDP(),
	},
	pod3Egress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork("10.0.0.0/8"),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    80,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork("10.0.0.0/8"),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    443,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  ipNetwork(""),
			DestNetwork: ipNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    67,
		},
		denyAllTCP(),
		denyAllUDP(),
	},
}

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, _ := net.ParseCIDR(addr)
	return network
}

func allowAllTCP() *renderer.ContivRule {
	ruleTCPAny := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleTCPAny
}

func allowAllUDP() *renderer.ContivRule {
	ruleUDPAny := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleUDPAny
}

func denyAllTCP() *renderer.ContivRule {
	ruleTCPNone := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleTCPNone
}

func denyAllUDP() *renderer.ContivRule {
	ruleUDPNone := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleUDPNone
}

func modifySrc(srcIP string, rules ...*renderer.ContivRule) []*renderer.ContivRule {
	modified := []*renderer.ContivRule{}
	for _, rule := range rules {
		modifiedRule := rule.Copy()
		modifiedRule.SrcNetwork = GetOneHostSubnet(srcIP)
		modified = append(modified, modifiedRule)
	}
	return modified
}

func modifyDst(rule *renderer.ContivRule, dstIPs ...string) []*renderer.ContivRule {
	modified := []*renderer.ContivRule{}
	for _, dstIP := range dstIPs {
		modifiedRule := rule.Copy()
		modifiedRule.DestNetwork = GetOneHostSubnet(dstIP)
		modified = append(modified, modifiedRule)
	}
	return modified
}

func verifyRules(table *ContivRuleTable, rules []*renderer.ContivRule) {
	cmp := compareRuleLists(table.Rules[:table.NumOfRules], rules)
	if cmp != 0 {
		fmt.Printf("Rule lists do not match:\n")
		fmt.Printf("%s\n", table.Rules[:table.NumOfRules])
		fmt.Printf("%s\n", rules)
	}
	gomega.Expect(cmp).To(gomega.BeEquivalentTo(0))
}

func allowPodEgress(podIP string, port uint16, protocol renderer.ProtocolType) *renderer.ContivRule {
	return &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  GetOneHostSubnet(podIP),
		DestNetwork: &net.IPNet{},
		SrcPort:     AnyPort,
		DestPort:    port,
		Protocol:    protocol,
	}
}

func blockPodEgress(podIP string, protocol renderer.ProtocolType) *renderer.ContivRule {
	return &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  GetOneHostSubnet(podIP),
		DestNetwork: &net.IPNet{},
		SrcPort:     AnyPort,
		DestPort:    AnyPort,
		Protocol:    protocol,
	}
}

func allowPodIngress(podIP string, port uint16, protocol renderer.ProtocolType) *renderer.ContivRule {
	return &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: GetOneHostSubnet(podIP),
		SrcPort:     AnyPort,
		DestPort:    port,
		Protocol:    protocol,
	}
}

func blockPodIngress(podIP string, protocol renderer.ProtocolType) *renderer.ContivRule {
	return &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: GetOneHostSubnet(podIP),
		SrcPort:     AnyPort,
		DestPort:    AnyPort,
		Protocol:    protocol,
	}
}

func verifyCachedPods(cacheView View, all, isolated PodSet) {
	gomega.Expect(cacheView.GetAllPods()).To(gomega.BeEquivalentTo(all))
	gomega.Expect(cacheView.GetIsolatedPods()).To(gomega.BeEquivalentTo(isolated))
}

func verifyUpdatedPods(txn Txn, updated, removed PodSet) {
	gomega.Expect(txn.GetUpdatedPods()).To(gomega.BeEquivalentTo(updated))
	gomega.Expect(txn.GetRemovedPods()).To(gomega.BeEquivalentTo(removed))
}

func verifyLocalTableChange(change *TxnChange, expPtr *ContivRuleTable, rules []*renderer.ContivRule, prevPods, newPods PodSet) {
	gomega.Expect(change).ToNot(gomega.BeNil())
	verifyLocalTable(change.Table, expPtr, rules, newPods)
	gomega.Expect(change.PreviousPods).To(gomega.BeEquivalentTo(prevPods))
}

func verifyPodLocalTable(view View, podID podmodel.ID, expPtr *ContivRuleTable, rules []*renderer.ContivRule, pods PodSet) {
	table := view.GetLocalTableByPod(podID)
	gomega.Expect(table).ToNot(gomega.BeNil())
	if expPtr != nil {
		gomega.Expect(table).To(gomega.Equal(expPtr))
	}
	gomega.Expect(table.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(table.Type).To(gomega.Equal(Local))
	verifyRules(table, rules)
	gomega.Expect(table.Pods).To(gomega.BeEquivalentTo(pods))
}

func verifyPodNilLocalTable(view View, podID podmodel.ID) {
	table := view.GetLocalTableByPod(podID)
	gomega.Expect(table).To(gomega.BeNil())
}

func verifyLocalTable(table *ContivRuleTable, expPtr *ContivRuleTable, rules []*renderer.ContivRule, pods PodSet) {
	gomega.Expect(table).ToNot(gomega.BeNil())
	if expPtr != nil {
		gomega.Expect(table.ID).To(gomega.Equal(expPtr.ID))
	}
	gomega.Expect(table.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(table.ID).ToNot(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(table.Type).To(gomega.Equal(Local))
	verifyRules(table, rules)
	gomega.Expect(table.Pods).To(gomega.BeEquivalentTo(pods))
}

func verifyGlobalTableChange(change *TxnChange, expPtr, notExpPtr *ContivRuleTable, rules []*renderer.ContivRule) {
	gomega.Expect(change).ToNot(gomega.BeNil())
	verifyGlobalTable(change.Table, expPtr, notExpPtr, rules)
	gomega.Expect(change.PreviousPods).To(gomega.BeEmpty())
}

func verifyGlobalTable(table *ContivRuleTable, expPtr, notExpPtr *ContivRuleTable, rules []*renderer.ContivRule) {
	gomega.Expect(table).ToNot(gomega.BeNil())
	if expPtr != nil {
		gomega.Expect(table).To(gomega.Equal(expPtr))
	}
	if notExpPtr != nil {
		gomega.Expect(table).ToNot(gomega.Equal(notExpPtr))
	}
	gomega.Expect(table.ID).To(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(table.Type).To(gomega.Equal(Global))
	verifyRules(table, rules)
	gomega.Expect(table.Pods).To(gomega.BeEmpty())
}

func verifyPodConfig(view View, podID podmodel.ID, cfg *PodConfig) {
	gomega.Expect(view.GetPodConfig(podID)).To(gomega.Equal(cfg))
}

func TestSingleEgressRuleOnePodEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleOnePodEgressOrientation")

	// Prepare input data.
	pods := NewPodSet(pod1)

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts1.rule}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)

	// Check initial cache content
	globalTable := ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn := ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	verifyPodConfig(txn, pod1, podCfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Local table was added.
	verifyLocalTableChange(changes[0], nil, egress, EmptyPodSet, pods)
	localTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	verifyPodLocalTable(txn, pod1, localTableTxn, egress, pods)
	verifyGlobalTable(txn.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Changes should be applied only after the commit.
	verifyPodConfig(ruleCache, pod1, nil)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, podCfg)
	verifyPodLocalTable(ruleCache, pod1, localTableTxn, egress, pods)
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)
}

func TestSingleEgressRuleOnePodIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleOnePodIngressOrientation")

	// Prepare input data.
	pods := NewPodSet(pod1)

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts1.rule}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)

	// Expected global table content.
	globalRules := modifyDst(ts1.rule, podIPs[0])
	globalRules = append(globalRules, allowAllTCP(), allowAllUDP())

	// Check initial cache content
	globalTable := ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn := ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	verifyPodConfig(txn, pod1, podCfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, EmptyPodSet)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	verifyGlobalTableChange(changes[0], nil, globalTable, globalRules)
	globalTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	verifyPodNilLocalTable(txn, pod1)
	verifyCachedPods(txn, pods, EmptyPodSet)
	verifyGlobalTable(txn.GetGlobalTable(), globalTableTxn, globalTable, globalRules)

	// Changes should be applied only after the commit.
	verifyPodConfig(ruleCache, pod1, nil)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, globalTableTxn, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, podCfg)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyCachedPods(ruleCache, pods, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn, globalTable, globalRules)
}

func TestSingleIngressRuleOnePodEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleOnePodEgressOrientation")

	// Prepare input data.
	pods := NewPodSet(pod1)
	ingress := []*renderer.ContivRule{ts2.rule}
	egress := []*renderer.ContivRule{}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)

	// Expected global table content.
	globalRules := modifySrc(podIPs[0], ts2.rule)
	globalRules = append(globalRules, allowAllTCP(), allowAllUDP()) /* order matters */

	// Check initial cache content
	globalTable := ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn := ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	verifyPodConfig(txn, pod1, podCfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, EmptyPodSet)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	verifyGlobalTableChange(changes[0], nil, globalTable, globalRules)
	globalTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	verifyPodNilLocalTable(txn, pod1)
	verifyCachedPods(txn, pods, EmptyPodSet)
	verifyGlobalTable(txn.GetGlobalTable(), globalTableTxn, globalTable, globalRules)

	// Changes should be applied only after the commit.
	verifyPodConfig(ruleCache, pod1, nil)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, globalTableTxn, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, podCfg)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyCachedPods(ruleCache, pods, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn, globalTable, globalRules)
}

func TestSingleIngressRuleOnePodIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleOnePodIngressOrientation")

	// Prepare input data.
	pods := NewPodSet(pod1)
	ingress := []*renderer.ContivRule{ts2.rule}
	egress := []*renderer.ContivRule{}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)

	// Check initial cache content
	globalTable := ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn := ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	verifyPodConfig(txn, pod1, podCfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Local table was added.
	verifyLocalTableChange(changes[0], nil, ingress, EmptyPodSet, pods)
	localTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	verifyPodLocalTable(txn, pod1, localTableTxn, ingress, pods)
	verifyGlobalTable(txn.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Changes should be applied only after the commit.
	verifyPodConfig(ruleCache, pod1, nil)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)
	verifyPodNilLocalTable(ruleCache, pod1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, podCfg)
	verifyPodLocalTable(ruleCache, pod1, localTableTxn, ingress, pods)
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)
}

func TestMultipleEgressRulesMultiplePodsEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleEgressRulesMultiplePodsEgressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts3.rule1, ts3.rule2, ts3.rule3, ts3.rule4}
	orderedEgress := []*renderer.ContivRule{ts3.rule1, ts3.rule3, ts3.rule2, ts3.rule4}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, pods1)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Single local table was added.
	verifyLocalTableChange(changes[0], nil, orderedEgress, EmptyPodSet, pods1)
	localTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	for i := 0; i < len(pods1); i++ {
		verifyPodLocalTable(txn, podIDs[i], localTableTxn, orderedEgress, pods1)
	}
	verifyGlobalTable(txn.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedEgress, pods1)
	}
	verifyCachedPods(ruleCache, pods1, pods1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Run second transaction.
	// Pod4 and Pod5 are added.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods2, EmptyPodSet)
	verifyCachedPods(txn, pods2, pods2)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// New pods were assigned to the existing local table.
	verifyLocalTableChange(changes[0], localTableTxn, orderedEgress, pods1, pods2)

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedEgress, pods2)
	}
	verifyCachedPods(ruleCache, pods2, pods2)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)
}

func TestMultipleEgressRulesMultiplePodsIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleEgressRulesMultiplePodsIngressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts3.rule1, ts3.rule2, ts3.rule3, ts3.rule4}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Expected global table content after the first transaction.
	var globalRules []*renderer.ContivRule
	globalRules = append(globalRules, modifyDst(ts3.rule1, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule3, podIPs[:3]...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(ts3.rule2, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule4, podIPs[:3]...)...)
	globalRules = append(globalRules, allowAllUDP())

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, EmptyPodSet)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	verifyGlobalTableChange(changes[0], nil, globalTable, globalRules)
	globalTableTxn1 := changes[0].Table

	// Test what the cache will contain after the transaction.
	for i := 0; i < len(pods1); i++ {
		verifyPodNilLocalTable(txn, podIDs[i])
	}
	verifyCachedPods(txn, pods1, EmptyPodSet)
	verifyGlobalTable(txn.GetGlobalTable(), globalTableTxn1, globalTable, globalRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyCachedPods(ruleCache, pods1, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn1, globalTable, globalRules)

	// Run second transaction.
	// Pod4 and Pod5 are added.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods2, EmptyPodSet)
	verifyCachedPods(txn, pods2, EmptyPodSet)

	// Expected global table content after the second transaction.
	globalRules = []*renderer.ContivRule{}
	globalRules = append(globalRules, modifyDst(ts3.rule1, podIPs...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule3, podIPs...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(ts3.rule2, podIPs...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule4, podIPs...)...)
	globalRules = append(globalRules, allowAllUDP())

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed again.
	verifyGlobalTableChange(changes[0], nil, globalTableTxn1, globalRules)
	globalTableTxn2 := changes[0].Table

	// Test what the cache will contain after the transaction.
	for i := 0; i < len(pods2); i++ {
		verifyPodNilLocalTable(txn, podIDs[i])
	}
	verifyCachedPods(txn, pods2, EmptyPodSet)
	verifyGlobalTable(txn.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRules)

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyCachedPods(ruleCache, pods2, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRules)
}

func TestMultipleIngressRulesMultiplePodsEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleIngressRulesMultiplePodsEgressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */
	ingress := []*renderer.ContivRule{ts4.rule1, ts4.rule2, ts4.rule3, ts4.rule4}
	egress := []*renderer.ContivRule{}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Expected global table content after the first transaction.
	var globalRules []*renderer.ContivRule
	for i := 0; i < len(pods1); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], ts4.rule1, ts4.rule3)...)
	}
	globalRules = append(globalRules, allowAllTCP())
	for i := 0; i < len(pods1); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], ts4.rule2, ts4.rule4)...)
	}
	globalRules = append(globalRules, allowAllUDP())

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, EmptyPodSet)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	verifyGlobalTableChange(changes[0], nil, globalTable, globalRules)
	globalTableTxn1 := changes[0].Table

	// Test what the cache will contain after the transaction.
	for i := 0; i < len(pods1); i++ {
		verifyPodNilLocalTable(txn, podIDs[i])
	}
	verifyCachedPods(txn, pods1, EmptyPodSet)
	verifyGlobalTable(txn.GetGlobalTable(), globalTableTxn1, globalTable, globalRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyCachedPods(ruleCache, pods1, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn1, globalTable, globalRules)

	// Run second transaction.
	// Pod4 and Pod5 are added.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods2, EmptyPodSet)
	verifyCachedPods(txn, pods2, EmptyPodSet)

	// Expected global table content after the second transaction.
	globalRules = []*renderer.ContivRule{}
	for i := 0; i < len(pods2); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], ts4.rule1, ts4.rule3)...)
	}
	globalRules = append(globalRules, allowAllTCP())
	for i := 0; i < len(pods2); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], ts4.rule2, ts4.rule4)...)
	}
	globalRules = append(globalRules, allowAllUDP())

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed again.
	verifyGlobalTableChange(changes[0], nil, globalTableTxn1, globalRules)
	globalTableTxn2 := changes[0].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyCachedPods(ruleCache, pods2, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRules)
}

func TestMultipleIngressRulesMultiplePodsIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleIngressRulesMultiplePodsIngressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */
	ingress := []*renderer.ContivRule{ts4.rule1, ts4.rule2, ts4.rule3, ts4.rule4}
	egress := []*renderer.ContivRule{}
	orderedIngress := []*renderer.ContivRule{ts4.rule1, ts4.rule3, ts4.rule2, ts4.rule4}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, pods1)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Single local table was added.
	verifyLocalTableChange(changes[0], nil, orderedIngress, EmptyPodSet, pods1)
	localTableTxn := changes[0].Table

	// Test what the cache will contain after the transaction.
	for i := 0; i < len(pods1); i++ {
		verifyPodLocalTable(txn, podIDs[i], localTableTxn, orderedIngress, pods1)
	}
	verifyGlobalTable(txn.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedIngress, pods1)
	}
	verifyCachedPods(ruleCache, pods1, pods1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Run second transaction.
	// Pod4 and Pod5 are added.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods2, EmptyPodSet)
	verifyCachedPods(txn, pods2, pods2)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// New pods were assigned to the existing local table.
	verifyLocalTableChange(changes[0], localTableTxn, orderedIngress, pods1, pods2)

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedIngress, pods2)
	}
	verifyCachedPods(ruleCache, pods2, pods2)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)
}

func TestCombinedRulesEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRulesEgressOrientation")

	// Prepare test data
	pods := NewPodSet(pod1, pod3)
	pod1Txn1Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress[1:],
		Egress:  ts5.pod1Egress[:2],
		Removed: false,
	}
	pod1Txn2Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress,
		Egress:  ts5.pod1Egress,
		Removed: false,
	}
	pod3Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: ts5.pod3Ingress,
		Egress:  ts5.pod3Egress,
		Removed: false,
	}

	// Expected output data
	pod1LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodEgress(pod1IP, renderer.TCP),
		allowPodEgress(pod3IP, 22, renderer.TCP), blockPodEgress(pod3IP, renderer.TCP),
		/* UDP: */ allowPodEgress(pod1IP, 161, renderer.UDP), blockPodEgress(pod1IP, renderer.UDP),
		pod1Txn1Cfg.Egress[1] /* smaller subnet */, pod1Txn1Cfg.Egress[0],
	}
	pod3LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodEgress(pod1IP, renderer.TCP),
		blockPodEgress(pod3IP, renderer.TCP), ts5.pod3Egress[0], ts5.pod3Egress[1], ts5.pod3Egress[3],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP), blockPodEgress(pod3IP, renderer.UDP),
		ts5.pod3Egress[2], ts5.pod3Egress[4],
	}
	globalRules := []*renderer.ContivRule{}
	/* TCP: */
	globalRules = append(globalRules, modifySrc(pod1IP, pod1Txn1Cfg.Ingress[1])...)
	globalRules = append(globalRules, modifySrc(pod3IP, pod3Cfg.Ingress[1], pod3Cfg.Ingress[2])...)
	globalRules = append(globalRules, allowAllTCP())
	/* UDP: */
	globalRules = append(globalRules, modifySrc(pod1IP, pod1Txn1Cfg.Ingress[0], pod1Txn1Cfg.Ingress[2])...)
	globalRules = append(globalRules, modifySrc(pod3IP, pod3Cfg.Ingress[0], pod3Cfg.Ingress[3])...)
	globalRules = append(globalRules, allowAllUDP())

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)

	// Run first transaction.
	txn := ruleCache.NewTxn()
	txn.Update(pod1, pod1Txn1Cfg)
	txn.Update(pod3, pod3Cfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(3))

	// 2 local tables were added.
	fmt.Printf("\n\n Table0: %s\n\n", changes[0].Table)
	fmt.Printf("\n\n Table1: %s\n\n", changes[1].Table)

	var pod1TableIdx, pod3TableIdx int
	if changes[0].Table.Pods.Has(pod1) {
		pod3TableIdx = 1
	} else {
		pod1TableIdx = 1
	}
	verifyLocalTableChange(changes[pod1TableIdx], nil, pod1LocalRules, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn1 := changes[pod1TableIdx].Table
	verifyLocalTableChange(changes[pod3TableIdx], nil, pod3LocalRules, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn1 := changes[pod3TableIdx].Table

	// Global table has changed.
	verifyGlobalTableChange(changes[2], nil, nil, globalRules)
	globalTableTxn1 := changes[2].Table

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1Txn1Cfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn1, pod1LocalRules, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn1, pod3LocalRules, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn1, nil, globalRules)

	// Run second transaction - update pod1
	txn = ruleCache.NewTxn()
	txn.Update(pod1, pod1Txn2Cfg)
	verifyUpdatedPods(txn, NewPodSet(pod1), EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Expected output data
	pod1LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ pod1Txn2Cfg.Egress[2],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP),
		pod1Txn2Cfg.Egress[1] /* smaller subnet */, pod1Txn2Cfg.Egress[0], pod1Txn2Cfg.Egress[3],
	}
	pod3LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ allowPodEgress(pod1IP, 80, renderer.TCP), blockPodEgress(pod1IP, renderer.TCP),
		blockPodEgress(pod3IP, renderer.TCP),
		ts5.pod3Egress[0], ts5.pod3Egress[1], ts5.pod3Egress[3],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP), blockPodEgress(pod3IP, renderer.UDP),
		ts5.pod3Egress[2], ts5.pod3Egress[4],
	}
	globalRulesTxn2 := []*renderer.ContivRule{}
	/* TCP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod1IP, pod1Txn2Cfg.Ingress[0], pod1Txn2Cfg.Ingress[2])...)
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod3IP, pod3Cfg.Ingress[1], pod3Cfg.Ingress[2])...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllTCP())
	/* UDP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod1IP, pod1Txn2Cfg.Ingress[1], pod1Txn2Cfg.Ingress[3])...)
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod3IP, pod3Cfg.Ingress[0], pod3Cfg.Ingress[3])...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllUDP())

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(5))

	// Two new local tables.
	var pod1LocalTableChange *TxnChange
	var pod3LocalTableChange *TxnChange
	var pod1LocalTableTxn1Removed, pod3LocalTableTxn1Removed bool
	for i := 0; i < 4; i++ {
		if changes[i].Table.Pods.Has(pod1) {
			gomega.Expect(pod1LocalTableChange).To(gomega.BeNil())
			pod1LocalTableChange = changes[i]
		}
		if changes[i].Table.Pods.Has(pod3) {
			gomega.Expect(pod3LocalTableChange).To(gomega.BeNil())
			pod3LocalTableChange = changes[i]
		}
		if changes[i].PreviousPods.Has(pod1) {
			gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeFalse())
			pod1LocalTableTxn1Removed = true
		}
		if changes[i].PreviousPods.Has(pod3) {
			gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeFalse())
			pod3LocalTableTxn1Removed = true
		}
	}
	gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod1LocalTableChange).ToNot(gomega.BeNil())
	gomega.Expect(pod3LocalTableChange).ToNot(gomega.BeNil())

	verifyLocalTableChange(pod1LocalTableChange, nil, pod1LocalRulesTxn2, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn2 := pod1LocalTableChange.Table
	verifyLocalTableChange(pod3LocalTableChange, nil, pod3LocalRulesTxn2, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn2 := pod3LocalTableChange.Table

	// Global table has changed.
	verifyGlobalTableChange(changes[4], nil, globalTableTxn1, globalRulesTxn2)
	globalTableTxn2 := changes[4].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1Txn2Cfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn2, pod1LocalRulesTxn2, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn2, pod3LocalRulesTxn2, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRulesTxn2)
}

func TestCombinedRulesIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRulesIngressOrientation")

	// Prepare test data
	pods := NewPodSet(pod1, pod3)
	pod1Txn1Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress[1:],
		Egress:  ts5.pod1Egress[:2],
		Removed: false,
	}
	pod1Txn2Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress,
		Egress:  ts5.pod1Egress,
		Removed: false,
	}
	pod3Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: ts5.pod3Ingress,
		Egress:  ts5.pod3Egress,
		Removed: false,
	}

	// Expected output data
	pod1LocalRules := []*renderer.ContivRule{
		/* TCP: */ pod1Txn1Cfg.Ingress[1],
		/* UDP: */ blockPodIngress(pod3IP, renderer.UDP),
		pod1Txn1Cfg.Ingress[0], pod1Txn1Cfg.Ingress[2],
	}
	pod3LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod3IP, renderer.TCP),
		pod3Cfg.Ingress[1], pod3Cfg.Ingress[2],
		/* UDP: */ pod3Cfg.Ingress[0], pod3Cfg.Ingress[3],
	}
	globalRules := []*renderer.ContivRule{}
	/* TCP: */
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[0], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[1], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[3], pod3IP)...)
	globalRules = append(globalRules, allowAllTCP())
	/* UDP: */
	globalRules = append(globalRules, modifyDst(pod1Txn1Cfg.Egress[1], pod1IP)...)
	globalRules = append(globalRules, modifyDst(pod1Txn1Cfg.Egress[0], pod1IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[2], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[4], pod3IP)...)
	globalRules = append(globalRules, allowAllUDP())

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)

	// Run first transaction.
	txn := ruleCache.NewTxn()
	txn.Update(pod1, pod1Txn1Cfg)
	txn.Update(pod3, pod3Cfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(3))

	// 2 local tables were added.
	var pod1TableIdx, pod3TableIdx int
	if changes[0].Table.Pods.Has(pod1) {
		pod3TableIdx = 1
	} else {
		pod1TableIdx = 1
	}
	verifyLocalTableChange(changes[pod1TableIdx], nil, pod1LocalRules, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn1 := changes[pod1TableIdx].Table
	verifyLocalTableChange(changes[pod3TableIdx], nil, pod3LocalRules, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn1 := changes[pod3TableIdx].Table

	// Global table has changed.
	verifyGlobalTableChange(changes[2], nil, nil, globalRules)
	globalTableTxn1 := changes[2].Table

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1Txn1Cfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn1, pod1LocalRules, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn1, pod3LocalRules, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn1, nil, globalRules)

	// Run second transaction - update pod1
	txn = ruleCache.NewTxn()
	txn.Update(pod1, pod1Txn2Cfg)
	verifyUpdatedPods(txn, NewPodSet(pod1), EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Expected output data
	pod1LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod1IP, renderer.TCP),
		pod1Txn2Cfg.Ingress[0], pod1Txn2Cfg.Ingress[2],
		/* UDP: */ blockPodIngress(pod1IP, renderer.UDP), blockPodIngress(pod3IP, renderer.UDP),
		pod1Txn2Cfg.Ingress[1], pod1Txn2Cfg.Ingress[3],
	}
	pod3LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod1IP, renderer.TCP), blockPodIngress(pod3IP, renderer.TCP),
		pod3Cfg.Ingress[1], pod3Cfg.Ingress[2],
		/* UDP: */ allowPodIngress(pod1IP, 53, renderer.UDP), blockPodIngress(pod1IP, renderer.UDP),
		/* removed: pod3Cfg.Ingress[0],*/ pod3Cfg.Ingress[3],
	}
	globalRulesTxn2 := []*renderer.ContivRule{}
	/* TCP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[0], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[1], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1Txn2Cfg.Egress[2], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[3], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllTCP())
	/* UDP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1Txn2Cfg.Egress[1], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1Txn2Cfg.Egress[0], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1Txn2Cfg.Egress[3], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[2], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[4], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllUDP())

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(5))

	// Two new local tables.
	var pod1LocalTableChange *TxnChange
	var pod3LocalTableChange *TxnChange
	var pod1LocalTableTxn1Removed, pod3LocalTableTxn1Removed bool
	for i := 0; i < 4; i++ {
		if changes[i].Table.Pods.Has(pod1) {
			gomega.Expect(pod1LocalTableChange).To(gomega.BeNil())
			pod1LocalTableChange = changes[i]
		}
		if changes[i].Table.Pods.Has(pod3) {
			gomega.Expect(pod3LocalTableChange).To(gomega.BeNil())
			pod3LocalTableChange = changes[i]
		}
		if changes[i].PreviousPods.Has(pod1) {
			gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeFalse())
			pod1LocalTableTxn1Removed = true
		}
		if changes[i].PreviousPods.Has(pod3) {
			gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeFalse())
			pod3LocalTableTxn1Removed = true
		}
	}
	gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod1LocalTableChange).ToNot(gomega.BeNil())
	gomega.Expect(pod3LocalTableChange).ToNot(gomega.BeNil())

	verifyLocalTableChange(pod1LocalTableChange, nil, pod1LocalRulesTxn2, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn2 := pod1LocalTableChange.Table
	verifyLocalTableChange(pod3LocalTableChange, nil, pod3LocalRulesTxn2, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn2 := pod3LocalTableChange.Table

	// Global table has changed.
	verifyGlobalTableChange(changes[4], nil, globalTableTxn1, globalRulesTxn2)
	globalTableTxn2 := changes[4].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1Txn2Cfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn2, pod1LocalRulesTxn2, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn2, pod3LocalRulesTxn2, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRulesTxn2)
}

func TestRemovedPodsEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestRemovedPodsEgressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs[:2]...) /* second TXN removes pod3 */

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts3.rule1, ts3.rule2, ts3.rule3, ts3.rule4}
	orderedEgress := []*renderer.ContivRule{ts3.rule1, ts3.rule3, ts3.rule2, ts3.rule4}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}
	pod3CfgTxn2 := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: EmptyRules,
		Egress:  EmptyRules,
		Removed: true,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, pods1)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Single local table was added.
	verifyLocalTableChange(changes[0], nil, orderedEgress, EmptyPodSet, pods1)
	localTableTxn := changes[0].Table

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedEgress, pods1)
	}
	verifyCachedPods(ruleCache, pods1, pods1)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	// Run second transaction.
	// Pod3 is removed.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	txn.Update(pod3, pod3CfgTxn2)
	verifyUpdatedPods(txn, pods1, NewPodSet(pod3))
	verifyCachedPods(txn, pods2, pods2)

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// pod3 was unassigned from the local table.
	verifyLocalTableChange(changes[0], localTableTxn, orderedEgress, pods1, pods2)

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodLocalTable(ruleCache, podIDs[i], localTableTxn, orderedEgress, pods2)
	}
	verifyPodConfig(ruleCache, pod3, nil)
	verifyPodNilLocalTable(ruleCache, pod3)
	verifyCachedPods(ruleCache, pods2, pods2)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTable, nil, EmptyRules)

	/* Also test cache flushing */
	ruleCache.Flush()
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], nil)
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyGlobalTable(ruleCache.GetGlobalTable(), nil, nil, EmptyRules)
}

func TestRemovedPodsIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestRemovedPodsIngressOrientation")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs[:2]...) /* second TXN contains all pods */
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{ts3.rule1, ts3.rule2, ts3.rule3, ts3.rule4}

	podCfg := []*PodConfig{}
	for i := range podIDs {
		podCfg = append(podCfg,
			&PodConfig{
				PodIP:   GetOneHostSubnet(podIPs[i]),
				Ingress: ingress,
				Egress:  egress,
				Removed: false,
			})
	}
	pod3CfgTxn2 := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: EmptyRules,
		Egress:  EmptyRules,
		Removed: true,
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)
	globalTable := ruleCache.GetGlobalTable()

	// Expected global table content after the first transaction.
	var globalRules []*renderer.ContivRule
	globalRules = append(globalRules, modifyDst(ts3.rule1, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule3, podIPs[:3]...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(ts3.rule2, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule4, podIPs[:3]...)...)
	globalRules = append(globalRules, allowAllUDP())

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, EmptyPodSet)

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	verifyGlobalTableChange(changes[0], nil, globalTable, globalRules)
	globalTableTxn1 := changes[0].Table

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyCachedPods(ruleCache, pods1, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn1, globalTable, globalRules)

	// Run second transaction.
	// Pod3 is removed.
	txn = ruleCache.NewTxn()

	for i := 0; i < len(pods2); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	txn.Update(pod3, pod3CfgTxn2)
	verifyUpdatedPods(txn, pods1, NewPodSet(pod3))
	verifyCachedPods(txn, pods2, EmptyPodSet)

	// Expected global table content after the second transaction.
	globalRules = []*renderer.ContivRule{}
	globalRules = append(globalRules, modifyDst(ts3.rule1, podIPs[:2]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule3, podIPs[:2]...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(ts3.rule2, podIPs[:2]...)...)
	globalRules = append(globalRules, modifyDst(ts3.rule4, podIPs[:2]...)...)
	globalRules = append(globalRules, allowAllUDP())

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed again.
	verifyGlobalTableChange(changes[0], nil, globalTableTxn1, globalRules)
	globalTableTxn2 := changes[0].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	for i := 0; i < len(pods2); i++ {
		verifyPodConfig(ruleCache, podIDs[i], podCfg[i])
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyPodConfig(ruleCache, pod3, nil)
	verifyPodNilLocalTable(ruleCache, pod3)
	verifyCachedPods(ruleCache, pods2, EmptyPodSet)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTableTxn1, globalRules)

	/* Also test cache flushing */
	ruleCache.Flush()
	for i := 0; i < len(pods1); i++ {
		verifyPodConfig(ruleCache, podIDs[i], nil)
		verifyPodNilLocalTable(ruleCache, podIDs[i])
	}
	verifyGlobalTable(ruleCache.GetGlobalTable(), nil, nil, EmptyRules)
}

func TestResyncEgressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestResyncEgressOrientation")

	// Prepare input data
	pods := NewPodSet(pod1, pod3)
	pod1ResyncCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress[1:],
		Egress:  ts5.pod1Egress[:2],
		Removed: false,
	}
	pod1TxnCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress,
		Egress:  ts5.pod1Egress,
		Removed: false,
	}
	pod3Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: ts5.pod3Ingress,
		Egress:  ts5.pod3Egress,
		Removed: false,
	}

	// Resync data taken from the outcome of Txn1 in TestCombinedRulesEgressOrientation:
	//  -> pod1 local table
	pod1LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodEgress(pod1IP, renderer.TCP),
		allowPodEgress(pod3IP, 22, renderer.TCP), blockPodEgress(pod3IP, renderer.TCP),
		/* UDP: */ allowPodEgress(pod1IP, 161, renderer.UDP), blockPodEgress(pod1IP, renderer.UDP),
		pod1ResyncCfg.Egress[1] /* smaller subnet */, pod1ResyncCfg.Egress[0],
	}
	pod1LocalTable := NewContivRuleTable("pod1-local")
	pod1LocalTable.Pods.Add(pod1)
	for _, rule := range pod1LocalRules {
		pod1LocalTable.InsertRule(rule)
	}

	//  -> pod3 local table
	pod3LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodEgress(pod1IP, renderer.TCP),
		blockPodEgress(pod3IP, renderer.TCP), ts5.pod3Egress[0], ts5.pod3Egress[1], ts5.pod3Egress[3],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP), blockPodEgress(pod3IP, renderer.UDP),
		ts5.pod3Egress[2], ts5.pod3Egress[4],
	}
	pod3LocalTable := NewContivRuleTable("pod3-local")
	pod3LocalTable.Pods.Add(pod3)
	for _, rule := range pod3LocalRules {
		pod3LocalTable.InsertRule(rule)
	}

	//  -> global table
	globalRules := []*renderer.ContivRule{}
	/* TCP: */
	globalRules = append(globalRules, modifySrc(pod1IP, pod1ResyncCfg.Ingress[1])...)
	globalRules = append(globalRules, modifySrc(pod3IP, pod3Cfg.Ingress[1], pod3Cfg.Ingress[2])...)
	globalRules = append(globalRules, allowAllTCP())
	/* UDP: */
	globalRules = append(globalRules, modifySrc(pod1IP, pod1ResyncCfg.Ingress[0], pod1ResyncCfg.Ingress[2])...)
	globalRules = append(globalRules, modifySrc(pod3IP, pod3Cfg.Ingress[0], pod3Cfg.Ingress[3])...)
	globalRules = append(globalRules, allowAllUDP())
	globalTable := NewContivRuleTable(GlobalTableID)
	for _, rule := range globalRules {
		globalTable.InsertRule(rule)
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)

	// Resync
	err := ruleCache.Resync([]*ContivRuleTable{pod1LocalTable, pod3LocalTable, globalTable})
	gomega.Expect(err).To(gomega.BeNil())

	// Run transaction - update both pods, but only pod1 has data changed
	txn := ruleCache.NewTxn()
	txn.Update(pod1, pod1TxnCfg)
	txn.Update(pod3, pod3Cfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Expected output data
	pod1LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ pod1TxnCfg.Egress[2],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP),
		pod1TxnCfg.Egress[1] /* smaller subnet */, pod1TxnCfg.Egress[0], pod1TxnCfg.Egress[3],
	}
	pod3LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ allowPodEgress(pod1IP, 80, renderer.TCP), blockPodEgress(pod1IP, renderer.TCP),
		blockPodEgress(pod3IP, renderer.TCP),
		ts5.pod3Egress[0], ts5.pod3Egress[1], ts5.pod3Egress[3],
		/* UDP: */ blockPodEgress(pod1IP, renderer.UDP), blockPodEgress(pod3IP, renderer.UDP),
		ts5.pod3Egress[2], ts5.pod3Egress[4],
	}
	globalRulesTxn2 := []*renderer.ContivRule{}
	/* TCP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod1IP, pod1TxnCfg.Ingress[0], pod1TxnCfg.Ingress[2])...)
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod3IP, pod3Cfg.Ingress[1], pod3Cfg.Ingress[2])...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllTCP())
	/* UDP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod1IP, pod1TxnCfg.Ingress[1], pod1TxnCfg.Ingress[3])...)
	globalRulesTxn2 = append(globalRulesTxn2, modifySrc(pod3IP, pod3Cfg.Ingress[0], pod3Cfg.Ingress[3])...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllUDP())

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(5))

	// Two new local tables.
	var pod1LocalTableChange *TxnChange
	var pod3LocalTableChange *TxnChange
	var pod1LocalTableTxn1Removed, pod3LocalTableTxn1Removed bool
	for i := 0; i < 4; i++ {
		if changes[i].Table.Pods.Has(pod1) {
			gomega.Expect(pod1LocalTableChange).To(gomega.BeNil())
			pod1LocalTableChange = changes[i]
		}
		if changes[i].Table.Pods.Has(pod3) {
			gomega.Expect(pod3LocalTableChange).To(gomega.BeNil())
			pod3LocalTableChange = changes[i]
		}
		if changes[i].PreviousPods.Has(pod1) {
			gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeFalse())
			pod1LocalTableTxn1Removed = true
		}
		if changes[i].PreviousPods.Has(pod3) {
			gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeFalse())
			pod3LocalTableTxn1Removed = true
		}
	}
	gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod1LocalTableChange).ToNot(gomega.BeNil())
	gomega.Expect(pod3LocalTableChange).ToNot(gomega.BeNil())

	verifyLocalTableChange(pod1LocalTableChange, nil, pod1LocalRulesTxn2, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn2 := pod1LocalTableChange.Table
	verifyLocalTableChange(pod3LocalTableChange, nil, pod3LocalRulesTxn2, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn2 := pod3LocalTableChange.Table

	// Global table has changed.
	verifyGlobalTableChange(changes[4], nil, globalTable, globalRulesTxn2)
	globalTableTxn2 := changes[4].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1TxnCfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn2, pod1LocalRulesTxn2, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn2, pod3LocalRulesTxn2, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTable, globalRulesTxn2)
}

func TestResyncIngressOrientation(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestResyncIngressOrientation")

	// Prepare input data
	pods := NewPodSet(pod1, pod3)
	pod1ResyncCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress[1:],
		Egress:  ts5.pod1Egress[:2],
		Removed: false,
	}
	pod1TxnCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod1IP),
		Ingress: ts5.pod1Ingress,
		Egress:  ts5.pod1Egress,
		Removed: false,
	}
	pod3Cfg := &PodConfig{
		PodIP:   GetOneHostSubnet(pod3IP),
		Ingress: ts5.pod3Ingress,
		Egress:  ts5.pod3Egress,
		Removed: false,
	}

	// Resync data taken from the outcome of Txn1 in TestCombinedRulesIngressOrientation:
	//  -> pod1 local table
	pod1LocalRules := []*renderer.ContivRule{
		/* TCP: */ pod1ResyncCfg.Ingress[1],
		/* UDP: */ blockPodIngress(pod3IP, renderer.UDP),
		pod1ResyncCfg.Ingress[0], pod1ResyncCfg.Ingress[2],
	}
	pod1LocalTable := NewContivRuleTable("pod1-local")
	pod1LocalTable.Pods.Add(pod1)
	for _, rule := range pod1LocalRules {
		pod1LocalTable.InsertRule(rule)
	}

	//  -> pod3 local table
	pod3LocalRules := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod3IP, renderer.TCP),
		pod3Cfg.Ingress[1], pod3Cfg.Ingress[2],
		/* UDP: */ pod3Cfg.Ingress[0], pod3Cfg.Ingress[3],
	}
	pod3LocalTable := NewContivRuleTable("pod3-local")
	pod3LocalTable.Pods.Add(pod3)
	for _, rule := range pod3LocalRules {
		pod3LocalTable.InsertRule(rule)
	}

	//  -> global table
	globalRules := []*renderer.ContivRule{}
	/* TCP: */
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[0], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[1], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[3], pod3IP)...)
	globalRules = append(globalRules, allowAllTCP())
	/* UDP: */
	globalRules = append(globalRules, modifyDst(pod1ResyncCfg.Egress[1], pod1IP)...)
	globalRules = append(globalRules, modifyDst(pod1ResyncCfg.Egress[0], pod1IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[2], pod3IP)...)
	globalRules = append(globalRules, modifyDst(pod3Cfg.Egress[4], pod3IP)...)
	globalRules = append(globalRules, allowAllUDP())
	globalTable := NewContivRuleTable(GlobalTableID)
	for _, rule := range globalRules {
		globalTable.InsertRule(rule)
	}

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(IngressOrientation)

	// Resync
	err := ruleCache.Resync([]*ContivRuleTable{pod1LocalTable, pod3LocalTable, globalTable})
	gomega.Expect(err).To(gomega.BeNil())

	// Run transaction - update both pods, but only pod1 has data changed
	txn := ruleCache.NewTxn()
	txn.Update(pod1, pod1TxnCfg)
	txn.Update(pod3, pod3Cfg)
	verifyUpdatedPods(txn, pods, EmptyPodSet)
	verifyCachedPods(txn, pods, pods)

	// Expected output data
	pod1LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod1IP, renderer.TCP),
		pod1TxnCfg.Ingress[0], pod1TxnCfg.Ingress[2],
		/* UDP: */ blockPodIngress(pod1IP, renderer.UDP), blockPodIngress(pod3IP, renderer.UDP),
		pod1TxnCfg.Ingress[1], pod1TxnCfg.Ingress[3],
	}
	pod3LocalRulesTxn2 := []*renderer.ContivRule{
		/* TCP: */ blockPodIngress(pod1IP, renderer.TCP), blockPodIngress(pod3IP, renderer.TCP),
		pod3Cfg.Ingress[1], pod3Cfg.Ingress[2],
		/* UDP: */ allowPodIngress(pod1IP, 53, renderer.UDP), blockPodIngress(pod1IP, renderer.UDP),
		/* removed: pod3Cfg.Ingress[0],*/ pod3Cfg.Ingress[3],
	}
	globalRulesTxn2 := []*renderer.ContivRule{}
	/* TCP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[0], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[1], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1TxnCfg.Egress[2], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[3], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllTCP())
	/* UDP: */
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1TxnCfg.Egress[1], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1TxnCfg.Egress[0], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod1TxnCfg.Egress[3], pod1IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[2], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, modifyDst(pod3Cfg.Egress[4], pod3IP)...)
	globalRulesTxn2 = append(globalRulesTxn2, allowAllUDP())

	// Verify changes to be committed.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(5))

	// Two new local tables.
	var pod1LocalTableChange *TxnChange
	var pod3LocalTableChange *TxnChange
	var pod1LocalTableTxn1Removed, pod3LocalTableTxn1Removed bool
	for i := 0; i < 4; i++ {
		if changes[i].Table.Pods.Has(pod1) {
			gomega.Expect(pod1LocalTableChange).To(gomega.BeNil())
			pod1LocalTableChange = changes[i]
		}
		if changes[i].Table.Pods.Has(pod3) {
			gomega.Expect(pod3LocalTableChange).To(gomega.BeNil())
			pod3LocalTableChange = changes[i]
		}
		if changes[i].PreviousPods.Has(pod1) {
			gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeFalse())
			pod1LocalTableTxn1Removed = true
		}
		if changes[i].PreviousPods.Has(pod3) {
			gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeFalse())
			pod3LocalTableTxn1Removed = true
		}
	}
	gomega.Expect(pod1LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod3LocalTableTxn1Removed).To(gomega.BeTrue())
	gomega.Expect(pod1LocalTableChange).ToNot(gomega.BeNil())
	gomega.Expect(pod3LocalTableChange).ToNot(gomega.BeNil())

	verifyLocalTableChange(pod1LocalTableChange, nil, pod1LocalRulesTxn2, EmptyPodSet, NewPodSet(pod1))
	pod1LocalTableTxn2 := pod1LocalTableChange.Table
	verifyLocalTableChange(pod3LocalTableChange, nil, pod3LocalRulesTxn2, EmptyPodSet, NewPodSet(pod3))
	pod3LocalTableTxn2 := pod3LocalTableChange.Table

	// Global table has changed.
	verifyGlobalTableChange(changes[4], nil, globalTable, globalRulesTxn2)
	globalTableTxn2 := changes[4].Table

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	verifyPodConfig(ruleCache, pod1, pod1TxnCfg)
	verifyPodConfig(ruleCache, pod3, pod3Cfg)
	verifyPodLocalTable(ruleCache, pod1, pod1LocalTableTxn2, pod1LocalRulesTxn2, NewPodSet(pod1))
	verifyPodLocalTable(ruleCache, pod3, pod3LocalTableTxn2, pod3LocalRulesTxn2, NewPodSet(pod3))
	verifyCachedPods(ruleCache, pods, pods)
	verifyGlobalTable(ruleCache.GetGlobalTable(), globalTableTxn2, globalTable, globalRulesTxn2)
}
