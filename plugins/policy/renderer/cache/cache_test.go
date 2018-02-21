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
)

var (
	EmptyPodSet = NewPodSet()
	EmptyRules  = []*renderer.ContivRule{}
)

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
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

func TestSingleEgressRuleOnePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleOnePod")

	// Prepare input data.
	pod1 := podIDs[0]
	pods := NewPodSet(pod1)

	rule := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// 1. Egress Orientation

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

	// 2. Ingress Orientation

	ruleCache.Flush()
	ruleCache.Init(IngressOrientation)

	// Expected global table content.
	globalRules := modifyDst(rule, podIPs[0])
	globalRules = append(globalRules, allowAllTCP(), allowAllUDP())

	// Check initial cache content
	globalTable = ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn = ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes = txn.GetChanges()
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
	err = txn.Commit()
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

func TestSingleIngressRuleOnePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleOnePod")

	// Prepare input data.
	pod1 := podIDs[0]
	pods := NewPodSet(pod1)

	rule := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("192.168.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{rule}
	egress := []*renderer.ContivRule{}
	podCfg := &PodConfig{
		PodIP:   GetOneHostSubnet(podIPs[0]),
		Ingress: ingress,
		Egress:  egress,
		Removed: false,
	}

	// 1. Egress Orientation

	// Create an instance of RendererCache
	ruleCache := &RendererCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(EgressOrientation)

	// Expected global table content.
	globalRules := modifySrc(podIPs[0], rule)
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

	// 2. Ingress Orientation

	ruleCache.Flush()
	ruleCache.Init(IngressOrientation)

	// Check initial cache content
	globalTable = ruleCache.GetGlobalTable()
	verifyGlobalTable(globalTable, nil, nil, EmptyRules)
	verifyCachedPods(ruleCache, EmptyPodSet, EmptyPodSet)

	// Run single transaction.
	txn = ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes = txn.GetChanges()
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
	err = txn.Commit()
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

func TestMultipleEgressRulesMultiplePods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleEgressRulesMultiplePods")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */

	rule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.10.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}
	rule2 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.10.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}
	rule3 := denyAllTCP()
	rule4 := denyAllUDP()

	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule1, rule2, rule3, rule4}
	orderedEgress := []*renderer.ContivRule{rule1, rule3, rule2, rule4}

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

	// 1. Egress Orientation

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

	// 2. Ingress Orientation

	ruleCache.Flush()
	ruleCache.Init(IngressOrientation)

	// Expected global table content after the first transaction.
	var globalRules []*renderer.ContivRule
	globalRules = append(globalRules, modifyDst(rule1, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(rule3, podIPs[:3]...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(rule2, podIPs[:3]...)...)
	globalRules = append(globalRules, modifyDst(rule4, podIPs[:3]...)...)
	globalRules = append(globalRules, allowAllUDP())

	// Run first transaction.
	txn = ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, EmptyPodSet)

	// Verify changes to be committed.
	changes = txn.GetChanges()
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
	err = txn.Commit()
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
	globalRules = append(globalRules, modifyDst(rule1, podIPs...)...)
	globalRules = append(globalRules, modifyDst(rule3, podIPs...)...) /* TCP before UDP */
	globalRules = append(globalRules, allowAllTCP())
	globalRules = append(globalRules, modifyDst(rule2, podIPs...)...)
	globalRules = append(globalRules, modifyDst(rule4, podIPs...)...)
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

func TestMultipleIngressRulesMultiplePods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleIngressRulesMultiplePods")

	// Prepare input data.
	pods1 := NewPodSet(podIDs[:3]...) /* first TXN contains pod1-pod3 */
	pods2 := NewPodSet(podIDs...)     /* second TXN contains all pods */

	rule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.10.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}
	rule2 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.10.0.0/16"),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}
	rule3 := denyAllTCP()
	rule4 := denyAllUDP()

	ingress := []*renderer.ContivRule{rule1, rule2, rule3, rule4}
	egress := []*renderer.ContivRule{}
	orderedIngress := []*renderer.ContivRule{rule1, rule3, rule2, rule4}

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

	// 1. Egress Orientation

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
		globalRules = append(globalRules, modifySrc(podIPs[i], rule1, rule3)...)
	}
	globalRules = append(globalRules, allowAllTCP())
	for i := 0; i < len(pods1); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], rule2, rule4)...)
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
		globalRules = append(globalRules, modifySrc(podIPs[i], rule1, rule3)...)
	}
	globalRules = append(globalRules, allowAllTCP())
	for i := 0; i < len(pods2); i++ {
		globalRules = append(globalRules, modifySrc(podIPs[i], rule2, rule4)...)
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

	// 2. Ingress Orientation

	ruleCache.Flush()
	ruleCache.Init(IngressOrientation)
	globalTable = ruleCache.GetGlobalTable()

	// Run first transaction.
	txn = ruleCache.NewTxn()

	// Perform update of the first three pods.
	for i := 0; i < len(pods1); i++ {
		txn.Update(podIDs[i], podCfg[i])
		verifyPodConfig(txn, podIDs[i], podCfg[i])
	}
	verifyUpdatedPods(txn, pods1, EmptyPodSet)
	verifyCachedPods(txn, pods1, pods1)

	// Verify changes to be committed.
	changes = txn.GetChanges()
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
	err = txn.Commit()
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

/* TODO: test for combined rules */
/* TODO: test for combined rules with Resync */
