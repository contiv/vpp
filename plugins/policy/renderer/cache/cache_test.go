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
	"github.com/onsi/gomega"
	"net"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	. "github.com/contiv/vpp/plugins/policy/utils"
)

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func verifyRules(table *ContivRuleTable, rules []*renderer.ContivRule) {
	gomega.Expect(
		compareRuleLists(table.Rules[:table.NumOfRules], rules)).To(
		gomega.BeEquivalentTo(0))
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

func TestSingleEgressRuleOnePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleOnePod")

	// Prepare input data.
	const (
		namespace = "default"
		pod1Name  = "pod1"
		pod1IP    = "10.10.1.1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pods := NewPodSet(pod1)

	rule := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}
	podCfg := &PodConfig{PodIP: GetOneHostSubnet(pod1IP), Ingress: ingress, Egress: egress, Removed: false}

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
	gomega.Expect(globalTable).ToNot(gomega.BeNil())
	gomega.Expect(globalTable.ID).To(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(globalTable.Type).To(gomega.BeEquivalentTo(Global))
	verifyRules(globalTable, []*renderer.ContivRule{})
	gomega.Expect(globalTable.Pods).To(gomega.BeEmpty())

	// Run single transaction.
	txn := ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes := txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	gomega.Expect(txn.GetPodConfig(pod1)).To(gomega.Equal(podCfg))
	gomega.Expect(txn.GetUpdatedPods()).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(txn.GetRemovedPods()).To(gomega.BeEmpty())
	gomega.Expect(txn.GetAllPods()).To(gomega.BeEquivalentTo(pods))

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Local table was added.
	change := changes[0]
	gomega.Expect(change.Table).ToNot(gomega.BeNil())
	gomega.Expect(change.Table.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(change.Table.Type).To(gomega.Equal(Local))
	verifyRules(change.Table, egress)
	gomega.Expect(change.Table.Pods).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(change.PreviousPods).To(gomega.BeEmpty())
	localTableTxn := change.Table

	// Test what the cache will contain after the transaction.
	gomega.Expect(txn.GetIsolatedPods()).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(txn.GetLocalTableByPod(pod1)).To(gomega.BeEquivalentTo(localTableTxn))
	globalTableTxn := txn.GetGlobalTable()
	gomega.Expect(globalTableTxn).ToNot(gomega.BeNil())
	gomega.Expect(globalTableTxn.ID).To(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(globalTableTxn.Type).To(gomega.BeEquivalentTo(Global))
	verifyRules(globalTableTxn, []*renderer.ContivRule{})
	gomega.Expect(globalTableTxn.Pods).To(gomega.BeEmpty())

	// Changes should be applied only after the commit.
	gomega.Expect(ruleCache.GetPodConfig(pod1)).To(gomega.BeNil())
	gomega.Expect(ruleCache.GetAllPods()).To(gomega.BeEmpty())
	gomega.Expect(ruleCache.GetIsolatedPods()).To(gomega.BeEmpty())
	gomega.Expect(ruleCache.GetLocalTableByPod(pod1)).To(gomega.BeNil())
	gomega.Expect(ruleCache.GetGlobalTable()).To(gomega.BeEquivalentTo(globalTable))

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	gomega.Expect(ruleCache.GetPodConfig(pod1)).To(gomega.Equal(podCfg))
	gomega.Expect(ruleCache.GetAllPods()).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(ruleCache.GetLocalTableByPod(pod1).ID).To(gomega.BeEquivalentTo(localTableTxn.ID))
	gomega.Expect(ruleCache.GetGlobalTable()).To(gomega.Equal(globalTable))
	gomega.Expect(ruleCache.GetIsolatedPods()).To(gomega.BeEquivalentTo(pods))

	// 2. Ingress Orientation
	ruleCache.Flush()
	ruleCache.Init(IngressOrientation)

	// Expected global table content.
	globalRule := rule.Copy()
	globalRule.DestNetwork = GetOneHostSubnet(pod1IP)
	globalRules := []*renderer.ContivRule{globalRule, allowAllTCP(), allowAllUDP()} /* order matters */

	// Check initial cache content
	globalTable = ruleCache.GetGlobalTable()
	gomega.Expect(globalTable).ToNot(gomega.BeNil())
	gomega.Expect(globalTable.ID).To(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(globalTable.Type).To(gomega.BeEquivalentTo(Global))
	verifyRules(globalTable, []*renderer.ContivRule{})
	gomega.Expect(globalTable.Pods).To(gomega.BeEmpty())

	// Run single transaction.
	txn = ruleCache.NewTxn()

	// Verify that initially there are no changes.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Perform single update.
	txn.Update(pod1, podCfg)
	gomega.Expect(txn.GetPodConfig(pod1)).To(gomega.Equal(podCfg))
	gomega.Expect(txn.GetUpdatedPods()).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(txn.GetRemovedPods()).To(gomega.BeEmpty())
	gomega.Expect(txn.GetAllPods()).To(gomega.BeEquivalentTo(pods))

	// Verify changes to be committed.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(1))

	// Global table has changed.
	change = changes[0]
	gomega.Expect(change.Table).ToNot(gomega.BeNil())
	gomega.Expect(change.Table.ID).To(gomega.BeEquivalentTo(GlobalTableID))
	gomega.Expect(change.Table.Type).To(gomega.Equal(Global))
	verifyRules(change.Table, globalRules)
	gomega.Expect(change.Table.Pods).To(gomega.BeEmpty())
	gomega.Expect(change.PreviousPods).To(gomega.BeEmpty())
	globalTableTxn = change.Table
	gomega.Expect(globalTableTxn).ToNot(gomega.Equal(globalTable))

	// Test what the cache will contain after the transaction.
	gomega.Expect(txn.GetIsolatedPods()).To(gomega.BeEmpty())
	gomega.Expect(txn.GetLocalTableByPod(pod1)).To(gomega.BeNil())
	gomega.Expect(txn.GetGlobalTable()).To(gomega.Equal(globalTableTxn))

	// Changes should be applied only after the commit.
	gomega.Expect(ruleCache.GetPodConfig(pod1)).To(gomega.BeNil())
	gomega.Expect(ruleCache.GetAllPods()).To(gomega.BeEmpty())
	gomega.Expect(ruleCache.GetIsolatedPods()).To(gomega.BeEmpty())
	gomega.Expect(ruleCache.GetLocalTableByPod(pod1)).To(gomega.BeNil())
	gomega.Expect(ruleCache.GetGlobalTable()).To(gomega.Equal(globalTable))

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	changes = txn.GetChanges()
	gomega.Expect(changes).To(gomega.HaveLen(0))

	// Verify cache content.
	gomega.Expect(ruleCache.GetPodConfig(pod1)).To(gomega.Equal(podCfg))
	gomega.Expect(ruleCache.GetAllPods()).To(gomega.BeEquivalentTo(pods))
	gomega.Expect(ruleCache.GetLocalTableByPod(pod1)).To(gomega.BeNil())
	gomega.Expect(ruleCache.GetGlobalTable()).To(gomega.Equal(globalTableTxn))
	verifyRules(ruleCache.GetGlobalTable(), globalRules)
	gomega.Expect(ruleCache.GetGlobalTable().Pods).To(gomega.BeEmpty())
	gomega.Expect(ruleCache.GetIsolatedPods()).To(gomega.BeEmpty())
}

/*
func TestSingleContivRuleMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleMultipleInterfaces")

	// Create an instance of ContivRuleCache
	ruleCache := &ContivRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init()

	// Prepare input data.
	rule := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update of the same rules for multiple interfaces.
	ifSet := NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")
	for ifName := range ifSet {
		err := txn.Update(ifName, ingress, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))

	// Verify changes to be committed.
	ingressChanges, egressChanges := txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(1))
	gomega.Expect(egressChanges).To(gomega.HaveLen(1))

	change := ingressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet))
	ingressListID := change.List.ID

	change = egressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet))
	egressListID := change.List.ID

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress1, ifEgress1 := ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSet))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSet))

	ifIngress2, ifEgress2 := ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())
	ifIngress3, ifEgress3 := ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))
	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))

	// Run second transaction.
	txn = ruleCache.NewTxn()

	// Add two more interfaces.
	ifSet2 := ifSet.Copy()
	ifSet2.Add("afpacket4")
	ifSet2.Add("afpacket5")
	for ifName := range ifSet2 {
		err := txn.Update(ifName, ingress, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet2))

	// Verify changes to be committed.
	ingressChanges, egressChanges = txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(1))
	gomega.Expect(egressChanges).To(gomega.HaveLen(1))

	change = ingressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).To(gomega.BeEquivalentTo(ingressListID))
	gomega.Expect(compareRuleLists(change.List.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(ifSet))
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet2))

	change = egressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(change.List.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(ifSet))
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet2))

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet2))
	ifIngress1, ifEgress1 = ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSet2))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSet2))

	ifIngress2, ifEgress2 = ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())
	ifIngress3, ifEgress3 = ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())
	ifIngress4, ifEgress4 := ruleCache.LookupByInterface("afpacket4")
	gomega.Expect(ifIngress4).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress4).ToNot(gomega.BeNil())
	ifIngress5, ifEgress5 := ruleCache.LookupByInterface("afpacket5")
	gomega.Expect(ifIngress5).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress5).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))
	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))
	gomega.Expect(ifIngress4.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress4.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))
	gomega.Expect(ifIngress5.ID).To(gomega.BeEquivalentTo(ifIngress1.ID))
	gomega.Expect(ifEgress5.ID).To(gomega.BeEquivalentTo(ifEgress1.ID))
}

func TestMultipleContivRulesSingleInterface(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesSingleInterface")

	// Create an instance of ContivRuleCache
	ruleCache := &ContivRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init()

	// Prepare input data.
	egRule1 := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule2 := &renderer.ContivRule{
		ID:          "deny-https",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    443,
	}
	inRule1 := &renderer.ContivRule{
		ID:          "deny-ssh",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("192.168.1.0/24"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		ID:          "random-rule",
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.0.0.0/8"),
		DestNetwork: ipNetwork("192.168.1.1/32"),
		Protocol:    renderer.UDP,
		SrcPort:     1111,
		DestPort:    2222,
	}
	ingress := []*renderer.ContivRule{inRule1, inRule2}
	egress := []*renderer.ContivRule{egRule1, egRule2}

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update for single interface.
	ifSet := NewInterfaceSet("afpacket1")
	for ifName := range ifSet {
		err := txn.Update(ifName, ingress, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))

	// Verify changes to be committed.
	ingressChanges, egressChanges := txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(1))
	gomega.Expect(egressChanges).To(gomega.HaveLen(1))

	change := ingressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet))
	ingressListID := change.List.ID

	change = egressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet))
	egressListID := change.List.ID

	// Commit changes into the cache.
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress, ifEgress := ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress.ID).To(gomega.BeEquivalentTo(ingressListID))
	gomega.Expect(compareRuleLists(ifIngress.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress.Interfaces).To(gomega.BeEquivalentTo(ifSet))

	gomega.Expect(ifEgress.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(ifEgress.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress.Interfaces).To(gomega.BeEquivalentTo(ifSet))

	// Run second transaction.
	txn = ruleCache.NewTxn()

	// Add ingress rule.
	inRule3 := &renderer.ContivRule{
		ID:          "new-rule",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("10.10.0.0/16"),
		DestNetwork: ipNetwork("192.168.1.1/32"),
		Protocol:    renderer.TCP,
		SrcPort:     3333,
		DestPort:    4444,
	}
	ingress2 := []*renderer.ContivRule{inRule1, inRule2, inRule3}
	var ingress2ListID string

	// Update interface rules.
	for ifName := range ifSet {
		err := txn.Update(ifName, ingress2, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))

	// Verify changes to be committed.
	ingressChanges, egressChanges = txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(2))
	gomega.Expect(egressChanges).To(gomega.HaveLen(0))

	for _, change := range ingressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if change.List.ID == ingressListID {
			// Original list for ingress was removed.
			gomega.Expect(compareRuleLists(change.List.Rules, ingress)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(ifSet))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEmpty())
		} else {
			// New list created for ingress.
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
			gomega.Expect(compareRuleLists(change.List.Rules, ingress2)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSet))
			ingress2ListID = change.List.ID
		}
	}

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress, ifEgress = ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress.ID).To(gomega.BeEquivalentTo(ingress2ListID))
	gomega.Expect(compareRuleLists(ifIngress.Rules, ingress2)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress.Interfaces).To(gomega.BeEquivalentTo(ifSet))

	gomega.Expect(ifEgress.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(ifEgress.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress.Interfaces).To(gomega.BeEquivalentTo(ifSet))
}

func TestMultipleContivRulesMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfaces")

	// Create an instance of ContivRuleCache
	ruleCache := &ContivRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init()

	// Prepare input data.
	egRule1 := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule2 := &renderer.ContivRule{
		ID:          "deny-https",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    443,
	}
	inRule1 := &renderer.ContivRule{
		ID:          "deny-ssh",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("192.168.1.0/24"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		ID:          "random-rule",
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.0.0.0/8"),
		DestNetwork: ipNetwork("192.168.1.1/32"),
		Protocol:    renderer.UDP,
		SrcPort:     1111,
		DestPort:    2222,
	}
	ingressA := []*renderer.ContivRule{inRule1, inRule2} // afpacket1, afpacket2
	ingressB := []*renderer.ContivRule{}                 // afpacket3
	egressA := []*renderer.ContivRule{egRule2}           // afpacket1
	egressB := []*renderer.ContivRule{egRule1, egRule2}  // afpacket2, afpacket3
	var ingressAListID string
	var ingressBListID string
	var egressAListID string
	var egressBListID string

	// Run first transaction.
	txn := ruleCache.NewTxn()

	// Perform update for multiple interfaces.
	ifSet := NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")
	ifSetInA := NewInterfaceSet("afpacket1", "afpacket2")
	ifSetInB := NewInterfaceSet("afpacket3")
	ifSetEgA := NewInterfaceSet("afpacket1")
	ifSetEgB := NewInterfaceSet("afpacket2", "afpacket3")

	err := txn.Update("afpacket1", ingressA, egressA)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket2", ingressA, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket3", ingressB, egressB)
	gomega.Expect(err).To(gomega.BeNil())

	// Verify changes to be committed.
	ingressChanges, egressChanges := txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(2))
	gomega.Expect(egressChanges).To(gomega.HaveLen(2))

	for _, change := range ingressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if compareRuleLists(change.List.Rules, ingressA) == 0 {
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))
			ingressAListID = change.List.ID
		} else {
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
			gomega.Expect(compareRuleLists(change.List.Rules, ingressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInB))
			ingressBListID = change.List.ID
		}
	}

	for _, change := range egressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if compareRuleLists(change.List.Rules, egressA) == 0 {
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgA))
			egressAListID = change.List.ID
		} else {
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
			gomega.Expect(compareRuleLists(change.List.Rules, egressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))
			egressBListID = change.List.ID
		}
	}

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress1, ifEgress1 := ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressAListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSetEgA))

	ifIngress2, ifEgress2 := ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress2.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress2.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress2.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress3, ifEgress3 := ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ingressBListID))
	gomega.Expect(compareRuleLists(ifIngress3.Rules, ingressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress3.Interfaces).To(gomega.BeEquivalentTo(ifSetInB))

	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress3.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress3.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	// Run second transaction.
	txn = ruleCache.NewTxn()

	// Change assignment of rules a bit.
	ingressC := []*renderer.ContivRule{inRule1} // afpacket1, afpacket3
	var ingressCListID string
	ifSetInA = NewInterfaceSet("afpacket2")
	ifSetInB = NewInterfaceSet()
	ifSetInC := NewInterfaceSet("afpacket1", "afpacket3")
	ifSetEgA = NewInterfaceSet()
	ifSetEgB = NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")

	err = txn.Update("afpacket1", ingressC, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket2", ingressA, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket3", ingressC, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))

	// Verify changes to be committed.
	ingressChanges, egressChanges = txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(3))
	gomega.Expect(egressChanges).To(gomega.HaveLen(2))

	for _, change := range ingressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if compareRuleLists(change.List.Rules, ingressC) == 0 {
			// New list created for ingress afpacket1+afpacket3.
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))
			ingressCListID = change.List.ID
		} else if change.List.ID == ingressAListID {
			// -afpacket1
			gomega.Expect(compareRuleLists(change.List.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1", "afpacket2")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))
		} else {
			// -afpacket3 (removed)
			gomega.Expect(compareRuleLists(change.List.Rules, ingressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket3")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInB))
		}
	}

	for _, change := range egressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if change.List.ID == egressAListID {
			// -afpacket1 (removed)
			gomega.Expect(compareRuleLists(change.List.Rules, egressA)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgA))
		} else {
			// +afpacket1
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
			gomega.Expect(compareRuleLists(change.List.Rules, egressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket2", "afpacket3")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))
		}
	}

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress1, ifEgress1 = ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressCListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressC)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress2, ifEgress2 = ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress2.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress2.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress2.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress2.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress3, ifEgress3 = ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ingressCListID))
	gomega.Expect(compareRuleLists(ifIngress3.Rules, ingressC)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress3.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))

	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress3.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress3.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))
}

func TestMultipleContivRulesMultipleInterfacesWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfacesWithResync")

	// Create an instance of ContivRuleCache
	ruleCache := &ContivRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init()

	// Prepare input data.
	egRule1 := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule2 := &renderer.ContivRule{
		ID:          "deny-https",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/16"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    443,
	}
	inRule1 := &renderer.ContivRule{
		ID:          "deny-ssh",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("192.168.1.0/24"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		ID:          "random-rule",
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("10.0.0.0/8"),
		DestNetwork: ipNetwork("192.168.1.1/32"),
		Protocol:    renderer.UDP,
		SrcPort:     1111,
		DestPort:    2222,
	}

	ingressA := []*renderer.ContivRule{inRule1, inRule2} // afpacket1, afpacket2
	ingressB := []*renderer.ContivRule{}                 // afpacket3
	egressA := []*renderer.ContivRule{egRule2}           // afpacket1
	egressB := []*renderer.ContivRule{egRule1, egRule2}  // afpacket2, afpacket3

	ingressAListID := "ingress-A"
	ingressBListID := "ingress-B"
	egressAListID := "egress-A"
	egressBListID := "egress-B"

	ifSet := NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")
	ifSetInA := NewInterfaceSet("afpacket1", "afpacket2")
	ifSetInB := NewInterfaceSet("afpacket3")
	ifSetEgA := NewInterfaceSet("afpacket1")
	ifSetEgB := NewInterfaceSet("afpacket2", "afpacket3")

	ingressLists := []*ContivRuleList{}
	ingressLists = append(ingressLists,
		&ContivRuleList{
			ID:         ingressAListID,
			Rules:      ingressA,
			Interfaces: ifSetInA,
			Private:    nil,
		})
	ingressLists = append(ingressLists,
		&ContivRuleList{
			ID:         ingressBListID,
			Rules:      ingressB,
			Interfaces: ifSetInB,
			Private:    nil,
		})

	egressLists := []*ContivRuleList{}
	egressLists = append(egressLists,
		&ContivRuleList{
			ID:         egressAListID,
			Rules:      egressA,
			Interfaces: ifSetEgA,
			Private:    nil,
		})
	egressLists = append(egressLists,
		&ContivRuleList{
			ID:         egressBListID,
			Rules:      egressB,
			Interfaces: ifSetEgB,
			Private:    nil,
		})

	// Perform Resync for multiple interfaces.
	err := ruleCache.Resync(ingressLists, egressLists)
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress1, ifEgress1 := ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressAListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSetEgA))

	ifIngress2, ifEgress2 := ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress2.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress2.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress2.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress3, ifEgress3 := ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ingressBListID))
	gomega.Expect(compareRuleLists(ifIngress3.Rules, ingressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress3.Interfaces).To(gomega.BeEquivalentTo(ifSetInB))

	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress3.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress3.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	// Run first transaction after the resync.
	txn := ruleCache.NewTxn()

	// Change assignment of rules a bit.
	ingressC := []*renderer.ContivRule{inRule1} // afpacket1, afpacket3
	var ingressCListID string
	ifSetInA = NewInterfaceSet("afpacket2")
	ifSetInB = NewInterfaceSet()
	ifSetInC := NewInterfaceSet("afpacket1", "afpacket3")
	ifSetEgA = NewInterfaceSet()
	ifSetEgB = NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")

	err = txn.Update("afpacket1", ingressC, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket2", ingressA, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	err = txn.Update("afpacket3", ingressC, egressB)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txn.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))

	// Verify changes to be committed.
	ingressChanges, egressChanges := txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(3))
	gomega.Expect(egressChanges).To(gomega.HaveLen(2))

	for _, change := range ingressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if compareRuleLists(change.List.Rules, ingressC) == 0 {
			// New list created for ingress afpacket1+afpacket3.
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))
			ingressCListID = change.List.ID
			gomega.Expect(ingressCListID).ToNot(gomega.BeEquivalentTo(ingressAListID))
			gomega.Expect(ingressCListID).ToNot(gomega.BeEquivalentTo(ingressBListID))
		} else if change.List.ID == ingressAListID {
			// -afpacket1
			gomega.Expect(compareRuleLists(change.List.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1", "afpacket2")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))
		} else {
			// -afpacket3 (removed)
			gomega.Expect(compareRuleLists(change.List.Rules, ingressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket3")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetInB))
		}
	}

	for _, change := range egressChanges {
		gomega.Expect(change.List).ToNot(gomega.BeNil())
		if change.List.ID == egressAListID {
			// -afpacket1 (removed)
			gomega.Expect(compareRuleLists(change.List.Rules, egressA)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgA))
		} else {
			// +afpacket1
			gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
			gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
			gomega.Expect(compareRuleLists(change.List.Rules, egressB)).To(gomega.BeEquivalentTo(0))
			gomega.Expect(change.PreviousInterfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket2", "afpacket3")))
			gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))
		}
	}

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(ifSet))
	ifIngress1, ifEgress1 = ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress1).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress1).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress1.ID).To(gomega.BeEquivalentTo(ingressCListID))
	gomega.Expect(compareRuleLists(ifIngress1.Rules, ingressC)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress1.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))

	gomega.Expect(ifEgress1.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress1.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress1.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress2, ifEgress2 = ruleCache.LookupByInterface("afpacket2")
	gomega.Expect(ifIngress2).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress2).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress2.ID).To(gomega.BeEquivalentTo(ingressAListID))
	gomega.Expect(compareRuleLists(ifIngress2.Rules, ingressA)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress2.Interfaces).To(gomega.BeEquivalentTo(ifSetInA))

	gomega.Expect(ifEgress2.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress2.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress2.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))

	ifIngress3, ifEgress3 = ruleCache.LookupByInterface("afpacket3")
	gomega.Expect(ifIngress3).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress3).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress3.ID).To(gomega.BeEquivalentTo(ingressCListID))
	gomega.Expect(compareRuleLists(ifIngress3.Rules, ingressC)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress3.Interfaces).To(gomega.BeEquivalentTo(ifSetInC))

	gomega.Expect(ifEgress3.ID).To(gomega.BeEquivalentTo(egressBListID))
	gomega.Expect(compareRuleLists(ifEgress3.Rules, egressB)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress3.Interfaces).To(gomega.BeEquivalentTo(ifSetEgB))
}
*/
