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
	"net"
	"testing"

	"strings"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/onsi/gomega"
)

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func TestSingleContivRuleOneInterface(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleOneInterface")

	// Create an instance of ContivRuleCache
	ruleCache := NewContivRuleCache()
	ruleCache.Deps.Log = logger

	// Prepare input data.
	rule := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}

	// Run single transaction.
	txn := ruleCache.NewTxn(false)

	// Verify that initially there are no changes.
	ingressChanges, egressChanges := txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(0))
	gomega.Expect(egressChanges).To(gomega.HaveLen(0))

	// Perform single update.
	err := txn.Update("afpacket1", ingress, egress)
	gomega.Expect(err).To(gomega.BeNil())

	// Verify changes to be committed.
	ingressChanges, egressChanges = txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(1))
	gomega.Expect(egressChanges).To(gomega.HaveLen(1))

	change := ingressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "ingress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
	ingressListID := change.List.ID

	change = egressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
	egressListID := change.List.ID

	// Changes should be applied only after the commit.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEmpty())
	ifIngress, ifEgress := ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress).To(gomega.BeNil())
	gomega.Expect(ifEgress).To(gomega.BeNil())

	// Commit changes into the cache.
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Transaction has finalized, no changes are pending.
	ingressChanges, egressChanges = txn.Changes()
	gomega.Expect(ingressChanges).To(gomega.HaveLen(0))
	gomega.Expect(egressChanges).To(gomega.HaveLen(0))

	// Verify cache content.
	gomega.Expect(ruleCache.AllInterfaces()).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
	ifIngress, ifEgress = ruleCache.LookupByInterface("afpacket1")
	gomega.Expect(ifIngress).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress).ToNot(gomega.BeNil())

	gomega.Expect(ifIngress.ID).To(gomega.BeEquivalentTo(ingressListID))
	gomega.Expect(compareRuleLists(ifIngress.Rules, ingress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifIngress.Interfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))

	gomega.Expect(ifEgress.ID).To(gomega.BeEquivalentTo(egressListID))
	gomega.Expect(compareRuleLists(ifEgress.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ifEgress.Interfaces).To(gomega.BeEquivalentTo(NewInterfaceSet("afpacket1")))
}

func TestSingleContivRuleMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleMultipleInterfaces")

	// Create an instance of ContivRuleCache
	ruleCache := NewContivRuleCache()
	ruleCache.Deps.Log = logger

	// Prepare input data.
	rule := &renderer.ContivRule{
		ID:          "deny-http",
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.0.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}

	// Run first transaction.
	txn := ruleCache.NewTxn(false)

	// Perform update of the same rules for multiple interfaces.
	ifSet := NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")
	for ifName := range ifSet {
		err := txn.Update(ifName, ingress, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}

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
	txn = ruleCache.NewTxn(false)

	// Add two more interfaces.
	ifSet2 := ifSet.Copy()
	ifSet2.Add("afpacket4")
	ifSet2.Add("afpacket5")
	for ifName := range ifSet2 {
		err := txn.Update(ifName, ingress, egress)
		gomega.Expect(err).To(gomega.BeNil())
	}

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
