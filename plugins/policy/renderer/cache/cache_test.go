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

	// Create an instance of ContivRuleCache
	ruleCache := NewContivRuleCache()
	ruleCache.Deps.Log = logroot.StandardLogger()

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
	gomega.Expect(ingressChanges).To(gomega.HaveLen(0))
	gomega.Expect(egressChanges).To(gomega.HaveLen(1))

	change := egressChanges[0]
	gomega.Expect(change.List).ToNot(gomega.BeNil())
	gomega.Expect(change.List.ID).ToNot(gomega.BeEmpty())
	gomega.Expect(strings.HasPrefix(change.List.ID, "egress")).To(gomega.BeTrue())
	gomega.Expect(compareRuleLists(change.List.Rules, egress)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(change.PreviousInterfaces).To(gomega.BeEmpty())
	gomega.Expect(change.List.Interfaces).To(gomega.HaveLen(1))
	gomega.Expect(change.List.Interfaces.Has("afpacket1")).To(gomega.BeTrue())
	listId := change.List.ID

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
	gomega.Expect(ifIngress).To(gomega.BeNil())
	gomega.Expect(ifEgress).ToNot(gomega.BeNil())
	gomega.Expect(ifEgress.ID).To(gomega.BeEquivalentTo(listId))
	gomega.Expect(ifEgress.Rules).To(gomega.BeEquivalentTo(egress))
	gomega.Expect(compareRuleLists(ifEgress.Rules, egress)).To(gomega.BeEquivalentTo(0))
}
