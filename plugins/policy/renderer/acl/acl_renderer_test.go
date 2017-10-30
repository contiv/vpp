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

package acl

import (
	"net"
	"testing"

	"github.com/onsi/gomega"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"
	acl_model "github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
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

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := cache.NewContivRuleCache()
	ruleCache.Deps.Log = logroot.StandardLogger()
	ruleCache.Deps.Log.SetLevel(logging.DebugLevel)
	aclRenderer := NewRenderer(txnTracker.NewDataChangeTxn, txnTracker.NewDataResyncTxn)
	aclRenderer.Deps.Log = logroot.StandardLogger()
	aclRenderer.Deps.Log.SetLevel(logging.DebugLevel)
	aclRenderer.Deps.Cache = ruleCache

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

	// Execute Renderer transaction.
	aclRenderer.NewTxn(false).Render("afpacket1", ingress, egress).Commit()

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	txn := txnTracker.CommittedTxns[0]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops := txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(1))
	op := ops[0]
	gomega.Expect(op.Value).ToNot(gomega.BeNil())
	acl, isACL := (op.Value).(*acl_model.AccessLists_Acl)
	gomega.Expect(isACL).To(gomega.BeTrue())
	gomega.Expect(op.Key).To(gomega.BeEquivalentTo(acl_model.Key(acl.AclName)))

	// Verify the single generated ACL.
	gomega.Expect(acl.Interfaces).ToNot(gomega.BeNil())
	gomega.Expect(acl.Interfaces.Ingress).To(gomega.HaveLen(0))
	gomega.Expect(acl.Interfaces.Egress).To(gomega.HaveLen(1))
	gomega.Expect(acl.Interfaces.Egress[0]).To(gomega.BeEquivalentTo("afpacket1"))
	gomega.Expect(acl.Rules).To(gomega.HaveLen(1))

	// Verify ACL rules.
	aclRule := acl.Rules[0]
	gomega.Expect(aclRule.RuleName).To(gomega.BeEquivalentTo(rule.ID))
	gomega.Expect(aclRule.Actions).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Actions.AclAction).To(gomega.BeEquivalentTo(acl_model.AclAction_DENY))
	gomega.Expect(aclRule.Matches).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.MacipRule).To(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Ip).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Ip.SourceNetwork).To(gomega.BeEquivalentTo(rule.SrcNetwork.String()))
	gomega.Expect(aclRule.Matches.IpRule.Ip.DestinationNetwork).To(gomega.BeEquivalentTo(""))
	gomega.Expect(aclRule.Matches.IpRule.Icmp).To(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Tcp).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort).To(gomega.BeEquivalentTo(rule.SrcPort))
	gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort).To(gomega.BeEquivalentTo(rule.SrcPort))
	gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort).To(gomega.BeEquivalentTo(rule.DestPort))
	gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort).To(gomega.BeEquivalentTo(rule.DestPort))
	gomega.Expect(aclRule.Matches.IpRule.Udp).To(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Other).To(gomega.BeNil())

	// Try to execute the same change again.
	aclRenderer.NewTxn(false).Render("afpacket1", ingress, egress).Commit()

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
}
