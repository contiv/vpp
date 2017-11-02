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

	"strings"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
)

type ACLSet map[string]struct{}                       // set of ACL names
type ACLByIfMap map[string]*acl_model.AccessLists_Acl // interface -> ACL

// MockVppPlugin is a mock for VPP plugin (defaultplugins).
type MockVppPlugin struct {
	ACLs []*acl_model.AccessLists_Acl
}

func NewMockVppPlugin() *MockVppPlugin {
	return &MockVppPlugin{ACLs: []*acl_model.AccessLists_Acl{}}
}

func (mvp *MockVppPlugin) DumpACLs() []*acl_model.AccessLists_Acl {
	return mvp.ACLs
}

func (mvp *MockVppPlugin) ClearACLs() {
	mvp.ACLs = []*acl_model.AccessLists_Acl{}
}

func (mvp *MockVppPlugin) AddACL(acl *acl_model.AccessLists_Acl) {
	mvp.ACLs = append(mvp.ACLs, acl)
}

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func (abim ACLByIfMap) GetACL(ifName string) *acl_model.AccessLists_Acl {
	acl, exists := abim[ifName]
	if exists {
		return acl
	}
	return nil
}

func (as ACLSet) Has(aclName string) bool {
	_, has := as[aclName]
	return has
}

func parseACLOps(ops []localclient.TxnOp) (putIngress ACLByIfMap, putEgress ACLByIfMap, deleted ACLSet) {
	putIngress = make(ACLByIfMap)
	putEgress = make(ACLByIfMap)
	deleted = make(ACLSet)
	for _, op := range ops {
		gomega.Expect(strings.HasPrefix(op.Key, acl_model.KeyPrefix())).To(gomega.BeTrue())
		if op.Value == nil {
			aclName := strings.TrimPrefix(op.Key, acl_model.KeyPrefix())
			deleted[aclName] = struct{}{}
		} else {
			acl, isACL := (op.Value).(*acl_model.AccessLists_Acl)
			gomega.Expect(isACL).To(gomega.BeTrue())
			gomega.Expect(acl.Interfaces).ToNot(gomega.BeNil())
			for _, ifName := range acl.Interfaces.Ingress {
				putIngress[ifName] = acl
			}
			for _, ifName := range acl.Interfaces.Egress {
				putEgress[ifName] = acl
			}
		}
	}
	return putIngress, putEgress, deleted
}

func verifyACLPut(op localclient.TxnOp, aclName string, ingress cache.InterfaceSet, egress cache.InterfaceSet,
	contivRule ...*renderer.ContivRule) string {

	// Type & key
	gomega.Expect(op.Value).ToNot(gomega.BeNil()) // Put
	acl, isACL := (op.Value).(*acl_model.AccessLists_Acl)
	gomega.Expect(isACL).To(gomega.BeTrue())
	gomega.Expect(acl.AclName).ToNot(gomega.BeEmpty())
	gomega.Expect(op.Key).To(gomega.BeEquivalentTo(acl_model.Key(acl.AclName)))
	return verifyACL(acl, aclName, ingress, egress, contivRule...)
}

func verifyACL(acl *acl_model.AccessLists_Acl, aclName string, ingress cache.InterfaceSet, egress cache.InterfaceSet,
	contivRule ...*renderer.ContivRule) string {

	gomega.Expect(acl.AclName).ToNot(gomega.BeEmpty())
	if aclName != "" {
		gomega.Expect(acl.AclName).To(gomega.BeEquivalentTo(aclName))
	}

	// Interfaces
	gomega.Expect(acl.Interfaces).ToNot(gomega.BeNil())
	inIfSet := cache.NewInterfaceSet()
	for _, ifName := range acl.Interfaces.Ingress {
		inIfSet.Add(ifName)
	}
	egIfSet := cache.NewInterfaceSet()
	for _, ifName := range acl.Interfaces.Egress {
		egIfSet.Add(ifName)
	}
	gomega.Expect(inIfSet).To(gomega.BeEquivalentTo(ingress))
	gomega.Expect(egIfSet).To(gomega.BeEquivalentTo(egress))

	// Rules
	gomega.Expect(acl.Rules).To(gomega.HaveLen(len(contivRule)))
	for idx, aclRule := range acl.Rules {
		verifyRule(aclRule, contivRule[idx])
	}

	return acl.AclName
}

func verifyRule(aclRule *acl_model.AccessLists_Acl_Rule, contivRule *renderer.ContivRule) {
	// Name
	gomega.Expect(aclRule.RuleName).To(gomega.BeEquivalentTo(contivRule.ID))
	// Action
	gomega.Expect(aclRule.Actions).ToNot(gomega.BeNil())
	if contivRule.Action == renderer.ActionPermit {
		gomega.Expect(aclRule.Actions.AclAction).To(gomega.BeEquivalentTo(acl_model.AclAction_PERMIT))
	} else {
		gomega.Expect(aclRule.Actions.AclAction).To(gomega.BeEquivalentTo(acl_model.AclAction_DENY))
	}
	// IP
	gomega.Expect(aclRule.Matches).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.MacipRule).To(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule).ToNot(gomega.BeNil())
	gomega.Expect(aclRule.Matches.IpRule.Ip).ToNot(gomega.BeNil())
	if len(contivRule.SrcNetwork.IP) > 0 {
		gomega.Expect(aclRule.Matches.IpRule.Ip.SourceNetwork).To(gomega.BeEquivalentTo(contivRule.SrcNetwork.String()))
	} else {
		gomega.Expect(aclRule.Matches.IpRule.Ip.SourceNetwork).To(gomega.BeEquivalentTo(""))
	}
	if len(contivRule.DestNetwork.IP) > 0 {
		gomega.Expect(aclRule.Matches.IpRule.Ip.DestinationNetwork).To(gomega.BeEquivalentTo(contivRule.DestNetwork.String()))
	} else {
		gomega.Expect(aclRule.Matches.IpRule.Ip.DestinationNetwork).To(gomega.BeEquivalentTo(""))
	}
	// L4
	gomega.Expect(aclRule.Matches.IpRule.Icmp).To(gomega.BeNil())
	if contivRule.Protocol == renderer.TCP {
		// TCP
		gomega.Expect(aclRule.Matches.IpRule.Tcp).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort).To(gomega.BeEquivalentTo(contivRule.SrcPort))
		gomega.Expect(aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort).To(gomega.BeEquivalentTo(contivRule.SrcPort))
		gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort).To(gomega.BeEquivalentTo(contivRule.DestPort))
		gomega.Expect(aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort).To(gomega.BeEquivalentTo(contivRule.DestPort))
	} else {
		// UDP
		gomega.Expect(aclRule.Matches.IpRule.Udp).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Udp.SourcePortRange).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort).To(gomega.BeEquivalentTo(contivRule.SrcPort))
		gomega.Expect(aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort).To(gomega.BeEquivalentTo(contivRule.SrcPort))
		gomega.Expect(aclRule.Matches.IpRule.Udp.DestinationPortRange).ToNot(gomega.BeNil())
		gomega.Expect(aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort).To(gomega.BeEquivalentTo(contivRule.DestPort))
		gomega.Expect(aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort).To(gomega.BeEquivalentTo(contivRule.DestPort))
	}
	gomega.Expect(aclRule.Matches.IpRule.Other).To(gomega.BeNil())
}

func TestSingleContivRuleOneInterface(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleOneInterface")

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           NewMockVppPlugin(),
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

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

	// Verify the single generated ACL.
	verifyACLPut(op, "", cache.NewInterfaceSet(), cache.NewInterfaceSet("afpacket1"), rule)

	// Try to execute the same change again.
	aclRenderer.NewTxn(false).Render("afpacket1", ingress, egress).Commit()

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
}

func TestSingleContivRuleMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleMultipleInterfaces")

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           NewMockVppPlugin(),
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

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

	// Execute Renderer transaction for 3 interfaces.
	rendererTxn := aclRenderer.NewTxn(false)
	ifSet := cache.NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")
	for ifName := range ifSet {
		rendererTxn.Render(ifName, ingress, egress)
	}
	err := rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

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

	// Verify the single generated ACL.
	aclName := verifyACLPut(op, "", cache.NewInterfaceSet(), ifSet, rule)

	// Try to execute the same change again.
	rendererTxn = aclRenderer.NewTxn(false)
	for ifName := range ifSet {
		rendererTxn.Render(ifName, ingress, egress)
	}
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Add two more interfaces.
	rendererTxn = aclRenderer.NewTxn(false)
	ifSet2 := cache.NewInterfaceSet()
	ifSet2.Add("afpacket4")
	ifSet2.Add("afpacket5")
	for ifName := range ifSet2 {
		rendererTxn.Render(ifName, ingress, egress)
	}
	ifSet.Join(ifSet2)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))
	txn = txnTracker.CommittedTxns[1]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops = txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(1))
	op = ops[0]

	// Verify the modified ACL.
	verifyACLPut(op, aclName, cache.NewInterfaceSet(), ifSet, rule)
}

func TestMultipleContivRulesSingleInterface(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesSingleInterface")

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           NewMockVppPlugin(),
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

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

	// Execute Renderer transaction for 3 interfaces.
	rendererTxn := aclRenderer.NewTxn(false)
	ifSet := cache.NewInterfaceSet("afpacket1")
	for ifName := range ifSet {
		rendererTxn.Render(ifName, ingress, egress)
	}
	err := rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
	txn := txnTracker.CommittedTxns[0]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops := txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(2))
	putIngress, putEgress, deleted := parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(0))
	gomega.Expect(putIngress).To(gomega.HaveLen(1))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(1))
	gomega.Expect(putEgress.GetACL("afpacket1")).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACL1 := verifyACL(putIngress.GetACL("afpacket1"), "", ifSet, cache.NewInterfaceSet(), ingress...)
	verifyACL(putEgress.GetACL("afpacket1"), "", cache.NewInterfaceSet(), ifSet, egress...)

	// Try to execute the same change again.
	rendererTxn = aclRenderer.NewTxn(false)
	for ifName := range ifSet {
		rendererTxn.Render(ifName, ingress, egress)
	}
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

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

	// Update interface rules.
	rendererTxn = aclRenderer.NewTxn(false)
	for ifName := range ifSet {
		rendererTxn.Render(ifName, ingress2, egress)
	}
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))
	txn = txnTracker.CommittedTxns[1]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops = txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(2))
	putIngress, putEgress, deleted = parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(1))
	gomega.Expect(deleted.Has(inACL1)).To(gomega.BeTrue())
	gomega.Expect(putIngress).To(gomega.HaveLen(1))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(0))

	// Verify the new ACL.
	inACL2 := verifyACL(putIngress.GetACL("afpacket1"), "", ifSet, cache.NewInterfaceSet(), ingress2...)
	gomega.Expect(inACL2).ToNot(gomega.BeEquivalentTo(inACL1))
}

func TestMultipleContivRulesMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfaces")

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           NewMockVppPlugin(),
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

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

	ifSetInA := cache.NewInterfaceSet("afpacket1", "afpacket2")
	ifSetEgA := cache.NewInterfaceSet("afpacket1")
	ifSetEgB := cache.NewInterfaceSet("afpacket2", "afpacket3")

	// Execute Renderer transaction for 3 interfaces.
	rendererTxn := aclRenderer.NewTxn(false)
	rendererTxn.Render("afpacket1", ingressA, egressA)
	rendererTxn.Render("afpacket2", ingressA, egressB)
	rendererTxn.Render("afpacket3", ingressB, egressB)
	err := rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
	txn := txnTracker.CommittedTxns[0]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops := txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(3))
	putIngress, putEgress, deleted := parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(0))
	gomega.Expect(putIngress).To(gomega.HaveLen(2))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket3")).To(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket3")).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACLA := verifyACL(putIngress.GetACL("afpacket1"), "", ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putIngress.GetACL("afpacket2"), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	egACLA := verifyACL(putEgress.GetACL("afpacket1"), "", cache.NewInterfaceSet(), ifSetEgA, egressA...)
	egACLB := verifyACL(putEgress.GetACL("afpacket2"), "", cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL("afpacket3"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)

	// Try to execute the same changes again.
	rendererTxn = aclRenderer.NewTxn(false)
	rendererTxn.Render("afpacket1", ingressA, egressA)
	rendererTxn.Render("afpacket2", ingressA, egressB)
	rendererTxn.Render("afpacket3", ingressB, egressB)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Change assignment of rules a bit.
	ingressC := []*renderer.ContivRule{inRule1} // afpacket1, afpacket3
	ifSetInA = cache.NewInterfaceSet("afpacket2")
	ifSetInC := cache.NewInterfaceSet("afpacket1", "afpacket3")
	ifSetEgB = cache.NewInterfaceSet("afpacket1", "afpacket2", "afpacket3")

	// Run second transaction (with effect).
	rendererTxn = aclRenderer.NewTxn(false)
	rendererTxn.Render("afpacket1", ingressC, egressB)
	rendererTxn.Render("afpacket2", ingressA, egressB)
	rendererTxn.Render("afpacket3", ingressC, egressB)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))
	txn = txnTracker.CommittedTxns[1]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops = txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(4))
	putIngress, putEgress, deleted = parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(1))
	gomega.Expect(deleted.Has(egACLA)).To(gomega.BeTrue())
	gomega.Expect(putIngress).To(gomega.HaveLen(3))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket3")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket3")).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	verifyACL(putIngress.GetACL("afpacket1"), "", ifSetInC, cache.NewInterfaceSet(), ingressC...)
	verifyACL(putIngress.GetACL("afpacket2"), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putEgress.GetACL("afpacket1"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL("afpacket2"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL("afpacket3"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
}

func TestMultipleContivRulesMultipleInterfacesWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfacesWithResync")

	mockVppPlugin := NewMockVppPlugin()

	// Prepare ACL Renderer and mock localclient.
	txnTracker := localclient.NewTxnTracker(nil)
	ruleCache := &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           mockVppPlugin,
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

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

	ifSetInA := cache.NewInterfaceSet("afpacket1", "afpacket2")
	ifSetEgA := cache.NewInterfaceSet("afpacket1")
	ifSetEgB := cache.NewInterfaceSet("afpacket2", "afpacket3")

	// Execute initial RESYNC Renderer transaction (from empty VPP state).
	rendererTxn := aclRenderer.NewTxn(true)
	rendererTxn.Render("afpacket1", ingressA, egressA)
	rendererTxn.Render("afpacket2", ingressA, egressB)
	rendererTxn.Render("afpacket3", ingressB, egressB)
	err := rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
	txn := txnTracker.CommittedTxns[0]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops := txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(3))
	putIngress, putEgress, deleted := parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(0))
	gomega.Expect(putIngress).To(gomega.HaveLen(2))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket3")).To(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket3")).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACLA := verifyACL(putIngress.GetACL("afpacket1"), "", ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putIngress.GetACL("afpacket2"), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	egACLA := verifyACL(putEgress.GetACL("afpacket1"), "", cache.NewInterfaceSet(), ifSetEgA, egressA...)
	egACLB := verifyACL(putEgress.GetACL("afpacket2"), "", cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL("afpacket3"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)

	// Remember the current VPP configuration.
	mockVppPlugin.AddACL(putIngress.GetACL("afpacket1"))
	mockVppPlugin.AddACL(putEgress.GetACL("afpacket1"))
	mockVppPlugin.AddACL(putEgress.GetACL("afpacket2"))

	// Simulate Agent restart.
	txnTracker = localclient.NewTxnTracker(nil)
	ruleCache = &cache.ContivRuleCache{
		Deps: cache.Deps{
			Log: logger,
		},
	}
	ruleCache.Init()
	aclRenderer = &Renderer{
		Deps: Deps{
			Log:           logger,
			Cache:         ruleCache,
			VPP:           mockVppPlugin,
			ACLTxnFactory: txnTracker.NewDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Resync: change assignment of rules a bit and remove afpacket3.
	ifSetInC := cache.NewInterfaceSet("afpacket1")
	ifSetInA = cache.NewInterfaceSet("afpacket2")
	ifSetEgB = cache.NewInterfaceSet("afpacket1", "afpacket2")

	ingressC := []*renderer.ContivRule{inRule1} // afpacket1

	// Execute second RESYNC transaction (from non-empty VPP state).
	rendererTxn = aclRenderer.NewTxn(true)
	rendererTxn.Render("afpacket1", ingressC, egressB)
	rendererTxn.Render("afpacket2", ingressA, egressB)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
	txn = txnTracker.CommittedTxns[1]
	gomega.Expect(txn.DataResyncTxn).To(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).ToNot(gomega.BeNil())

	// Verify transaction operations.
	ops = txn.DataChangeTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(4))
	putIngress, putEgress, deleted = parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(1))
	gomega.Expect(deleted.Has(egACLA)).To(gomega.BeTrue())
	gomega.Expect(putIngress).To(gomega.HaveLen(2))
	gomega.Expect(putIngress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL("afpacket2")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(2))
	gomega.Expect(putEgress.GetACL("afpacket1")).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL("afpacket2")).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACLC := verifyACL(putIngress.GetACL("afpacket1"), "", ifSetInC, cache.NewInterfaceSet(), ingressC...)
	gomega.Expect(inACLC).ToNot(gomega.BeEquivalentTo(inACLA))
	verifyACL(putIngress.GetACL("afpacket2"), egACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putEgress.GetACL("afpacket1"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL("afpacket2"), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
}
