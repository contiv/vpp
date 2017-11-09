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

	. "github.com/contiv/vpp/mock/contiv"
	"github.com/contiv/vpp/mock/localclient"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/acl/cache"
)

type ACLSet map[string]struct{}                       // set ACL names
type ACLByIfMap map[string]*acl_model.AccessLists_Acl // interface -> ACL

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

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod1IfName = "afpacket1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

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

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)

	txnTracker := localclient.NewTxnTracker(nil)

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:                 logger,
			Contiv:              contiv,
			ACLTxnFactory:       txnTracker.NewDataChangeTxn,
			ACLResyncTxnFactory: txnTracker.NewDataResyncTxn,
		},
	}
	aclRenderer.Init()

	// Execute Renderer transaction.
	aclRenderer.NewTxn(false).Render(pod1, nil, ingress, egress).Commit()

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
	verifyACLPut(op, "", cache.NewInterfaceSet(), cache.NewInterfaceSet(pod1IfName), rule)

	// Try to execute the same change again.
	aclRenderer.NewTxn(false).Render(pod1, nil, ingress, egress).Commit()

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
}

func TestSingleContivRuleMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleContivRuleMultipleInterfaces")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod1IfName = "afpacket1"
		pod2Name   = "pod2"
		pod2IfName = "afpacket2"
		pod3Name   = "pod3"
		pod3IfName = "afpacket3"
		pod4Name   = "pod4"
		pod4IfName = "afpacket4"
		pod5Name   = "pod5"
		pod5IfName = "afpacket5"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}
	pod3 := podmodel.ID{Name: pod3Name, Namespace: namespace}
	pod4 := podmodel.ID{Name: pod4Name, Namespace: namespace}
	pod5 := podmodel.ID{Name: pod5Name, Namespace: namespace}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)
	contiv.SetPodIfName(pod2, pod2IfName)
	contiv.SetPodIfName(pod3, pod3IfName)
	contiv.SetPodIfName(pod4, pod4IfName)
	contiv.SetPodIfName(pod5, pod5IfName)

	txnTracker := localclient.NewTxnTracker(nil)

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:                 logger,
			Contiv:              contiv,
			ACLTxnFactory:       txnTracker.NewDataChangeTxn,
			ACLResyncTxnFactory: txnTracker.NewDataResyncTxn,
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
	ifSet := cache.NewInterfaceSet(pod1IfName, pod2IfName, pod3IfName)
	pods := []podmodel.ID{pod1, pod2, pod3}
	for _, pod := range pods {
		rendererTxn.Render(pod, nil, ingress, egress)
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
	for _, pod := range pods {
		rendererTxn.Render(pod, nil, ingress, egress)
	}
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Add two more interfaces.
	rendererTxn = aclRenderer.NewTxn(false)
	ifSet2 := cache.NewInterfaceSet(pod4IfName, pod5IfName)
	pods = []podmodel.ID{pod4, pod5}
	for _, pod := range pods {
		rendererTxn.Render(pod, nil, ingress, egress)
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

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod1IfName = "afpacket1"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)

	txnTracker := localclient.NewTxnTracker(nil)

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:                 logger,
			Contiv:              contiv,
			ACLTxnFactory:       txnTracker.NewDataChangeTxn,
			ACLResyncTxnFactory: txnTracker.NewDataResyncTxn,
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
	ifSet := cache.NewInterfaceSet(pod1IfName)
	rendererTxn.Render(pod1, nil, ingress, egress)
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
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(1))
	gomega.Expect(putEgress.GetACL(pod1IfName)).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACL1 := verifyACL(putIngress.GetACL(pod1IfName), "", ifSet, cache.NewInterfaceSet(), ingress...)
	verifyACL(putEgress.GetACL(pod1IfName), "", cache.NewInterfaceSet(), ifSet, egress...)

	// Try to execute the same change again.
	rendererTxn = aclRenderer.NewTxn(false)
	rendererTxn.Render(pod1, nil, ingress, egress)
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
	rendererTxn.Render(pod1, nil, ingress2, egress)
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
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(0))

	// Verify the new ACL.
	inACL2 := verifyACL(putIngress.GetACL(pod1IfName), "", ifSet, cache.NewInterfaceSet(), ingress2...)
	gomega.Expect(inACL2).ToNot(gomega.BeEquivalentTo(inACL1))
}

func TestMultipleContivRulesMultipleInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfaces")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod1IfName = "afpacket1"
		pod2Name   = "pod2"
		pod2IfName = "afpacket2"
		pod3Name   = "pod3"
		pod3IfName = "afpacket3"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}
	pod3 := podmodel.ID{Name: pod3Name, Namespace: namespace}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)
	contiv.SetPodIfName(pod2, pod2IfName)
	contiv.SetPodIfName(pod3, pod3IfName)

	txnTracker := localclient.NewTxnTracker(nil)

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:                 logger,
			Contiv:              contiv,
			ACLTxnFactory:       txnTracker.NewDataChangeTxn,
			ACLResyncTxnFactory: txnTracker.NewDataResyncTxn,
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

	ifSetInA := cache.NewInterfaceSet(pod1IfName, pod2IfName)
	ifSetEgA := cache.NewInterfaceSet(pod1IfName)
	ifSetEgB := cache.NewInterfaceSet(pod2IfName, pod3IfName)

	// Execute Renderer transaction for 3 interfaces.
	rendererTxn := aclRenderer.NewTxn(false)
	rendererTxn.Render(pod1, nil, ingressA, egressA)
	rendererTxn.Render(pod2, nil, ingressA, egressB)
	rendererTxn.Render(pod3, nil, ingressB, egressB)
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
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod3IfName)).To(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod3IfName)).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACLA := verifyACL(putIngress.GetACL(pod1IfName), "", ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putIngress.GetACL(pod2IfName), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	egACLA := verifyACL(putEgress.GetACL(pod1IfName), "", cache.NewInterfaceSet(), ifSetEgA, egressA...)
	egACLB := verifyACL(putEgress.GetACL(pod2IfName), "", cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL(pod3IfName), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)

	// Try to execute the same changes again.
	rendererTxn = aclRenderer.NewTxn(false)
	rendererTxn.Render(pod1, nil, ingressA, egressA)
	rendererTxn.Render(pod2, nil, ingressA, egressB)
	rendererTxn.Render(pod3, nil, ingressB, egressB)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Change assignment of rules a bit.
	ingressC := []*renderer.ContivRule{inRule1} // afpacket1, afpacket3
	ifSetInA = cache.NewInterfaceSet(pod2IfName)
	ifSetInC := cache.NewInterfaceSet(pod1IfName, pod3IfName)
	ifSetEgB = cache.NewInterfaceSet(pod1IfName, pod2IfName, pod3IfName)

	// Run second transaction (with effect).
	rendererTxn = aclRenderer.NewTxn(false)
	rendererTxn.Render(pod1, nil, ingressC, egressB)
	rendererTxn.Render(pod2, nil, ingressA, egressB)
	rendererTxn.Render(pod3, nil, ingressC, egressB)
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
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod3IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod3IfName)).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	verifyACL(putIngress.GetACL(pod1IfName), "", ifSetInC, cache.NewInterfaceSet(), ingressC...)
	verifyACL(putIngress.GetACL(pod2IfName), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putEgress.GetACL(pod1IfName), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL(pod2IfName), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL(pod3IfName), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)
}

func TestMultipleContivRulesMultipleInterfacesWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleContivRulesMultipleInterfacesWithResync")

	// Prepare input data.
	const (
		namespace  = "default"
		pod1Name   = "pod1"
		pod1IfName = "afpacket1"
		pod2Name   = "pod2"
		pod2IfName = "afpacket2"
		pod3Name   = "pod3"
		pod3IfName = "afpacket3"
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}
	pod3 := podmodel.ID{Name: pod3Name, Namespace: namespace}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodIfName(pod1, pod1IfName)
	contiv.SetPodIfName(pod2, pod2IfName)
	contiv.SetPodIfName(pod3, pod3IfName)

	txnTracker := localclient.NewTxnTracker(nil)

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:                 logger,
			Contiv:              contiv,
			ACLTxnFactory:       txnTracker.NewDataChangeTxn,
			ACLResyncTxnFactory: txnTracker.NewDataResyncTxn,
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

	ifSetInA := cache.NewInterfaceSet(pod1IfName, pod2IfName)
	ifSetEgA := cache.NewInterfaceSet(pod1IfName)
	ifSetEgB := cache.NewInterfaceSet(pod2IfName, pod3IfName)

	// Execute RESYNC Renderer transaction for 3 interfaces.
	rendererTxn := aclRenderer.NewTxn(true)
	rendererTxn.Render(pod1, nil, ingressA, egressA)
	rendererTxn.Render(pod2, nil, ingressA, egressB)
	rendererTxn.Render(pod3, nil, ingressB, egressB)
	err := rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
	txn := txnTracker.CommittedTxns[0]
	gomega.Expect(txn.DataResyncTxn).ToNot(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).To(gomega.BeNil())

	// Verify transaction operations.
	ops := txn.DataResyncTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(3))
	putIngress, putEgress, deleted := parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(0))
	gomega.Expect(putIngress).To(gomega.HaveLen(2))
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod3IfName)).To(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(3))
	gomega.Expect(putEgress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod3IfName)).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	inACLA := verifyACL(putIngress.GetACL(pod1IfName), "", ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putIngress.GetACL(pod2IfName), inACLA, ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putEgress.GetACL(pod1IfName), "", cache.NewInterfaceSet(), ifSetEgA, egressA...)
	egACLB := verifyACL(putEgress.GetACL(pod2IfName), "", cache.NewInterfaceSet(), ifSetEgB, egressB...)
	verifyACL(putEgress.GetACL(pod3IfName), egACLB, cache.NewInterfaceSet(), ifSetEgB, egressB...)

	// Resync: change change assignment of rules a bit and remove afpacket3.
	ifSetInA = cache.NewInterfaceSet(pod1IfName)
	ifSetInB := cache.NewInterfaceSet(pod2IfName)
	ifSetEgA = cache.NewInterfaceSet(pod1IfName, pod2IfName)

	ingressA = []*renderer.ContivRule{inRule1}          // afpacket1
	ingressB = []*renderer.ContivRule{inRule1, inRule2} // afpacket2
	egressA = []*renderer.ContivRule{egRule1, egRule2}  // afpacket1,2

	// Run second RESYNC transaction.
	rendererTxn = aclRenderer.NewTxn(true)
	rendererTxn.Render(pod1, nil, ingressA, egressA)
	rendererTxn.Render(pod2, nil, ingressB, egressA)
	err = rendererTxn.Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify localclient transactions.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))
	txn = txnTracker.CommittedTxns[1]
	gomega.Expect(txn.DataResyncTxn).ToNot(gomega.BeNil())
	gomega.Expect(txn.DataChangeTxn).To(gomega.BeNil())

	// Verify transaction operations.
	ops = txn.DataResyncTxn.Ops
	gomega.Expect(ops).To(gomega.HaveLen(3))
	putIngress, putEgress, deleted = parseACLOps(ops)
	gomega.Expect(deleted).To(gomega.HaveLen(0))
	gomega.Expect(putIngress).To(gomega.HaveLen(2))
	gomega.Expect(putIngress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putIngress.GetACL(pod2IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress).To(gomega.HaveLen(2))
	gomega.Expect(putEgress.GetACL(pod1IfName)).ToNot(gomega.BeNil())
	gomega.Expect(putEgress.GetACL(pod2IfName)).ToNot(gomega.BeNil())

	// Verify the generated ACLs.
	verifyACL(putIngress.GetACL(pod1IfName), "", ifSetInA, cache.NewInterfaceSet(), ingressA...)
	verifyACL(putIngress.GetACL(pod2IfName), "", ifSetInB, cache.NewInterfaceSet(), ingressB...)
	egACLA := verifyACL(putEgress.GetACL(pod1IfName), "", cache.NewInterfaceSet(), ifSetEgA, egressA...)
	verifyACL(putEgress.GetACL(pod2IfName), egACLA, cache.NewInterfaceSet(), ifSetEgA, egressA...)
}
