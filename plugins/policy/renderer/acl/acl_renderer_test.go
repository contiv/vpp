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

package acl

import (
	"github.com/onsi/gomega"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"

	. "github.com/contiv/vpp/mock/aclengine"
	. "github.com/contiv/vpp/mock/contiv"
	. "github.com/contiv/vpp/mock/defaultplugins"
	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
	. "github.com/contiv/vpp/plugins/policy/renderer/testdata"
	. "github.com/contiv/vpp/plugins/policy/utils"
)

const (
	mainIfName      = "GbE"
	vxlanIfName     = "VXLAN-BVI"
	hostInterIfName = "VPP-Host"

	maxPortNum = uint32(^uint16(0))
	googleDNS  = "8.8.8.8" /* just random IP from the Internet */
	somePort   = 500       /* some port number to use as the source port */
	somePort2  = 600       /* some port number to use as the source port */
)

func verifyReflectiveACL(engine *MockACLEngine, contiv contiv.API, ifName string, expectedToHave bool) {
	ifs := contiv.GetOtherPhysicalIfNames()
	ifs = append(ifs, contiv.GetVxlanBVIIfName())
	ifs = append(ifs, contiv.GetMainPhysicalIfName())
	ifs = append(ifs, contiv.GetHostInterconnectIfName())
	ifs = append(ifs, ifName)

	acl := engine.GetInboundACL(ifName)
	if !expectedToHave {
		gomega.Expect(acl).To(gomega.BeNil())
		return
	}
	gomega.Expect(acl).ToNot(gomega.BeNil())
	gomega.Expect(acl.AclName).To(gomega.BeEquivalentTo(ACLNamePrefix + ReflectiveACLName))
	gomega.Expect(acl.Rules).To(gomega.HaveLen(2))
	rule1 := acl.Rules[0]
	rule2 := acl.Rules[1]
	gomega.Expect(acl.Interfaces).ToNot(gomega.BeNil())
	for _, ifName := range ifs {
		gomega.Expect(acl.Interfaces.Ingress).To(gomega.ContainElement(ifName))
	}
	gomega.Expect(acl.Interfaces.Egress).To(gomega.HaveLen(0))

	// TCP any
	gomega.Expect(rule1.Actions).ToNot(gomega.BeNil())
	gomega.Expect(rule1.Actions.AclAction).To(gomega.BeEquivalentTo(vpp_acl.AclAction_REFLECT))
	gomega.Expect(rule1.Matches).ToNot(gomega.BeNil())
	gomega.Expect(rule1.Matches.MacipRule).To(gomega.BeNil())
	gomega.Expect(rule1.Matches.IpRule).ToNot(gomega.BeNil())
	ipRule := rule1.Matches.IpRule
	gomega.Expect(ipRule.Other).To(gomega.BeNil())
	gomega.Expect(ipRule.Icmp).To(gomega.BeNil())
	gomega.Expect(ipRule.Udp).To(gomega.BeNil())
	gomega.Expect(ipRule.Ip).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Tcp).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Ip.SourceNetwork).To(gomega.BeEmpty())
	gomega.Expect(ipRule.Ip.DestinationNetwork).To(gomega.BeEmpty())
	gomega.Expect(ipRule.Tcp.TcpFlagsValue).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Tcp.TcpFlagsMask).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Tcp.SourcePortRange).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Tcp.DestinationPortRange).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Tcp.SourcePortRange.LowerPort).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Tcp.SourcePortRange.UpperPort).To(gomega.BeEquivalentTo(maxPortNum))
	gomega.Expect(ipRule.Tcp.DestinationPortRange.LowerPort).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Tcp.DestinationPortRange.UpperPort).To(gomega.BeEquivalentTo(maxPortNum))

	// UDP any
	gomega.Expect(rule2.Actions).ToNot(gomega.BeNil())
	gomega.Expect(rule2.Actions.AclAction).To(gomega.BeEquivalentTo(vpp_acl.AclAction_REFLECT))
	gomega.Expect(rule2.Matches).ToNot(gomega.BeNil())
	gomega.Expect(rule2.Matches.MacipRule).To(gomega.BeNil())
	gomega.Expect(rule2.Matches.IpRule).ToNot(gomega.BeNil())
	ipRule = rule2.Matches.IpRule
	gomega.Expect(ipRule.Other).To(gomega.BeNil())
	gomega.Expect(ipRule.Icmp).To(gomega.BeNil())
	gomega.Expect(ipRule.Tcp).To(gomega.BeNil())
	gomega.Expect(ipRule.Ip).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Udp).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Ip.SourceNetwork).To(gomega.BeEmpty())
	gomega.Expect(ipRule.Ip.DestinationNetwork).To(gomega.BeEmpty())
	gomega.Expect(ipRule.Udp.SourcePortRange).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Udp.DestinationPortRange).ToNot(gomega.BeNil())
	gomega.Expect(ipRule.Udp.SourcePortRange.LowerPort).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Udp.SourcePortRange.UpperPort).To(gomega.BeEquivalentTo(maxPortNum))
	gomega.Expect(ipRule.Udp.DestinationPortRange.LowerPort).To(gomega.BeEquivalentTo(0))
	gomega.Expect(ipRule.Udp.DestinationPortRange.UpperPort).To(gomega.BeEquivalentTo(maxPortNum))
}

func verifyGlobalTable(engine *MockACLEngine, contiv contiv.API, expectedToHave bool) {
	ifs := contiv.GetOtherPhysicalIfNames()
	ifs = append(ifs, contiv.GetVxlanBVIIfName())
	ifs = append(ifs, contiv.GetMainPhysicalIfName())
	ifs = append(ifs, contiv.GetHostInterconnectIfName())

	acl := engine.GetACLByName(ACLNamePrefix + cache.GlobalTableID)
	if !expectedToHave {
		gomega.Expect(acl).To(gomega.BeNil())
		return
	}
	gomega.Expect(acl).ToNot(gomega.BeNil())
	gomega.Expect(acl.Rules).ToNot(gomega.HaveLen(0))
	gomega.Expect(acl.Interfaces).ToNot(gomega.BeNil())
	gomega.Expect(acl.Interfaces.Ingress).To(gomega.HaveLen(0))
	for _, ifName := range ifs {
		gomega.Expect(acl.Interfaces.Egress).To(gomega.ContainElement(ifName))
	}
	gomega.Expect(acl.Interfaces.Egress).To(gomega.HaveLen(len(ifs)))
}

func TestEgressRulesOnePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestEgressRulesOnePod")

	// Prepare input data
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{Ts3.Rule1 /* UDP not allowed */, Ts3.Rule3, Ts3.Rule4}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute Renderer transaction.
	err := aclRenderer.NewTxn(true).Render(Pod1, GetOneHostSubnet(Pod1IP), ingress, egress, false).Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(2))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyGlobalTable(aclEngine, contiv, false)

	// Test connections (Pod1 can receive connection only from 10.10.0.0/16:[TCP:ANY]).
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.TCP, somePort, 8080)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.UDP, somePort, 500)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.TCP, somePort, 81)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))

	// Try to execute the same change again.
	err = aclRenderer.NewTxn(false).Render(Pod1, GetOneHostSubnet(Pod1IP), ingress, egress, false).Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
}

func TestIngressRulesOnePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestIngressRulesOnePod")

	// Prepare input data
	ingress := []*renderer.ContivRule{Ts4.Rule1 /* UDP not allowed */, Ts4.Rule3, Ts4.Rule4}
	egress := []*renderer.ContivRule{}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute Renderer transaction.
	err := aclRenderer.NewTxn(true).Render(Pod1, GetOneHostSubnet(Pod1IP), ingress, egress, false).Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(3))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections (Pod1 can initiate connection only to 10.10.0.0/16:[TCP:ANY]).
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow)) /* pod can talk to itself */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, "10.10.50.1", renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, "10.10.50.1", renderer.TCP, somePort, 81)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, "10.10.50.1", renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))

	// Try to execute the same change again.
	err = aclRenderer.NewTxn(false).Render(Pod1, GetOneHostSubnet(Pod1IP), ingress, egress, false).Commit()
	gomega.Expect(err).To(gomega.BeNil())

	// Verify that the change had no further effect.
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))
}

func TestEgressRulesTwoPods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestEgressRulesTwoPods")

	// Prepare input data
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{Ts3.Rule1 /* UDP not allowed */, Ts3.Rule3, Ts3.Rule4}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)
	contiv.SetPodIfName(Pod2, Pod2IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod2, Pod2IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute Renderer transaction.
	txn := aclRenderer.NewTxn(true)
	txn.Render(Pod1, GetOneHostSubnet(Pod1IP), ingress, egress, false)
	txn.Render(Pod2, GetOneHostSubnet(Pod2IP), ingress, egress, false)
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(2)) /* pod1 and pod2 should share the same local table */
	gomega.Expect(aclEngine.GetNumOfACLChanges()).To(gomega.Equal(2))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod2IfName, true)
	verifyGlobalTable(aclEngine, contiv, false)

	// Test connections (Pod1, Pod2 can receive connection only from 10.10.0.0/16:[TCP:ANY]).
	//  -> dst = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod2, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod2, Pod1, renderer.TCP, somePort, 8080)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.TCP, somePort, 8080)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod2, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod2, Pod1, renderer.UDP, somePort, 500)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod1, renderer.UDP, somePort, 500)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.TCP, somePort, 81)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	//  -> dst = pod2
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod2, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod2, renderer.TCP, somePort, 8080)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod2, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod2, renderer.TCP, somePort, 8080)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod2, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod2, renderer.UDP, somePort, 500)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod2, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod6, Pod2, renderer.UDP, somePort, 500)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod2, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod2, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod2, renderer.TCP, somePort, 81)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod("10.10.50.1", Pod2, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionDenySyn))

	// Remove pod2 - pod1 should still have the same local table.
	err = aclRenderer.NewTxn(false).Render(Pod2, GetOneHostSubnet(Pod2IP), []*renderer.ContivRule{}, []*renderer.ContivRule{}, true).Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(2))
	gomega.Expect(aclEngine.GetNumOfACLChanges()).To(gomega.Equal(4)) /* changed interfaces for local table + reflective ACL */
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod2IfName, false)
	verifyGlobalTable(aclEngine, contiv, false)
}

func TestCombinedRules(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRules")

	// Prepare test data
	pod1Txn1Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress[1:],
		Egress:  Ts5.Pod1Egress[:2],
	}
	pod1Txn2Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress,
		Egress:  Ts5.Pod1Egress,
	}
	pod3Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod3IP),
		Ingress: Ts5.Pod3Ingress,
		Egress:  Ts5.Pod3Egress,
	}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)
	contiv.SetPodIfName(Pod3, Pod3IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod3, Pod3IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute first Renderer transaction.
	txn := aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Txn1Cfg.PodIP, pod1Txn1Cfg.Ingress, pod1Txn1Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, pod3Cfg.Ingress, pod3Cfg.Egress, false)
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(4))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod3IfName, true)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections.
	// -> src = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = pod3
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 514)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = internet
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 67)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionDenySyn))

	// Execute second Renderer transaction (change pod1 config).
	txn = aclRenderer.NewTxn(false)
	txn.Render(Pod1, pod1Txn2Cfg.PodIP, pod1Txn2Cfg.Ingress, pod1Txn2Cfg.Egress, false)
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(4))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod3IfName, true)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections.
	// -> src = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = pod3
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 514)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = internet
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 53)).To(gomega.Equal(ConnActionDenySyn))  /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionDenySyn))  /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 67)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionDenySyn))

}

func TestCombinedRulesWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRulesWithResync")

	// Prepare test data
	pod1Txn1Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress[1:],
		Egress:  Ts5.Pod1Egress[:2],
	}
	pod1Txn2Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress,
		Egress:  Ts5.Pod1Egress,
	}
	pod3Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod3IP),
		Ingress: Ts5.Pod3Ingress,
		Egress:  Ts5.Pod3Egress,
	}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)
	contiv.SetPodIfName(Pod3, Pod3IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod3, Pod3IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute first Renderer transaction.
	txn := aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Txn1Cfg.PodIP, pod1Txn1Cfg.Ingress, pod1Txn1Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, pod3Cfg.Ingress, pod3Cfg.Egress, false)
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Dump ACLs and put them to mock defaultplugins.
	acls := aclEngine.DumpACLs()
	vppPlugins.AddACL(acls...)

	// Simulate restart of ACL Renderer.
	txnTracker = localclient.NewTxnTracker(aclEngine.ApplyTxn)
	aclRenderer = &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute second Renderer transaction (from non-empty state; change pod1 config).
	txn = aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Txn2Cfg.PodIP, pod1Txn2Cfg.Ingress, pod1Txn2Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, pod3Cfg.Ingress, pod3Cfg.Egress, false)
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(4))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod3IfName, true)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections.
	// -> src = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = pod3
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 514)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = internet
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionDenySyn)) /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 53)).To(gomega.Equal(ConnActionDenySyn))  /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionDenySyn))  /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 67)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionDenySyn))
}

func TestCombinedRulesWithResyncAndRemovedPod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRulesWithResyncAndRemovedPod")

	// Prepare test data
	pod1Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress[1:],
		Egress:  Ts5.Pod1Egress[:2],
	}
	pod3Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod3IP),
		Ingress: Ts5.Pod3Ingress,
		Egress:  Ts5.Pod3Egress,
	}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)
	contiv.SetPodIfName(Pod3, Pod3IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod3, Pod3IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute first Renderer transaction.
	txn := aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Cfg.PodIP, pod1Cfg.Ingress, pod1Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, pod3Cfg.Ingress, pod3Cfg.Egress, false)
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Dump ACLs and put them to mock defaultplugins.
	acls := aclEngine.DumpACLs()
	vppPlugins.AddACL(acls...)

	// Simulate restart of ACL Renderer.
	txnTracker = localclient.NewTxnTracker(aclEngine.ApplyTxn)
	aclRenderer = &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute second Renderer transaction (from non-empty state; keep pod1 config & ***remove pod3***).
	txn = aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Cfg.PodIP, pod1Cfg.Ingress, pod1Cfg.Egress, false)
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(3))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod3IfName, false)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections (removed pod3 = no ACLs assigned to pod3).
	// -> src = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = pod3
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 514)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))           /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))           /* changed */
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	// -> src = internet
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 67)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
}

func TestCombinedRulesWithRemovedPods(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestCombinedRulesWithRemovedPods")

	// Prepare test data
	pod1Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod1IP),
		Ingress: Ts5.Pod1Ingress[1:],
		Egress:  Ts5.Pod1Egress[:2],
	}
	pod3Cfg := &cache.PodConfig{
		PodIP:   GetOneHostSubnet(Pod3IP),
		Ingress: Ts5.Pod3Ingress,
		Egress:  Ts5.Pod3Egress,
	}

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodIfName(Pod1, Pod1IfName)
	contiv.SetPodIfName(Pod3, Pod3IfName)

	// -> ACL engine
	aclEngine := NewMockACLEngine(logger, contiv)
	aclEngine.RegisterPod(Pod1, Pod1IP, false)
	aclEngine.RegisterPod(Pod3, Pod3IP, false)
	aclEngine.RegisterPod(Pod6, Pod6IP, true)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(aclEngine.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()

	// Prepare ACL Renderer.
	aclRenderer := &Renderer{
		Deps: Deps{
			Log:           logger,
			Contiv:        contiv,
			VPP:           vppPlugins,
			ACLTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}
	aclRenderer.Init()

	// Execute first Renderer transaction.
	txn := aclRenderer.NewTxn(true)
	txn.Render(Pod1, pod1Cfg.PodIP, pod1Cfg.Ingress, pod1Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, pod3Cfg.Ingress, pod3Cfg.Egress, false)
	err := txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(1))

	// Execute second Renderer transaction (keep pod1 config & ***remove pod3***).
	txn = aclRenderer.NewTxn(false)
	txn.Render(Pod1, pod1Cfg.PodIP, pod1Cfg.Ingress, pod1Cfg.Egress, false)
	txn.Render(Pod3, pod3Cfg.PodIP, []*renderer.ContivRule{}, []*renderer.ContivRule{}, true)
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(2))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(3))
	verifyReflectiveACL(aclEngine, contiv, Pod1IfName, true)
	verifyReflectiveACL(aclEngine, contiv, Pod3IfName, false)
	verifyGlobalTable(aclEngine, contiv, true)

	// Test connections (removed pod3 = no ACLs assigned to pod3).
	// -> src = pod1
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.UDP, somePort, 162)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod3, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod1, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod1, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionDenySyn))
	// -> src = pod3
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.UDP, somePort, 514)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod3, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.UDP, somePort, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 22)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod1, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))           /* changed */
	gomega.Expect(aclEngine.ConnectionPodToPod(Pod3, Pod6, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow))           /* changed */
	gomega.Expect(aclEngine.ConnectionPodToInternet(Pod3, googleDNS, renderer.TCP, somePort, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */
	// -> src = internet
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.UDP, somePort2, 53)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod1, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 161)).To(gomega.Equal(ConnActionAllow)) /* changed */
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.UDP, somePort2, 67)).To(gomega.Equal(ConnActionAllow))
	gomega.Expect(aclEngine.ConnectionInternetToPod(googleDNS, Pod3, renderer.TCP, somePort2, 80)).To(gomega.Equal(ConnActionAllow)) /* changed */

	// Execute third Renderer transaction (***remove pod1 as well***).
	txn = aclRenderer.NewTxn(false)
	txn.Render(Pod1, pod1Cfg.PodIP, []*renderer.ContivRule{}, []*renderer.ContivRule{}, true)
	err = txn.Commit()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(txnTracker.PendingTxns).To(gomega.HaveLen(0))
	gomega.Expect(txnTracker.CommittedTxns).To(gomega.HaveLen(3))

	// Test ACLs.
	gomega.Expect(aclEngine.GetNumOfACLs()).To(gomega.Equal(1)) /* just reflective ACL */
	verifyReflectiveACL(aclEngine, contiv, mainIfName, true)
	verifyGlobalTable(aclEngine, contiv, false)
}
