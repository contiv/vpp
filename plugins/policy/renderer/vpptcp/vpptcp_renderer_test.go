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

package vpptcp

import (
	"net"
	"testing"

	"github.com/onsi/gomega"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	"os"

	. "github.com/contiv/vpp/mock/contiv"
	. "github.com/contiv/vpp/mock/sessionrules"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	vpptcprule "github.com/contiv/vpp/plugins/policy/renderer/vpptcp/rule"
	. "github.com/contiv/vpp/plugins/policy/utils"
)

var mockSessionRules *MockSessionRules

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func TestMain(m *testing.M) {
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	mockSessionRules = NewMockSessionRules(logger, vpptcprule.SessionRuleTagPrefix)
	os.Exit(m.Run())
}

func TestSingleEgressRuleSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleSinglePod")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

	rule := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.2.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	ingress := []*renderer.ContivRule{}
	egress := []*renderer.ContivRule{rule}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:              logger,
			Contiv:           contiv,
			GoVPPChan:        vppChan,
			GoVPPChanBufSize: 20,
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, GetOneHostSubnet(pod1IP), ingress, egress, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 80, "192.168.2.0/24", 0, "TCP", "DENY")).To(gomega.BeTrue())
}

func TestSingleIngressRuleSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleSinglePod")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

	rule := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	ingress := []*renderer.ContivRule{rule}
	egress := []*renderer.ContivRule{}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:              logger,
			Contiv:           contiv,
			GoVPPChan:        vppChan,
			GoVPPChanBufSize: 2,
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, GetOneHostSubnet(pod1IP), ingress, egress, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(0))
}

func TestMultipleRulesSinglePodWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesSinglePodWithDataChange")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

	inRule1 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.1.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.2.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    23,
	}
	egRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingress := []*renderer.ContivRule{inRule1, inRule2}
	egress := []*renderer.ContivRule{egRule1, egRule2}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:              logger,
			Contiv:           contiv,
			GoVPPChan:        vppChan,
			GoVPPChanBufSize: 5,
		},
	}
	vppTCPRenderer.Init()

	// Execute first Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, GetOneHostSubnet(pod1IP), ingress, egress, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(5))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.1.0.0/16", 80, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(3))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 23, "192.168.2.0/24", 0, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())

	// Prepare new data.
	inRule3 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingress2 := []*renderer.ContivRule{inRule1, inRule3}
	egress2 := []*renderer.ContivRule{egRule2}

	// Execute second first Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, GetOneHostSubnet(pod1IP), ingress2, egress2, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(9))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(3))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "0.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "128.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())

}

func TestMultipleRulesMultiplePodsWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultiplePodsWithDataChange")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
		pod2Name       = "pod2"
		pod2IP         = "192.168.1.2"
		pod2VPPNsIndex = 15
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	inRule1 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.1.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.2.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    23,
	}
	egRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingressPod1 := []*renderer.ContivRule{inRule1, inRule2}
	egressPod1 := []*renderer.ContivRule{egRule1, egRule2}

	ingressPod2 := []*renderer.ContivRule{inRule1}
	egressPod2 := []*renderer.ContivRule{egRule2}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	contiv.SetPodNsIndex(pod2, pod2VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChan,
		},
	}
	vppTCPRenderer.Init()

	// Execute first Renderer transaction for two pods.
	txn := vppTCPRenderer.NewTxn(false)
	txn.Render(pod1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1, false)
	txn.Render(pod2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2, false)
	txn.Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(8))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.1.0.0/16", 80, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(5))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 23, "192.168.2.0/24", 0, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod2IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod2IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())

	// Prepare new data.
	inRule3 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingressPod1 = []*renderer.ContivRule{inRule1}
	egressPod1 = []*renderer.ContivRule{egRule2}

	ingressPod2 = []*renderer.ContivRule{inRule1, inRule3}
	egressPod2 = []*renderer.ContivRule{}

	// Execute second Renderer transaction for both pods.
	txn = vppTCPRenderer.NewTxn(false)
	txn.Render(pod1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1, false)
	txn.Render(pod2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2, false)
	txn.Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(14))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(3))
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "0.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "128.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
}

func TestMultipleRulesMultiplePodsWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultiplePodsWithResync")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
		pod2Name       = "pod2"
		pod2IP         = "192.168.1.2"
		pod2VPPNsIndex = 15
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}
	pod2 := podmodel.ID{Name: pod2Name, Namespace: namespace}

	inRule1 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.1.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}
	egRule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.2.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    23,
	}
	egRule2 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingressPod1 := []*renderer.ContivRule{inRule1, inRule2}
	egressPod1 := []*renderer.ContivRule{egRule1, egRule2}

	ingressPod2 := []*renderer.ContivRule{inRule1}
	egressPod2 := []*renderer.ContivRule{egRule2}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	contiv.SetPodNsIndex(pod2, pod2VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:              logger,
			Contiv:           contiv,
			GoVPPChan:        vppChan,
			GoVPPChanBufSize: 12,
		},
	}
	vppTCPRenderer.Init()

	// Execute first Renderer transaction for two pods.
	txn := vppTCPRenderer.NewTxn(false)
	txn.Render(pod1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1, false)
	txn.Render(pod2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2, false)
	txn.Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(8))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.1.0.0/16", 80, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(5))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 23, "192.168.2.0/24", 0, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod2IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod2IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())

	// Prepare new data.
	inRule3 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingressPod1 = []*renderer.ContivRule{inRule1}
	egressPod1 = []*renderer.ContivRule{egRule2}

	ingressPod2 = []*renderer.ContivRule{inRule1, inRule3}
	egressPod2 = []*renderer.ContivRule{}

	// Simulate restart (I)
	vppTCPRenderer = &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChan,
		},
	}
	vppTCPRenderer.Init()

	// Execute RESYNC Renderer transaction for both pods.
	txn = vppTCPRenderer.NewTxn(true)
	txn.Render(pod1, GetOneHostSubnet(pod1IP), ingressPod1, egressPod1, false)
	txn.Render(pod2, GetOneHostSubnet(pod2IP), ingressPod2, egressPod2, false)
	txn.Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(16))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(3))
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "0.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod2VPPNsIndex).HasRule("", 0, "128.0.0.0/1", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "0.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "128.0.0.0/1", 0, "UDP", "DENY")).To(gomega.BeTrue())
}

func TestSinglePodWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSinglePodWithResync")

	// Prepare input data.
	const (
		namespace      = "default"
		pod1Name       = "pod1"
		pod1IP         = "192.168.1.1"
		pod1VPPNsIndex = 10
	)
	pod1 := podmodel.ID{Name: pod1Name, Namespace: namespace}

	inRule1 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    22,
	}
	inRule2 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork(""),
		DestNetwork: ipNetwork("10.0.0.0/8"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    23,
	}
	egRule1 := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  ipNetwork("192.168.2.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	}

	ingress := []*renderer.ContivRule{inRule1, inRule2}
	egress := []*renderer.ContivRule{egRule1}

	// Prepare mocks.
	contiv := NewMockContiv()
	contiv.SetPodNsIndex(pod1, pod1VPPNsIndex)
	mockSessionRules.Clear()
	vppChan := mockSessionRules.NewVPPChan()
	gomega.Expect(vppChan).ToNot(gomega.BeNil())

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChan,
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, GetOneHostSubnet(pod1IP), ingress, egress, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(3))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 23, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 80, "192.168.2.0/24", 0, "TCP", "DENY")).To(gomega.BeTrue())

	// Simulate restart (I)
	vppTCPRenderer = &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChan,
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer RESYNC transaction.
	vppTCPRenderer.NewTxn(true).Render(pod1, GetOneHostSubnet(pod1IP), ingress, egress, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(5)) // + dump + ping
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 23, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 80, "192.168.2.0/24", 0, "TCP", "DENY")).To(gomega.BeTrue())

	// Simulate restart (II)
	vppTCPRenderer = &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChan,
		},
	}
	vppTCPRenderer.Init()

	// Prepare new data.
	egRule2 := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  ipNetwork("192.168.3.0/24"),
		DestNetwork: ipNetwork(""),
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}

	ingress2 := []*renderer.ContivRule{inRule2}
	egress2 := []*renderer.ContivRule{egRule1, egRule2}

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(true).Render(pod1, GetOneHostSubnet(pod1IP), ingress2, egress2, false).Commit()

	// Verify output
	gomega.Expect(mockSessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(mockSessionRules.GetReqCount()).To(gomega.BeEquivalentTo(9)) // + dump + ping + one removed + one added
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(mockSessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 23, "TCP", "ALLOW")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(2))
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 80, "192.168.2.0/24", 0, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(mockSessionRules.GlobalTable().HasRule(pod1IP, 0, "192.168.3.0/24", 0, "UDP", "ALLOW")).To(gomega.BeTrue())
}
