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
	"github.com/ligato/cn-infra/logging/logroot"

	. "github.com/contiv/vpp/mock/contiv"
	. "github.com/contiv/vpp/mock/sessionrules"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

// Function returns the IP subnet that contains only the given host
// (i.e. /32 for IPv4, /128 for IPv6).
func getOneHostSubnet(hostAddr string) *net.IPNet {
	ip := net.ParseIP(hostAddr)
	if ip == nil {
		return nil
	}
	ipNet := &net.IPNet{IP: ip}
	if ip.To4() != nil {
		ipNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
	} else {
		ipNet.Mask = net.CIDRMask(net.IPv6len*8, net.IPv6len*8)
	}
	return ipNet
}

func TestSingleEgressRuleSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
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
		ID:          "deny-http",
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
	sessionRules := NewMockSessionRules(logger, SessionRuleTag)

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: sessionRules.NewVPPChan(),
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, getOneHostSubnet(pod1IP), ingress, egress).Commit()

	// Verify output
	gomega.Expect(sessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(sessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(sessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(sessionRules.GlobalTable().HasRule(pod1IP, 80, "192.168.2.0/24", 0, "TCP", "DENY")).To(gomega.BeTrue())
}

func TestSingleIngressRuleSinglePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
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
		ID:          "deny-ssh",
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
	sessionRules := NewMockSessionRules(logger, SessionRuleTag)

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: sessionRules.NewVPPChan(),
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, getOneHostSubnet(pod1IP), ingress, egress).Commit()

	// Verify output
	gomega.Expect(sessionRules.GetErrCount()).To(gomega.BeEquivalentTo(0))
	gomega.Expect(sessionRules.LocalTable(pod1VPPNsIndex).NumOfRules()).To(gomega.BeEquivalentTo(1))
	gomega.Expect(sessionRules.LocalTable(pod1VPPNsIndex).HasRule("", 0, "10.0.0.0/8", 22, "TCP", "DENY")).To(gomega.BeTrue())
	gomega.Expect(sessionRules.GlobalTable().NumOfRules()).To(gomega.BeEquivalentTo(0))

}
