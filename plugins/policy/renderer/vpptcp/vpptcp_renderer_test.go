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

	"git.fd.io/govpp.git/adapter/mock"
	govppmock "git.fd.io/govpp.git/adapter/mock"
	//"git.fd.io/govpp.git/adapter/mock/binapi"
	"git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"

	. "github.com/contiv/vpp/mock/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/bin_api/session"
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

func vppChanMock() *api.Channel {
	vppMock := &mock.VppAdapter{}
	vppMock.RegisterBinAPITypes(session.Types)

	vppMock.MockReplyHandler(func(request govppmock.MessageDTO) (reply []byte, msgID uint16, prepared bool) {
		reqName, found := vppMock.GetMsgNameByID(request.MsgID)
		if !found {
			logroot.StandardLogger().Error("Not existing req msg name for MsgID=", request.MsgID)
			return reply, 0, false
		}
		logroot.StandardLogger().Debug("MockReplyHandler ", request.MsgID, " ", reqName)

		/* TODO
		if reqName == "sw_interface_dump" {
			codec := govpp.MsgCodec{}
			ifDump := interfaces_bin.SwInterfaceDump{}
			err := codec.DecodeMsg(request.Data, &ifDump)
			if err != nil {
				logroot.StandardLogger().Error(err)
				return reply, 0, false
			}
			msgID, err := vppMock.GetMsgID("sw_interface_details", "")
			if err != nil {
				logroot.StandardLogger().Error(err)
				return reply, 0, false
			}

			if ifDump.NameFilterValid == 1 {
				ifDetail := interfaces_bin.SwInterfaceDetails{}
				ifDetail.InterfaceName = ifDump.NameFilter
				reply, err := vppMock.ReplyBytes(request, &ifDetail)
				if err == nil {
					return reply, msgID, true
				}
			}

		} else if strings.HasSuffix(reqName, "_dump") {
			//do nothing and let reply next time for control_ping
		} else {
			if replyMsg, msgID, ok := vppMock.ReplyFor(reqName); ok {
				val := reflect.ValueOf(replyMsg)
				valType := val.Type()
				if binapi.HasSwIfIdx(valType) {
					swIfIndexSeq++
					logroot.StandardLogger().Debug("Succ default reply for ", reqName, " ", msgID, " sw_if_idx=", swIfIndexSeq)
					binapi.SetSwIfIdx(val, swIfIndexSeq)
				} else {
					logroot.StandardLogger().Debug("Succ default reply for ", reqName, " ", msgID)
				}

				reply, err := vppMock.ReplyBytes(request, replyMsg)
				if err == nil {
					return reply, msgID, true
				}
				logroot.StandardLogger().Error("Error creating bytes ", err)
			} else {
				logroot.StandardLogger().Info("No default reply for ", reqName, ", ", request.MsgID)
			}
		}
		*/

		return reply, 0, false
	})

	conn, err := govpp.Connect(vppMock)
	if err != nil {
		return nil
	}

	c, _ := conn.NewAPIChannel()
	return c
}

func TestSomething(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSomething")

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

	// Prepare VPPTCP Renderer.
	vppTCPRenderer := &Renderer{
		Deps: Deps{
			Log:       logger,
			Contiv:    contiv,
			GoVPPChan: vppChanMock(),
		},
	}
	vppTCPRenderer.Init()

	// Execute Renderer transaction.
	vppTCPRenderer.NewTxn(false).Render(pod1, getOneHostSubnet(pod1IP), ingress, egress).Commit()

	// TODO: Verify output
}
