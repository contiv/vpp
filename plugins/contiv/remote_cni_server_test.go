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

package contiv

import (
	"context"
	"net"
	"testing"

	"git.fd.io/govpp.git/adapter/mock"
	govppmock "git.fd.io/govpp.git/adapter/mock"
	"git.fd.io/govpp.git/adapter/mock/binapi"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/ligato/vpp-agent/clientv1/defaultplugins"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/af_packet"
	interfaces_bin "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/memif"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/tap"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/vpe"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/vxlan"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/bfd"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"
	"github.com/onsi/gomega"
	"reflect"
	"strings"

	"git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/ip"
)

const (
	containerID = "sadfja813227wdhfjkh2319784dgh"
	podName     = "ubuntu"
)

var swIfIndexSeq uint32

var req = cni.CNIRequest{
	Version:          "0.2.3",
	InterfaceName:    "eth0",
	ContainerId:      containerID,
	NetworkNamespace: "/var/run/2345243",
	ExtraArguments:   "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=" + podName + ";K8S_POD_INFRA_CONTAINER_ID=7d673108b0ff9b2f59f977ca5f4cef347cb9ca66888614068882fbfaba4de752",
}

func TestVeth1NameFromRequest(t *testing.T) {
	gomega.RegisterTestingT(t)

	server := newRemoteCNIServer(logroot.StandardLogger(),
		func() linux.DataChangeDSL { return NewMockDataChangeDSL(nil) },
		&kvdbproxy.Plugin{},
		nil,
		nil,
		nil)

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	gomega.Expect(hostIfName).To(gomega.BeEquivalentTo("eth0"))
}

func TestAdd(t *testing.T) {
	gomega.RegisterTestingT(t)

	configuredContainers := containeridx.NewConfigIndex(logroot.StandardLogger(), core.PluginName("Plugin-name"), "title")
	swIfIdx := swIfIndexMock()
	txns := &txnTracker{onSend: addIfsIntoTheIndex(swIfIdx)}

	server := newRemoteCNIServer(logroot.StandardLogger(),
		txns.newTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		vppChanMock(),
		swIfIdx)
	server.hostCalls = &mockLinuxCalls{}

	reply, err := server.Add(context.Background(), &req)

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

	gomega.Expect(len(txns.txns)).To(gomega.BeEquivalentTo(3))
	// TODO add asserts for txns

	res := configuredContainers.LookupPodName(podName)
	gomega.Expect(len(res)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(res).To(gomega.ContainElement(containerID))

	// TODO clear txnTracker

	reply, err = server.Delete(context.Background(), &req)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

}

func vppChanMock() *api.Channel {
	vppMock := &mock.VppAdapter{}
	vppMock.RegisterBinAPITypes(interfaces_bin.Types)
	vppMock.RegisterBinAPITypes(memif.Types)
	vppMock.RegisterBinAPITypes(tap.Types)
	vppMock.RegisterBinAPITypes(af_packet.Types)
	vppMock.RegisterBinAPITypes(vpe.Types)
	vppMock.RegisterBinAPITypes(vxlan.Types)
	vppMock.RegisterBinAPITypes(ip.Types)

	vppMock.MockReplyHandler(func(request govppmock.MessageDTO) (reply []byte, msgID uint16, prepared bool) {
		reqName, found := vppMock.GetMsgNameByID(request.MsgID)
		if !found {
			logroot.StandardLogger().Error("Not existing req msg name for MsgID=", request.MsgID)
			return reply, 0, false
		}
		logroot.StandardLogger().Debug("MockReplyHandler ", request.MsgID, " ", reqName)

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

		return reply, 0, false
	})

	conn, connChan, err := govpp.AsyncConnect(vppMock)
	if err != nil {
		return nil
	}
	<-connChan

	c, _ := conn.NewAPIChannel()
	return c
}

func addIfsIntoTheIndex(mapping ifaceidx.SwIfIndexRW) func(*MockDataChangeDSL) error {
	return func(dsl *MockDataChangeDSL) error {
		var cnt uint32 = 1
		for k, v := range dsl.performedPut {
			if strings.HasPrefix(k, vpp_intf.InterfaceKeyPrefix()) {
				name, err := vpp_intf.ParseNameFromKey(k)
				if err != nil {
					return err
				}
				if data, ok := v.(*vpp_intf.Interfaces_Interface); ok {
					mapping.RegisterName(name, cnt, data)
					cnt++
				}

			}
		}
		return nil
	}
}

func swIfIndexMock() ifaceidx.SwIfIndexRW {
	mapping := nametoidx.NewNameToIdx(logroot.StandardLogger(), "plugin", "swIf", ifaceidx.IndexMetadata)

	return ifaceidx.NewSwIfIndex(mapping)
}

type txnTracker struct {
	txns   []*MockDataChangeDSL
	onSend func(txn *MockDataChangeDSL) error
}

func (t *txnTracker) newTxn() linux.DataChangeDSL {
	txn := NewMockDataChangeDSL(t.onSend)
	t.txns = append(t.txns, txn)
	return txn
}

type MockDataChangeDSL struct {
	onSend         func(txn *MockDataChangeDSL) error
	expectedPut    map[string]interface{}
	expectedDelete map[string]interface{}
	performedPut   map[string]proto.Message
	performedDel   []string
}

func NewMockDataChangeDSL(onSend func(*MockDataChangeDSL) error) *MockDataChangeDSL {
	return &MockDataChangeDSL{onSend: onSend,
		expectedPut:    map[string]interface{}{},
		expectedDelete: map[string]interface{}{},
		performedPut:   map[string]proto.Message{}}
}

type MockPutDSL struct {
	parent *MockDataChangeDSL
}

type MockDeleteDSL struct {
	parent *MockDataChangeDSL
}

// Put initiates a chained sequence of data change DSL statements declaring
// new or changing existing configurable objects.
func (dsl *MockDataChangeDSL) Put() linux.PutDSL {
	return &MockPutDSL{dsl}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (dsl *MockDataChangeDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{dsl}
}

// Send propagates requested changes to the plugins.
func (dsl *MockDataChangeDSL) Send() defaultplugins.Reply {
	var err error
	if dsl.onSend != nil {
		err = dsl.onSend(dsl)
	}
	return &Reply{err}
}

// Interface adds a request to create or update VPP network interface.
func (dsl *MockPutDSL) VppInterface(val *vpp_intf.Interfaces_Interface) linux.PutDSL {
	dsl.parent.performedPut[vpp_intf.InterfaceKey(val.Name)] = val
	return dsl
}

// BfdSession adds a request to create or update bidirectional forwarding
// detection session.
func (dsl *MockPutDSL) BfdSession(val *bfd.SingleHopBFD_Session) linux.PutDSL {
	dsl.parent.performedPut[bfd.SessionKey(val.Interface)] = val
	return dsl
}

// BfdAuthKeys adds a request to create or update bidirectional forwarding
// detection key.
func (dsl *MockPutDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linux.PutDSL {
	dsl.parent.performedPut[bfd.AuthKeysKey(string(val.Id))] = val
	return dsl
}

// BfdEchoFunction adds a request to create or update bidirectional forwarding
// detection echo function.
func (dsl *MockPutDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linux.PutDSL {
	dsl.parent.performedPut[bfd.EchoFunctionKey(val.EchoSourceInterface)] = val
	return dsl
}

// BD adds a request to create or update VPP Bridge Domain.
func (dsl *MockPutDSL) BD(val *l2.BridgeDomains_BridgeDomain) linux.PutDSL {
	dsl.parent.performedPut[l2.BridgeDomainKey(val.Name)] = val
	return dsl
}

// BDFIB adds a request to create or update VPP L2 Forwarding Information Base.
func (dsl *MockPutDSL) BDFIB(val *l2.FibTableEntries_FibTableEntry) linux.PutDSL {
	dsl.parent.performedPut[l2.FibKey(val.BridgeDomain, val.PhysAddress)] = val
	return dsl
}

// XConnect adds a request to create or update VPP Cross Connect.
func (dsl *MockPutDSL) XConnect(val *l2.XConnectPairs_XConnectPair) linux.PutDSL {
	dsl.parent.performedPut[l2.XConnectKey(val.ReceiveInterface)] = val
	return dsl
}

// StaticRoute adds a request to create or update VPP L3 Static Route.
func (dsl *MockPutDSL) StaticRoute(val *l3.StaticRoutes_Route) linux.PutDSL {
	_, dstAddr, _ := net.ParseCIDR(val.DstIpAddr)
	dsl.parent.performedPut[l3.RouteKey(val.VrfId, dstAddr, val.NextHopAddr)] = val
	return dsl
}

// ACL adds a request to create or update VPP Access Control List.
func (dsl *MockPutDSL) ACL(val *acl.AccessLists_Acl) linux.PutDSL {
	dsl.parent.performedPut[acl.Key(val.AclName)] = val
	return dsl
}

func (dsl *MockPutDSL) LinuxInterface(val *linux_intf.LinuxInterfaces_Interface) linux.PutDSL {
	return dsl
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (dsl *MockPutDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{dsl.parent}
}

// Send propagates requested changes to the plugins.
func (dsl *MockPutDSL) Send() defaultplugins.Reply {
	return dsl.parent.Send()
}

// Interface adds a request to delete an existing VPP network interface.
func (dsl *MockDeleteDSL) VppInterface(interfaceName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, vpp_intf.InterfaceKey(interfaceName))
	return dsl
}

// BfdSession adds a request to delete an existing bidirectional forwarding
// detection session.
func (dsl *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, bfd.SessionKey(bfdSessionIfaceName))
	return dsl
}

// BfdAuthKeys adds a request to delete an existing bidirectional forwarding
// detection key.
func (dsl *MockDeleteDSL) BfdAuthKeys(bfdKeyName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, bfd.AuthKeysKey(bfdKeyName))
	return dsl
}

// BfdEchoFunction adds a request to delete an existing bidirectional forwarding
// detection echo function.
func (dsl *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, bfd.EchoFunctionKey(bfdEchoName))
	return dsl
}

// BD adds a request to delete an existing VPP Bridge Domain.
func (dsl *MockDeleteDSL) BD(bdName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, l2.BridgeDomainKey(bdName))
	return dsl
}

// BDFIB adds a request to delete an existing VPP L2 Forwarding Information
// Base.
func (dsl *MockDeleteDSL) BDFIB(bdName string, mac string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, l2.FibKey(bdName, mac))
	return dsl
}

// XConnect adds a request to delete an existing VPP Cross Connect.
func (dsl *MockDeleteDSL) XConnect(rxIfName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, l2.XConnectKey(rxIfName))
	return dsl
}

// StaticRoute adds a request to delete an existing VPP L3 Static Route..
func (dsl *MockDeleteDSL) StaticRoute(vrf uint32, dstAddrInput *net.IPNet, nextHopAddr net.IP) linux.DeleteDSL {
	//_, dstAddr, _ := net.ParseCIDR(dstAddrInput)
	dsl.parent.performedDel = append(dsl.parent.performedDel, l3.RouteKey(vrf, dstAddrInput, nextHopAddr.String()))
	return dsl
}

// ACL adds a request to delete an existing VPP Access Control List.
func (dsl *MockDeleteDSL) ACL(aclName string) linux.DeleteDSL {
	dsl.parent.performedDel = append(dsl.parent.performedDel, acl.Key(aclName))
	return dsl
}
func (dsl *MockDeleteDSL) LinuxInterface(ifname string) linux.DeleteDSL {
	return dsl
}

// Put changes the DSL mode to allow configuration editing.
func (dsl *MockDeleteDSL) Put() linux.PutDSL {
	return &MockPutDSL{dsl.parent}
}

// Send propagates requested changes to the plugins.
func (dsl *MockDeleteDSL) Send() defaultplugins.Reply {
	return dsl.parent.Send()
}

// Reply interface allows to wait for a reply to previously called Send() and
// extract the result from it (success/error).
type Reply struct {
	err error
}

// ReceiveReply waits for a reply to previously called Send() and returns
// the result (error or nil).
func (dsl Reply) ReceiveReply() error {
	return dsl.err
}
