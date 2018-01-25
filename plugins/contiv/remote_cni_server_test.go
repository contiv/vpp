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
	"reflect"
	"strings"
	"testing"

	"git.fd.io/govpp.git/adapter/mock"
	govppmock "git.fd.io/govpp.git/adapter/mock"
	"git.fd.io/govpp.git/adapter/mock/binapi"
	"git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/af_packet"
	interfaces_bin "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/ip"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/memif"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/tap"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vpe"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vxlan"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"

	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/onsi/gomega"
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

var config = Config{
	IPAMConfig: ipam.Config{
		PodSubnetCIDR:           "10.1.0.0/16",
		PodNetworkPrefixLen:     24,
		VPPHostSubnetCIDR:       "172.30.0.0/16",
		VPPHostNetworkPrefixLen: 24,
		NodeInterconnectCIDR:    "192.168.16.0/24",
		VxlanCIDR:               "192.168.30.0/24",
	},
}

func TestVeth1NameFromRequest(t *testing.T) {
	gomega.RegisterTestingT(t)

	txns := localclient.NewTxnTracker(nil)

	server, err := newRemoteCNIServer(logrus.DefaultLogger(),
		txns.NewLinuxDataChangeTxn,
		&kvdbproxy.Plugin{},
		nil,
		nil,
		nil,
		"testlabel",
		&config,
		nil,
		0)
	gomega.Expect(err).To(gomega.BeNil())

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	gomega.Expect(hostIfName).To(gomega.BeEquivalentTo("eth0"))
}

func TestAdd(t *testing.T) {
	gomega.RegisterTestingT(t)

	swIfIdx := swIfIndexMock()
	txns := localclient.NewTxnTracker(addIfsIntoTheIndex(swIfIdx))
	configuredContainers := containeridx.NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")

	server, err := newRemoteCNIServer(logrus.DefaultLogger(),
		txns.NewLinuxDataChangeTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		vppChanMock(),
		swIfIdx,
		"testLabel",
		&config,
		nil,
		0)
	gomega.Expect(err).To(gomega.BeNil())

	// unless we pretend that connectivity is configured requests are blocked
	server.vswitchConnectivityConfigured = true

	reply, err := server.Add(context.Background(), &req)

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(3))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	res := configuredContainers.LookupPodName(podName)
	gomega.Expect(len(res)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(res).To(gomega.ContainElement(containerID))

	txns.Clear()

	reply, err = server.Delete(context.Background(), &req)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

}

func TestConfigureVswitch(t *testing.T) {
	gomega.RegisterTestingT(t)

	swIfIdx := swIfIndexMock()
	txns := localclient.NewTxnTracker(addIfsIntoTheIndex(swIfIdx))
	configuredContainers := containeridx.NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")

	server, err := newRemoteCNIServer(logrus.DefaultLogger(),
		txns.NewLinuxDataChangeTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		vppChanMock(),
		swIfIdx,
		"testLabel",
		&config,
		nil,
		0)

	gomega.Expect(err).To(gomega.BeNil())
	err = server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(5))

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(6))

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
			logrus.DefaultLogger().Error("Not existing req msg name for MsgID=", request.MsgID)
			return reply, 0, false
		}
		logrus.DefaultLogger().Debug("MockReplyHandler ", request.MsgID, " ", reqName)

		if reqName == "sw_interface_dump" {
			codec := govpp.MsgCodec{}
			ifDump := interfaces_bin.SwInterfaceDump{}
			err := codec.DecodeMsg(request.Data, &ifDump)
			if err != nil {
				logrus.DefaultLogger().Error(err)
				return reply, 0, false
			}
			msgID, err := vppMock.GetMsgID("sw_interface_details", "")
			if err != nil {
				logrus.DefaultLogger().Error(err)
				return reply, 0, false
			}

			if ifDump.NameFilterValid == 1 {
				ifDetail := interfaces_bin.SwInterfaceDetails{}
				ifDetail.InterfaceName = ifDump.NameFilter
				// TODO: for more complex tests we have to track assigned swIfIndex to interfaces
				ifDetail.SwIfIndex = 1
				ifDetail.L2Address = []byte("abcdef")
				ifDetail.L2AddressLength = 6

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
					logrus.DefaultLogger().Debug("Succ default reply for ", reqName, " ", msgID, " sw_if_idx=", swIfIndexSeq)
					binapi.SetSwIfIdx(val, swIfIndexSeq)
				} else {
					logrus.DefaultLogger().Debug("Succ default reply for ", reqName, " ", msgID)
				}

				reply, err := vppMock.ReplyBytes(request, replyMsg)
				if err == nil {
					return reply, msgID, true
				}
				logrus.DefaultLogger().Error("Error creating bytes ", err)
			} else {
				logrus.DefaultLogger().Info("No default reply for ", reqName, ", ", request.MsgID)
			}
		}

		return reply, 0, false
	})

	conn, err := govpp.Connect(vppMock)
	if err != nil {
		return nil
	}

	c, _ := conn.NewAPIChannel()
	return c
}

func addIfsIntoTheIndex(mapping ifaceidx.SwIfIndexRW) func(txn *localclient.Txn) error {
	return func(txn *localclient.Txn) error {
		var cnt uint32 = 1
		if txn.LinuxDataChangeTxn == nil {
			// RESYNC not handled
			return nil
		}
		for _, op := range txn.LinuxDataChangeTxn.Ops {
			if op.Value != nil /* Put */ && strings.HasPrefix(op.Key, vpp_intf.InterfaceKeyPrefix()) {
				name, err := vpp_intf.ParseNameFromKey(op.Key)
				if err != nil {
					return err
				}
				if data, ok := (op.Value).(*vpp_intf.Interfaces_Interface); ok {
					mapping.RegisterName(name, cnt, data)
					cnt++
				}
			}
		}
		return nil
	}
}

func swIfIndexMock() ifaceidx.SwIfIndexRW {
	mapping := nametoidx.NewNameToIdx(logrus.DefaultLogger(), "plugin", "swIf", ifaceidx.IndexMetadata)

	return ifaceidx.NewSwIfIndex(mapping)
}
