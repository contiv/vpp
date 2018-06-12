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
	"fmt"
	"net"
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
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/golang/protobuf/proto"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/af_packet"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/dhcp"
	interfaces_bin "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/ip"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/memif"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/tap"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vpe"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vxlan"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"

	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/onsi/gomega"
)

const (
	containerID  = "sadfja813227wdhfjkh2319784dgh"
	podName      = "ubuntu"
	podNamespace = "default"
)

var swIfIndexSeq uint32

var req = cni.CNIRequest{
	Version:          "0.2.3",
	InterfaceName:    "eth0",
	ContainerId:      containerID,
	NetworkNamespace: "/var/run/2345243",
	ExtraArguments:   "IgnoreUnknown=1;K8S_POD_NAMESPACE=" + podNamespace + ";K8S_POD_NAME=" + podName + ";K8S_POD_INFRA_CONTAINER_ID=7d673108b0ff9b2f59f977ca5f4cef347cb9ca66888614068882fbfaba4de752",
}

var (
	configVethL2NoTCP = Config{
		TCPstackDisabled:  true,
		UseL2Interconnect: true,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:           "10.1.0.0/16",
			PodNetworkPrefixLen:     24,
			PodIfIPCIDR:             "10.2.1.0/24",
			VPPHostSubnetCIDR:       "172.30.0.0/16",
			VPPHostNetworkPrefixLen: 24,
			NodeInterconnectCIDR:    "192.168.16.0/24",
			VxlanCIDR:               "192.168.30.0/24",
		},
	}
	configTapVxlanTCP = Config{
		UseTAPInterfaces:    true,
		TAPInterfaceVersion: 2,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:           "10.1.0.0/16",
			PodNetworkPrefixLen:     24,
			PodIfIPCIDR:             "10.2.1.0/24",
			VPPHostSubnetCIDR:       "172.30.0.0/16",
			VPPHostNetworkPrefixLen: 24,
			NodeInterconnectCIDR:    "192.168.16.0/24",
			VxlanCIDR:               "192.168.30.0/24",
		},
	}
	nodeConfig = OneNodeConfig{
		NodeName: "test-node",
		Gateway:  "192.168.1.100",
		MainVPPInterface: InterfaceWithIP{
			InterfaceName: "GigabitEthernet0/0/0/1",
			IP:            "192.168.1.1/24",
		},
		OtherVPPInterfaces: []InterfaceWithIP{
			{
				InterfaceName: "GigabitEthernet0/0/0/10",
				IP:            "192.168.1.10/24",
			},
		},
	}
	nodeDHCPConfig = OneNodeConfig{
		NodeName: "test-node",
		MainVPPInterface: InterfaceWithIP{
			InterfaceName: "GigabitEthernet0/0/0/1",
			UseDHCP:       true,
		},
		OtherVPPInterfaces: []InterfaceWithIP{
			{
				InterfaceName: "GigabitEthernet0/0/0/10",
				IP:            "192.168.1.10/24",
			},
		},
	}
	otherNodeInfo = node.NodeInfo{
		Id:                  5,
		Name:                "node5",
		IpAddress:           "1.2.3.4/25",
		ManagementIpAddress: "192.168.42.5",
	}
)

func setupTestCNIServer(config *Config, nodeConfig *OneNodeConfig, existingInterfaces ...string) (*remoteCNIserver, *localclient.TxnTracker, *containeridx.ConfigIndex, *govpp.Connection) {
	swIfIdx := swIfIndexMock()
	// add existing interfaces into swIfIndex
	for i, intf := range existingInterfaces {
		swIfIdx.RegisterName(intf, uint32(i+1), nil)
	}

	txns := localclient.NewTxnTracker(addIfsIntoTheIndex(swIfIdx))
	configuredContainers := containeridx.NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title", nil)

	vppMockChan, vppMockConn := vppChanMock()

	server, err := newRemoteCNIServer(logrus.DefaultLogger(),
		txns.NewLinuxDataChangeTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		vppMockChan,
		swIfIdx,
		dhcpIndexMock(),
		"testLabel",
		config,
		nodeConfig,
		1,
		nil,
		nil)
	server.test = true
	gomega.Expect(err).To(gomega.BeNil())

	return server, txns, configuredContainers, vppMockConn
}

func TestHwAddress(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, _, _, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	var addresses []string

	checkUniqueness := func(existing []string, nodeID uint32) (updated []string) {
		a := server.hwAddrForVXLAN(nodeID)
		fmt.Println(a)
		gomega.Expect(existing).NotTo(gomega.ContainElement(a))
		return append(addresses, a)
	}

	// the first valid value
	addresses = checkUniqueness(addresses, 1)
	addresses = checkUniqueness(addresses, 2)
	// max value generated in backward compatible way
	addresses = checkUniqueness(addresses, 255)

	addresses = checkUniqueness(addresses, 256)
	addresses = checkUniqueness(addresses, 257)
	addresses = checkUniqueness(addresses, 512)

	// max value
	addresses = checkUniqueness(addresses, 256*256*256*256-1)

}

func TestAddDelVeth(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, configuredContainers, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	// pretend that connectivity is configured to unblock CNI requests
	server.vswitchConnectivityConfigured = true

	// CNI Add
	reply, err := server.Add(context.Background(), &req)

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(2)) // not applied reverts
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(3))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	res := configuredContainers.LookupPodName(podName)
	gomega.Expect(len(res)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(res).To(gomega.ContainElement(containerID))

	txns.Clear()

	// CNI Delete
	reply, err = server.Delete(context.Background(), &req)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())
}

func TestConfigureVswitchDHCP(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, &nodeDHCPConfig, nodeDHCPConfig.MainVPPInterface.InterfaceName)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(5))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// node IP is empty since DHCP reply have not been received
	gomega.Expect(server.GetNodeIP()).To(gomega.BeEmpty())
	// host interconnect IF must be configured
	gomega.Expect(server.GetHostInterconnectIfName()).ToNot(gomega.BeEmpty())

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(6))
}

func TestAddDelTap(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, configuredContainers, conn := setupTestCNIServer(&configTapVxlanTCP, &nodeConfig)
	defer conn.Disconnect()

	// pretend that connectivity is configured to unblock CNI requests
	server.vswitchConnectivityConfigured = true

	// CNI Add
	reply, err := server.Add(context.Background(), &req)

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(2)) // not applied reverts
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(4))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	res := configuredContainers.LookupPodName(podName)
	gomega.Expect(len(res)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(res).To(gomega.ContainElement(containerID))

	txns.Clear()

	// CNI Delete
	reply, err = server.Delete(context.Background(), &req)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())
}

func TestConfigureVswitchVeth(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configVethL2NoTCP, &nodeConfig, nodeConfig.OtherVPPInterfaces[0].InterfaceName)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(5))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// check physical interface name
	physIf := server.GetMainPhysicalIfName()
	gomega.Expect(physIf).To(gomega.BeEquivalentTo(nodeConfig.MainVPPInterface.InterfaceName))
	// node IP must not be empty
	nodeIP, nodeNet := server.GetNodeIP()
	gomega.Expect(nodeIP).ToNot(gomega.BeEmpty())
	gomega.Expect(nodeNet).ToNot(gomega.BeNil())
	// host interconnect IF must be configured
	gomega.Expect(server.GetHostInterconnectIfName()).ToNot(gomega.BeEmpty())
	// using L2 interconnect - no VXLAN IF name
	gomega.Expect(server.GetVxlanBVIIfName()).To(gomega.BeEmpty())
	// gateway is configured
	gomega.Expect(server.GetDefaultGatewayIP().Equal(net.ParseIP("192.168.1.100"))).To(gomega.BeTrue())
	// with extra physical interfaces
	gomega.Expect(server.GetOtherPhysicalIfNames()).To(gomega.Equal([]string{"GigabitEthernet0/0/0/10"}))

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(6))
}

func TestConfigureVswitchTap(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(5))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// node IP must not be empty
	nodeIP, nodeNet := server.GetNodeIP()
	gomega.Expect(nodeIP).ToNot(gomega.BeEmpty())
	gomega.Expect(nodeNet).ToNot(gomega.BeNil())
	// host interconnect IF must be configured
	gomega.Expect(server.GetHostInterconnectIfName()).ToNot(gomega.BeEmpty())
	// using VXLANs - VXLAN IF name must not be empty
	gomega.Expect(server.GetVxlanBVIIfName()).ToNot(gomega.BeEmpty())

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(6))
}

func TestNodeAddDelL2(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put})
	gomega.Expect(err).To(gomega.BeNil())

	// check that the VXLAN interface does not exist
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", otherNodeInfo.Id))
	gomega.Expect(vxlanIf).To(gomega.BeNil())

	// check routes to the other node pointing to node IP
	nexthopIP := server.ipPrefixToAddress(otherNodeInfo.IpAddress)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP)
	gomega.Expect(len(routes)).To(gomega.BeEquivalentTo(3))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete})
	gomega.Expect(err).To(gomega.BeNil())
}

func TestNodeAddDelVXLAN(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put})
	gomega.Expect(err).To(gomega.BeNil())

	// check that the VXLAN tunnel config has been properly added
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", otherNodeInfo.Id))
	gomega.Expect(vxlanIf).ToNot(gomega.BeNil())
	gomega.Expect(otherNodeInfo.IpAddress).To(gomega.ContainSubstring(vxlanIf.Vxlan.DstAddress))

	// check routes to the other node pointing to VXLAN IP
	nexthopIP, _ := server.ipam.VxlanIPAddress(otherNodeInfo.Id)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP.String())
	gomega.Expect(len(routes)).To(gomega.BeEquivalentTo(3))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete})
	gomega.Expect(err).To(gomega.BeNil())
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
		nil,
		"testlabel",
		&configVethL2NoTCP,
		nil,
		1, nil, nil)
	gomega.Expect(err).To(gomega.BeNil())

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	gomega.Expect(hostIfName).To(gomega.BeEquivalentTo("eth0"))
}

func vppChanMock() (*api.Channel, *govpp.Connection) {
	vppMock := &mock.VppAdapter{}
	vppMock.RegisterBinAPITypes(interfaces_bin.Types)
	vppMock.RegisterBinAPITypes(memif.Types)
	vppMock.RegisterBinAPITypes(tap.Types)
	vppMock.RegisterBinAPITypes(af_packet.Types)
	vppMock.RegisterBinAPITypes(vpe.Types)
	vppMock.RegisterBinAPITypes(vxlan.Types)
	vppMock.RegisterBinAPITypes(ip.Types)
	vppMock.RegisterBinAPITypes(dhcp.Types)

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
		return nil, nil
	}

	c, _ := conn.NewAPIChannel()
	return c, conn
}

func addIfsIntoTheIndex(mapping ifaceidx.SwIfIndexRW) func(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	return func(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
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

func dhcpIndexMock() ifaceidx.DhcpIndex {
	mapping := nametoidx.NewNameToIdx(logrus.DefaultLogger(), "plugin", "dhcpIf", ifaceidx.IndexDHCPMetadata)

	return ifaceidx.NewDHCPIndex(mapping)
}

// interfaceInLatestRevs returns interface of given name from the map of latest revisions
func interfaceInLatestRevs(latestRevs *syncbase.PrevRevisions, ifName string) *vpp_intf.Interfaces_Interface {
	for _, key := range latestRevs.ListKeys() {
		if strings.HasPrefix(key, vpp_intf.InterfacePrefix) && strings.HasSuffix(key, ifName) {
			intf := &vpp_intf.Interfaces_Interface{}
			_, value := latestRevs.Get(key)
			value.GetValue(intf)
			return intf
		}
	}
	return nil
}

// routesViaInLatestRevs returns routes pointing to privided next hop IP from the map of latest revisions
func routesViaInLatestRevs(latestRevs *syncbase.PrevRevisions, nexthopIP string) []*vpp_l3.StaticRoutes_Route {
	routes := make([]*vpp_l3.StaticRoutes_Route, 0)

	for _, key := range latestRevs.ListKeys() {
		if strings.HasPrefix(key, vpp_l3.VrfPrefix) && strings.HasSuffix(key, nexthopIP) {
			route := &vpp_l3.StaticRoutes_Route{}
			_, value := latestRevs.Get(key)
			value.GetValue(route)
			routes = append(routes, route)
		}
	}

	return routes
}

// nodeAddDelEvent simulates addition of a k8s node into a cluster
type nodeAddDelEvent struct {
	evType datasync.PutDel
}

func (e *nodeAddDelEvent) Done(error) {}

func (e nodeAddDelEvent) GetChangeType() datasync.PutDel {
	return e.evType
}

func (e nodeAddDelEvent) GetKey() string {
	return node.AllocatedIDsKeyPrefix
}

func (e nodeAddDelEvent) GetValue(value proto.Message) error {
	if e.evType == datasync.Put {
		v := value.(*node.NodeInfo)
		v.Id = otherNodeInfo.Id
		v.Name = otherNodeInfo.Name
		v.IpAddress = otherNodeInfo.IpAddress
		v.ManagementIpAddress = otherNodeInfo.ManagementIpAddress
	}
	return nil
}

func (e nodeAddDelEvent) GetPrevValue(prevValue proto.Message) (prevValueExist bool, err error) {
	if e.evType == datasync.Put {
		return false, nil
	}
	v := prevValue.(*node.NodeInfo)
	v.Id = otherNodeInfo.Id
	v.Name = otherNodeInfo.Name
	v.IpAddress = otherNodeInfo.IpAddress
	v.ManagementIpAddress = otherNodeInfo.ManagementIpAddress
	return true, nil
}

func (e nodeAddDelEvent) GetRevision() int64 {
	// return revision should be bigger than resync Rev in order to apply the change
	return 1
}
