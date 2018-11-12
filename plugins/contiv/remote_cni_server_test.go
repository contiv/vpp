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

/*
import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/onsi/gomega"

	"git.fd.io/govpp.git/adapter/mock"
	govppmock "git.fd.io/govpp.git/adapter/mock"
	"git.fd.io/govpp.git/adapter/mock/binapi"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/codec"
	govpp "git.fd.io/govpp.git/core"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/ligato/cn-infra/idxmap"
	idxmap_mem "github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging/logrus"

	interfaces_bin "github.com/ligato/vpp-agent/plugins/vpp/binapi/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/go-errors/errors"
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
		UseL2Interconnect: true,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:           "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			PodVPPSubnetCIDR:             "10.2.1.0/24",
			VPPHostSubnetCIDR:       "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectCIDR:    "192.168.16.0/24",
			VxlanCIDR:               "192.168.30.0/24",
		},
	}
	configTapVxlanTCP = Config{
		UseTAPInterfaces:    true,
		TAPInterfaceVersion: 2,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:           "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			PodVPPSubnetCIDR:             "10.2.1.0/24",
			VPPHostSubnetCIDR:       "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectCIDR:    "192.168.16.0/24",
			VxlanCIDR:               "192.168.30.0/24",
		},
	}
	configTapVxlanDHCP = Config{
		UseTAPInterfaces:    true,
		TAPInterfaceVersion: 2,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:           "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			PodVPPSubnetCIDR:             "10.2.1.0/24",
			VPPHostSubnetCIDR:       "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectDHCP:    true,
			VxlanCIDR:               "192.168.30.0/24",
		},
	}
	nodeConfig = NodeConfig{
		NodeName: "test-node",
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			Gateway: "192.168.1.100",
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: "GigabitEthernet0/0/0/1",
				IP:            "192.168.1.1/24",
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: "GigabitEthernet0/0/0/10",
					IP:            "192.168.1.10/24",
				},
			},
		},
	}
	nodeDHCPConfig = NodeConfig{
		NodeName: "test-node",
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: "GigabitEthernet0/0/0/1",
				UseDHCP:       true,
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: "GigabitEthernet0/0/0/10",
					IP:            "192.168.1.10/24",
				},
			},
		},
	}
	otherNodeInfo = node.NodeInfo{
		Id:                  5,
		Name:                "node5",
		IpAddress:           "1.2.3.4/25",
		ManagementIpAddress: "192.168.42.5",
	}
	nodeWith2mgmtIP = node.NodeInfo{
		Id:                  6,
		Name:                "node6",
		IpAddress:           "1.2.3.6/25",
		ManagementIpAddress: "10.10.76.79,10.10.76.161",
	}
)

func setupTestCNIServer(config *Config, nodeConfig *NodeConfig, existingInterfaces ...string) (*remoteCNIserver, *localclient.TxnTracker, *containeridx.ConfigIndex, *govpp.Connection) {
	swIfIdx := swIfIndexMock()
	// add existing interfaces into swIfIndex
	for i, intf := range existingInterfaces {
		swIfIdx.Put(intf, ifaceidx.IfaceMetadata{SwIfIndex: uint32(i + 1)})
	}

	txns := localclient.NewTxnTracker(addIfsIntoTheIndex(swIfIdx))
	configuredContainers := containeridx.NewConfigIndex(logrus.DefaultLogger(), "title", nil)

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

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(1))
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

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// node IP is empty since DHCP reply have not been received
	gomega.Expect(server.GetNodeIP()).To(gomega.BeEmpty())
	// host interconnect IF must be configured
	gomega.Expect(server.GetHostInterconnectIfName()).ToNot(gomega.BeEmpty())

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(2))
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

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(1))
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

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(1))
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
	defaultIfName, defaultIfIP := server.GetDefaultInterface()
	gomega.Expect(defaultIfIP.String()).To(gomega.Equal("192.168.1.1"))
	gomega.Expect(defaultIfName).To(gomega.BeEquivalentTo(nodeConfig.MainVPPInterface.InterfaceName))
	// with extra physical interfaces
	gomega.Expect(server.GetOtherPhysicalIfNames()).To(gomega.Equal([]string{"GigabitEthernet0/0/0/10"}))

	server.close()
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(2))
}

func TestConfigureVswitchTap(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(1))
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
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(2))
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
	nexthopIP := ipNetToAddress(otherNodeInfo.IpAddress)
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
	gomega.Expect(otherNodeInfo.IpAddress).To(gomega.ContainSubstring(vxlanIf.GetVxlan().DstAddress))

	// check routes to the other node pointing to VXLAN IP
	nexthopIP, _ := server.ipam.VxlanIPAddress(otherNodeInfo.Id)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP.String())
	gomega.Expect(len(routes)).To(gomega.BeEquivalentTo(3))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete})
	gomega.Expect(err).To(gomega.BeNil())
}

func TestNodeAddDelNodeWithMultipleMgmtAddresses(t *testing.T) {
	gomega.RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	gomega.Expect(err).To(gomega.BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put, nodeInfo: &nodeWith2mgmtIP})
	gomega.Expect(err).To(gomega.BeNil())

	// check that the VXLAN tunnel config has been properly added
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", nodeWith2mgmtIP.Id))
	gomega.Expect(vxlanIf).ToNot(gomega.BeNil())
	gomega.Expect(nodeWith2mgmtIP.IpAddress).To(gomega.ContainSubstring(vxlanIf.GetVxlan().DstAddress))

	// check routes to the other node pointing to VXLAN IP
	nexthopIP, _ := server.ipam.VxlanIPAddress(nodeWith2mgmtIP.Id)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP.String())
	gomega.Expect(len(routes)).To(gomega.BeEquivalentTo(4))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete, nodeInfo: &nodeWith2mgmtIP})
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
		1, nil, nil, nil)
	gomega.Expect(err).To(gomega.BeNil())

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	gomega.Expect(hostIfName).To(gomega.BeEquivalentTo("eth0"))
}

func initServerForDHCPTesting() (*remoteCNIserver, *govpp.Connection, idxmap.NamedMappingRW) {
	swIfIdx := swIfIndexMock()

	txns := localclient.NewTxnTracker(addIfsIntoTheIndex(swIfIdx))
	configuredContainers := containeridx.NewConfigIndex(logrus.DefaultLogger(), "title", nil)

	vppMockChan, vppMockConn := vppChanMock()

	dhcpIndex := dhcpIndexMock()
	server, err := newRemoteCNIServer(logrus.DefaultLogger(),
		txns.NewLinuxDataChangeTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		vppMockChan,
		swIfIdx,
		dhcpIndex,
		"testLabel",
		&configTapVxlanDHCP,
		&nodeDHCPConfig,
		1,
		nil,
		nil,
		nil)
	server.test = true
	gomega.Expect(err).To(gomega.BeNil())
	return server, vppMockConn, dhcpIndex
}

func TestWithDHCPDelayedNotif(t *testing.T) {
	gomega.RegisterTestingT(t)

	var server *remoteCNIserver

	server, conn, dhcpIndex := initServerForDHCPTesting()
	defer conn.Disconnect()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := server.resync()
		gomega.Expect(err).To(gomega.BeNil())
		wg.Done()
	}()
	time.Sleep(200 * time.Millisecond)
	dhcpIndex.Put(nodeDHCPConfig.MainVPPInterface.InterfaceName, &vpp_intf.DHCPLease{
		InterfaceName: nodeDHCPConfig.MainVPPInterface.InterfaceName,
		HostIpAddress: "1.1.1.1/24",
	})
	wg.Wait()
	getIP := func() string {
		ip, _ := server.GetNodeIP()
		return ip.String()
	}
	gomega.Eventually(getIP).Should(gomega.BeEquivalentTo("1.1.1.1"))
}

func TestWithDHCPQuickNotif(t *testing.T) {
	gomega.RegisterTestingT(t)

	var server *remoteCNIserver

	server, conn, dhcpIndex := initServerForDHCPTesting()
	defer conn.Disconnect()

	dhcpIndex.Put(nodeDHCPConfig.MainVPPInterface.InterfaceName, &vpp_intf.DHCPLease{
		InterfaceName: nodeDHCPConfig.MainVPPInterface.InterfaceName,
		HostIpAddress: "1.1.1.1/24",
	})

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := server.resync()
		gomega.Expect(err).To(gomega.BeNil())
		wg.Done()
	}()
	wg.Wait()
	getIP := func() string {
		ip, _ := server.GetNodeIP()
		return ip.String()
	}
	gomega.Eventually(getIP).Should(gomega.BeEquivalentTo("1.1.1.1"))
}

func vppChanMock() (api.Channel, *govpp.Connection) {
	vppMock := mock.NewVppAdapter()

	vppMock.MockReplyHandler(func(request govppmock.MessageDTO) (reply []byte, msgID uint16, prepared bool) {
		reqName, found := vppMock.GetMsgNameByID(request.MsgID)
		if !found {
			logrus.DefaultLogger().Error("Not existing req msg name for MsgID=", request.MsgID)
			return reply, 0, false
		}
		logrus.DefaultLogger().Debug("MockReplyHandler ", request.MsgID, " ", reqName)

		if reqName == "sw_interface_dump" {
			codec := &codec.MsgCodec{}
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

func addIfsIntoTheIndex(mapping ifaceidx.IfaceMetadataIndexRW) func(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	return func(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
		var cnt uint32 = 1
		if txn.LinuxDataChangeTxn == nil {
			// RESYNC not handled
			return nil
		}
		for _, op := range txn.LinuxDataChangeTxn.Ops {
			if op.Value != nil && strings.HasPrefix(op.Key, vpp_intf.Prefix) {
				name, isInterfaceKey := vpp_intf.ParseNameFromKey(op.Key)
				if !isInterfaceKey {
					return errors.New("failed to parse interface name from key")
				}
				mapping.Put(name, ifaceidx.IfaceMetadata{SwIfIndex: cnt})
				cnt++
			}
		}
		return nil
	}
}

func swIfIndexMock() ifaceidx.IfaceMetadataIndexRW {
	return ifaceidx.NewIfaceIndex(logrus.DefaultLogger(), "swIf")
}

func dhcpIndexMock() idxmap.NamedMappingRW {
	return idxmap_mem.NewNamedMapping(logrus.DefaultLogger(), "test-dhcp_indexes", nil)
}

// interfaceInLatestRevs returns interface of given name from the map of latest revisions
func interfaceInLatestRevs(latestRevs *syncbase.PrevRevisions, ifName string) *vpp_intf.Interface {
	for _, key := range latestRevs.ListKeys() {
		if strings.HasPrefix(key, vpp_intf.Prefix) && strings.HasSuffix(key, ifName) {
			intf := &vpp_intf.Interface{}
			_, value := latestRevs.Get(key)
			value.GetValue(intf)
			return intf
		}
	}
	return nil
}

// routesViaInLatestRevs returns routes pointing to privided next hop IP from the map of latest revisions
func routesViaInLatestRevs(latestRevs *syncbase.PrevRevisions, nexthopIP string) []*vpp_l3.StaticRoute {
	routes := make([]*vpp_l3.StaticRoute, 0)

	for _, key := range latestRevs.ListKeys() {
		if strings.HasPrefix(key, vpp_l3.RoutePrefix) && strings.HasSuffix(key, nexthopIP) {
			route := &vpp_l3.StaticRoute{}
			_, value := latestRevs.Get(key)
			value.GetValue(route)
			routes = append(routes, route)
		}
	}

	return routes
}

// nodeAddDelEvent simulates addition of a k8s node into a cluster
type nodeAddDelEvent struct {
	evType   datasync.Op
	nodeInfo *node.NodeInfo
}

func (e *nodeAddDelEvent) Done(error) {}

func (e nodeAddDelEvent) GetChangeType() datasync.Op {
	return e.evType
}

func (e nodeAddDelEvent) GetKey() string {
	return node.AllocatedIDsKeyPrefix
}

func (e nodeAddDelEvent) GetValue(value proto.Message) error {
	if e.evType == datasync.Put {
		if e.nodeInfo == nil {
			e.nodeInfo = &otherNodeInfo
		}
		v := value.(*node.NodeInfo)
		v.Id = e.nodeInfo.Id
		v.Name = e.nodeInfo.Name
		v.IpAddress = e.nodeInfo.IpAddress
		v.ManagementIpAddress = e.nodeInfo.ManagementIpAddress
	}
	return nil
}

func (e nodeAddDelEvent) GetPrevValue(prevValue proto.Message) (prevValueExist bool, err error) {
	if e.evType == datasync.Put {
		return false, nil
	}
	if e.nodeInfo == nil {
		e.nodeInfo = &otherNodeInfo
	}
	v := prevValue.(*node.NodeInfo)
	v.Id = e.nodeInfo.Id
	v.Name = e.nodeInfo.Name
	v.IpAddress = e.nodeInfo.IpAddress
	v.ManagementIpAddress = e.nodeInfo.ManagementIpAddress
	return true, nil
}

func (e nodeAddDelEvent) GetRevision() int64 {
	// return revision should be bigger than resync Rev in order to apply the change
	return 1
}
*/
