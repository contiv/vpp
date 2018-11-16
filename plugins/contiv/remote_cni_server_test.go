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
	"strconv"
	"strings"
	"testing"

	"github.com/go-errors/errors"
	. "github.com/onsi/gomega"

	idxmap_mem "github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging/logrus"

	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/dockerclient"
	"github.com/contiv/vpp/mock/localclient"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	// node 1
	node1   = "node1"
	node1ID = 1

	Gbe8           = "GigabitEthernet0/8/0"
	Gbe8IP         = "10.10.10.100/24"
	Gbe9           = "GigabitEthernet0/9/0"
	Gbe9IP         = "10.10.20.5/24"
	GwIP           = "10.10.10.1"
	GwIPWithPrefix = "10.10.10.1/24"

	hostIP1 = "10.3.1.10"
	hostIP2 = "10.0.2.15"

	pod1Container        = "<pod1-container-ID>"
	pod1ContainerUpdated = "<pod1-container-ID-updated>"
	pod1PID              = 124
	pod1Ns               = "/proc/124/ns/net"
	pod1Name             = "pod1"
	pod1Namespace        = "default"

	// node 2
	node2Name          = "node2"
	node2ID            = 2
	node2IP            = "10.10.10.200/24"
	node2MgmtIP        = "10.50.50.50"
	node2MgmtIPUpdated = "10.70.70.70"
)

var (
	keyPrefixes = []string{node.AllocatedIDsKeyPrefix, k8sPod.KeyPrefix()}

	hostIPs = []net.IP{net.ParseIP(hostIP1), net.ParseIP(hostIP2)}

	nodeDHCPConfig = &NodeConfig{
		NodeName: node1,
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			StealInterface: "eth0",
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: Gbe8,
				UseDHCP:       true,
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: Gbe9,
					IP:            Gbe9IP,
				},
			},
		},
	}

	configTapVxlanDHCP = &Config{
		UseTAPInterfaces:    true,
		TAPInterfaceVersion: 2,
		IPAMConfig: ipam.Config{
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			PodVPPSubnetCIDR:              "10.2.1.0/24",
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectDHCP:          true,
			VxlanCIDR:                     "192.168.30.0/24",
		},
	}

	/*
		configVethL2NoTCP = &Config{
			UseL2Interconnect: true,
			IPAMConfig: ipam.Config{
				PodSubnetCIDR:                 "10.1.0.0/16",
				PodSubnetOneNodePrefixLen:     24,
				PodVPPSubnetCIDR:              "10.2.1.0/24",
				VPPHostSubnetCIDR:             "172.30.0.0/16",
				VPPHostSubnetOneNodePrefixLen: 24,
				NodeInterconnectCIDR:          "192.168.16.0/24",
				VxlanCIDR:                     "192.168.30.0/24",
			},
		}
	*/
)

func TestBasicStuff(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	// DHCP
	dhcpIndexes := idxmap_mem.NewNamedMapping(logrus.DefaultLogger(), "test-dhcp_indexes", nil)

	// NICs
	physicalIfaces := map[uint32]string{
		1: Gbe8,
		2: Gbe9,
	}

	// STN
	stnReply := &stn_grpc.STNReply{
		IpAddresses: []string{Gbe8IP},
		Routes: []*stn_grpc.STNReply_Route{
			{
				DestinationSubnet: "20.20.20.0/24",
				NextHopIp:         "10.10.10.1",
			},
		},
	}

	// Docker
	dockerClient := NewMockDockerClient()
	dockerClient.Connect()

	// datasync
	datasync := NewMockDataSync()

	// transactions
	txnTracker := localclient.NewTxnTracker(nil)

	// Remote CNI Server init
	args := &remoteCNIserverArgs{
		Logger:     logrus.DefaultLogger(),
		nodeID:     node1ID,
		txnFactory: txnTracker.NewControllerTxn,
		physicalIfsDump: func() (map[uint32]string, error) {
			return physicalIfaces, nil
		},
		getStolenInterfaceInfo: stolenInterfaceInfo("eth0", stnReply),
		hostLinkIPsDump: func() ([]net.IP, error) {
			return hostIPs, nil
		},
		dockerClient:                dockerClient,
		govppChan:                   nil,
		dhcpIndex:                   dhcpIndexes,
		agentLabel:                  "node1",
		nodeConfig:                  nodeDHCPConfig,
		config:                      configTapVxlanDHCP,
		nodeInterconnectExcludedIPs: []net.IP{net.ParseIP(GwIP)},
		http:                        nil,
	}

	server, err := newRemoteCNIServer(args)
	server.test = true
	Expect(err).To(BeNil())

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv := datasync.Resync(keyPrefixes...)
	err = server.Resync(ParseResyncEvent(resyncEv, nil))
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// simulate DHCP event
	dhcpIndexes.Put(Gbe8, &interfaces.DHCPLease{InterfaceName: Gbe8, HostIpAddress: Gbe8IP, RouterIpAddress: GwIPWithPrefix})

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	node2 := &node.NodeInfo{
		Name:                node2Name,
		Id:                  node2ID,
		IpAddress:           node2IP,
		ManagementIpAddress: node2MgmtIP,
	}
	dataChange := datasync.Put(nodeIDKey(node2ID), node2)
	err = server.Update(dataChange.GetChanges()[0])
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Other node Mgmt IP update --------------------------------")

	// add another node
	node2Update := &node.NodeInfo{
		Name:                node2Name,
		Id:                  node2ID,
		IpAddress:           node2IP,
		ManagementIpAddress: node2MgmtIPUpdated,
	}
	dataChange = datasync.Put(nodeIDKey(node2ID), node2Update)
	err = server.Update(dataChange.GetChanges()[0])
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Add pod --------------------------------------------------")

	// add pod
	cniReq := &cni.CNIRequest{
		ContainerId:      pod1Container,
		NetworkNamespace: pod1Ns,
		InterfaceName:    "eth0",
		ExtraArguments:   "K8S_POD_NAMESPACE=" + pod1Namespace + ";K8S_POD_NAME=" + pod1Name,
	}
	pod1ID := k8sPod.ID{Name: pod1Name, Namespace: pod1Namespace}
	reply, err := server.Add(context.Background(), cniReq)
	Expect(err).To(BeNil())
	txnCount++
	Expect(reply).ToNot(BeNil())
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Add pod (updated, prev. is obsolete) ---------------------")

	// add pod
	cniReq.ContainerId = pod1ContainerUpdated
	reply, err = server.Add(context.Background(), cniReq)
	Expect(err).To(BeNil())
	txnCount += 2 // also removing obsolete config
	Expect(reply).ToNot(BeNil())
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// register the new pod with the mocks
	pod1IP := podIPFromCNIReply(reply)
	Expect(pod1IP).ToNot(BeNil())
	dockerClient.AddPod(pod1ID, pod1ContainerUpdated, pod1PID)
	dataChange = datasync.Put(k8sPod.Key(pod1Name, pod1Namespace), &k8sPod.Pod{
		Namespace: pod1Namespace,
		Name:      pod1Name,
		IpAddress: pod1IP.String(),
	})
	err = server.Update(dataChange.GetChanges()[0]) // NOOP
	Expect(err).To(BeNil())
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync with non-empty K8s state --------------------------")

	// resync now with the IP from DHCP, new pod and the other node
	resyncEv = datasync.Resync(keyPrefixes...)
	err = server.Resync(ParseResyncEvent(resyncEv, nil))
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Restart (without node IP) --------------------------------")

	// restart
	server, err = newRemoteCNIServer(args)
	server.test = true
	Expect(err).To(BeNil())
	// resync
	resyncEv = datasync.Resync(keyPrefixes...)
	err = server.Resync(ParseResyncEvent(resyncEv, nil))
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Delete pod -----------------------------------------------")

	// delete pod
	reply, err = server.Delete(context.Background(), cniReq)
	Expect(err).To(BeNil())
	Expect(reply).ToNot(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// un-register the pod from the mocks
	dockerClient.DelPod(pod1ID)
	dataChange = datasync.Delete(k8sPod.Key(pod1Name, pod1Namespace))
	err = server.Update(dataChange.GetChanges()[0]) // NOOP
	Expect(err).To(BeNil())
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Delete node ----------------------------------------------")

	// delete the other node
	dataChange = datasync.Delete(nodeIDKey(node2ID))
	err = server.Update(dataChange.GetChanges()[0])
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync just before Close ---------------------------------")

	resyncEv = datasync.Resync(keyPrefixes...)
	err = server.Resync(ParseResyncEvent(resyncEv, nil))
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Close ----------------------------------------------------")

	server.Close()
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
}

// stolenInterfaceInfo is a factory for StolenInterfaceInfoClb
func stolenInterfaceInfo(expInterface string, reply *stn_grpc.STNReply) StolenInterfaceInfoClb {
	return func(ifName string) (*stn_grpc.STNReply, error) {
		if ifName != expInterface {
			return nil, errors.New("not the expected stolen interface")
		}
		return reply, nil
	}
}

func nodeIDKey(index int) string {
	str := strconv.FormatUint(uint64(index), 10)
	return node.AllocatedIDsKeyPrefix + str
}

func podIPFromCNIReply(reply *cni.CNIReply) net.IP {
	Expect(reply).ToNot(BeNil())
	Expect(reply.Interfaces).To(HaveLen(1))
	Expect(reply.Interfaces[0].IpAddresses).To(HaveLen(1))
	addr := strings.Split(reply.Interfaces[0].IpAddresses[0].Address, "/")[0]
	return net.ParseIP(addr)
}

/* Old UTs for inspiration:

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
	Expect(err).To(BeNil())

	return server, txns, configuredContainers, vppMockConn
}

func TestHwAddress(t *testing.T) {
	RegisterTestingT(t)

	server, _, _, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	var addresses []string

	checkUniqueness := func(existing []string, nodeID uint32) (updated []string) {
		a := server.hwAddrForVXLAN(nodeID)
		fmt.Println(a)
		Expect(existing).NotTo(ContainElement(a))
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
	RegisterTestingT(t)

	server, txns, configuredContainers, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	// pretend that connectivity is configured to unblock CNI requests
	server.vswitchConnectivityConfigured = true

	// CNI Add
	reply, err := server.Add(context.Background(), &req)

	Expect(err).To(BeNil())
	Expect(reply).NotTo(BeNil())

	Expect(len(txns.PendingTxns)).To(BeEquivalentTo(0))
	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	res := configuredContainers.LookupPodName(podName)
	Expect(len(res)).To(BeEquivalentTo(1))
	Expect(res).To(ContainElement(containerID))

	txns.Clear()

	// CNI Delete
	reply, err = server.Delete(context.Background(), &req)
	Expect(err).To(BeNil())
	Expect(reply).NotTo(BeNil())
}

func TestConfigureVswitchDHCP(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, &nodeDHCPConfig, nodeDHCPConfig.MainVPPInterface.InterfaceName)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// node IP is empty since DHCP reply have not been received
	Expect(server.GetNodeIP()).To(BeEmpty())
	// host interconnect IF must be configured
	Expect(server.GetHostInterconnectIfName()).ToNot(BeEmpty())

	server.close()
	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(2))
}

func TestAddDelTap(t *testing.T) {
	RegisterTestingT(t)

	server, txns, configuredContainers, conn := setupTestCNIServer(&configTapVxlanTCP, &nodeConfig)
	defer conn.Disconnect()

	// pretend that connectivity is configured to unblock CNI requests
	server.vswitchConnectivityConfigured = true

	// CNI Add
	reply, err := server.Add(context.Background(), &req)

	Expect(err).To(BeNil())
	Expect(reply).NotTo(BeNil())

	Expect(len(txns.PendingTxns)).To(BeEquivalentTo(0))
	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	res := configuredContainers.LookupPodName(podName)
	Expect(len(res)).To(BeEquivalentTo(1))
	Expect(res).To(ContainElement(containerID))

	txns.Clear()

	// CNI Delete
	reply, err = server.Delete(context.Background(), &req)
	Expect(err).To(BeNil())
	Expect(reply).NotTo(BeNil())
}

func TestConfigureVswitchVeth(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configVethL2NoTCP, &nodeConfig, nodeConfig.OtherVPPInterfaces[0].InterfaceName)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// check physical interface name
	physIf := server.GetMainPhysicalIfName()
	Expect(physIf).To(BeEquivalentTo(nodeConfig.MainVPPInterface.InterfaceName))
	// node IP must not be empty
	nodeIP, nodeNet := server.GetNodeIP()
	Expect(nodeIP).ToNot(BeEmpty())
	Expect(nodeNet).ToNot(BeNil())
	// host interconnect IF must be configured
	Expect(server.GetHostInterconnectIfName()).ToNot(BeEmpty())
	// using L2 interconnect - no VXLAN IF name
	Expect(server.GetVxlanBVIIfName()).To(BeEmpty())
	// gateway is configured
	defaultIfName, defaultIfIP := server.GetDefaultInterface()
	Expect(defaultIfIP.String()).To(Equal("192.168.1.1"))
	Expect(defaultIfName).To(BeEquivalentTo(nodeConfig.MainVPPInterface.InterfaceName))
	// with extra physical interfaces
	Expect(server.GetOtherPhysicalIfNames()).To(Equal([]string{"GigabitEthernet0/0/0/10"}))

	server.close()
	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(2))
}

func TestConfigureVswitchTap(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(1))
	// TODO add asserts for txns(one linux plugin txn and one default plugins txn) / currently applied config

	// node IP must not be empty
	nodeIP, nodeNet := server.GetNodeIP()
	Expect(nodeIP).ToNot(BeEmpty())
	Expect(nodeNet).ToNot(BeNil())
	// host interconnect IF must be configured
	Expect(server.GetHostInterconnectIfName()).ToNot(BeEmpty())
	// using VXLANs - VXLAN IF name must not be empty
	Expect(server.GetVxlanBVIIfName()).ToNot(BeEmpty())

	server.close()
	Expect(len(txns.CommittedTxns)).To(BeEquivalentTo(2))
}

func TestNodeAddDelL2(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configVethL2NoTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put})
	Expect(err).To(BeNil())

	// check that the VXLAN interface does not exist
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", otherNodeInfo.Id))
	Expect(vxlanIf).To(BeNil())

	// check routes to the other node pointing to node IP
	nexthopIP := ipNetToAddress(otherNodeInfo.IpAddress)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP)
	Expect(len(routes)).To(BeEquivalentTo(3))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete})
	Expect(err).To(BeNil())
}

func TestNodeAddDelVXLAN(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put})
	Expect(err).To(BeNil())

	// check that the VXLAN tunnel config has been properly added
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", otherNodeInfo.Id))
	Expect(vxlanIf).ToNot(BeNil())
	Expect(otherNodeInfo.IpAddress).To(ContainSubstring(vxlanIf.GetVxlan().DstAddress))

	// check routes to the other node pointing to VXLAN IP
	nexthopIP, _ := server.ipam.VxlanIPAddress(otherNodeInfo.Id)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP.String())
	Expect(len(routes)).To(BeEquivalentTo(3))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete})
	Expect(err).To(BeNil())
}

func TestNodeAddDelNodeWithMultipleMgmtAddresses(t *testing.T) {
	RegisterTestingT(t)

	server, txns, _, conn := setupTestCNIServer(&configTapVxlanTCP, nil)
	defer conn.Disconnect()

	// exec resync to configure vswitch
	err := server.resync()
	Expect(err).To(BeNil())

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Put, nodeInfo: &nodeWith2mgmtIP})
	Expect(err).To(BeNil())

	// check that the VXLAN tunnel config has been properly added
	vxlanIf := interfaceInLatestRevs(txns.LatestRevisions, fmt.Sprintf("vxlan%d", nodeWith2mgmtIP.Id))
	Expect(vxlanIf).ToNot(BeNil())
	Expect(nodeWith2mgmtIP.IpAddress).To(ContainSubstring(vxlanIf.GetVxlan().DstAddress))

	// check routes to the other node pointing to VXLAN IP
	nexthopIP, _ := server.ipam.VxlanIPAddress(nodeWith2mgmtIP.Id)
	routes := routesViaInLatestRevs(txns.LatestRevisions, nexthopIP.String())
	Expect(len(routes)).To(BeEquivalentTo(4))

	err = server.nodeChangePropagateEvent(&nodeAddDelEvent{evType: datasync.Delete, nodeInfo: &nodeWith2mgmtIP})
	Expect(err).To(BeNil())
}

func TestVeth1NameFromRequest(t *testing.T) {
	RegisterTestingT(t)

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
	Expect(err).To(BeNil())

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	Expect(hostIfName).To(BeEquivalentTo("eth0"))
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
	Expect(err).To(BeNil())
	return server, vppMockConn, dhcpIndex
}

func TestWithDHCPDelayedNotif(t *testing.T) {
	RegisterTestingT(t)

	var server *remoteCNIserver

	server, conn, dhcpIndex := initServerForDHCPTesting()
	defer conn.Disconnect()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := server.resync()
		Expect(err).To(BeNil())
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
	Eventually(getIP).Should(BeEquivalentTo("1.1.1.1"))
}

func TestWithDHCPQuickNotif(t *testing.T) {
	RegisterTestingT(t)

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
		Expect(err).To(BeNil())
		wg.Done()
	}()
	wg.Wait()
	getIP := func() string {
		ip, _ := server.GetNodeIP()
		return ip.String()
	}
	Eventually(getIP).Should(BeEquivalentTo("1.1.1.1"))
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
