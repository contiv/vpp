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

package ipnet

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/go-errors/errors"
	. "github.com/onsi/gomega"

	"github.com/ligato/cn-infra/datasync/syncbase"
	idxmap_mem "github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	vpp_interfaces "github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/eventloop"
	. "github.com/contiv/vpp/mock/govpp"
	. "github.com/contiv/vpp/mock/ifplugin"
	"github.com/contiv/vpp/mock/localclient"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"
	"github.com/contiv/vpp/mock/vppagent/handler"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/ipam"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
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

	pod1Container = "<pod1-container-ID>"
	pod1PID       = 124
	pod1Ns        = "/proc/124/ns/net"
	pod1Name      = "pod1"
	pod1Namespace = "default"

	// node 2
	node2Name          = "node2"
	node2ID            = 2
	node2IP            = "10.10.10.200/24"
	node2MgmtIP        = "10.50.50.50"
	node2MgmtIPUpdated = "10.70.70.70"
)

var (
	keyPrefixes = []string{k8sPod.KeyPrefix()}

	hostIPs = []net.IP{net.ParseIP(hostIP1), net.ParseIP(hostIP2)}

	configTapVxlanDHCP = &config.Config{
		InterfaceConfig: config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		IPAMConfig: config.IPAMConfig{
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectDHCP:          true,
			VxlanCIDR:                     "192.168.30.0/24",
		},
	}

	noDHCPNodeConfig = config.NodeConfig{
		NodeName: node1,
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: Gbe8,
				UseDHCP:       false,
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: Gbe9,
					UseDHCP:       false,
				},
			},
		},
	}

	ipVer4Srv6NodeToNodeConfig = &config.Config{
		InterfaceConfig: config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
			TAPv2RxRingSize:     1024,
			TAPv2TxRingSize:     1024,
		},
		RoutingConfig: config.RoutingConfig{
			NodeToNodeTransport:   "srv6",
			UseSRv6ForServices:    true,
			RouteServiceCIDRToVPP: true,
		},
		IPAMConfig: config.IPAMConfig{
			NodeInterconnectCIDR:          "e10:f00d::/90",
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			VxlanCIDR:                     "192.168.30.0/24",
			ServiceCIDR:                   "10.96.0.0/12",
			SRv6: config.SRv6Config{
				ServicePolicyBSIDSubnetCIDR:       "8fff::/16",
				ServicePodLocalSIDSubnetCIDR:      "9300::/16",
				ServiceHostLocalSIDSubnetCIDR:     "9300::/16",
				ServiceNodeLocalSIDSubnetCIDR:     "9000::/16",
				NodeToNodePodLocalSIDSubnetCIDR:   "9501::/16",
				NodeToNodeHostLocalSIDSubnetCIDR:  "9500::/16",
				NodeToNodePodPolicySIDSubnetCIDR:  "8501::/16",
				NodeToNodeHostPolicySIDSubnetCIDR: "8500::/16",
			},
		},
		NodeConfig: []config.NodeConfig{
			noDHCPNodeConfig,
		},
	}

	ipVer6TunnelTestingContivConf = &config.Config{
		InterfaceConfig: config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		RoutingConfig: config.RoutingConfig{
			NodeToNodeTransport: "srv6",
			UseSRv6ForServices:  true,
		},
		IPAMConfig: config.IPAMConfig{
			NodeInterconnectDHCP:          false,
			NodeInterconnectCIDR:          "e10:f00d::/90",
			PodSubnetCIDR:                 "2001::/48",
			PodSubnetOneNodePrefixLen:     64,
			VPPHostSubnetCIDR:             "2002::/64",
			VPPHostSubnetOneNodePrefixLen: 112,
			VxlanCIDR:                     "2005::/112",
			ServiceCIDR:                   "2096::/110",
			SRv6: config.SRv6Config{
				ServicePolicyBSIDSubnetCIDR:       "8fff::/16",
				ServicePodLocalSIDSubnetCIDR:      "9300::/16",
				ServiceHostLocalSIDSubnetCIDR:     "9300::/16",
				ServiceNodeLocalSIDSubnetCIDR:     "9000::/16",
				NodeToNodePodLocalSIDSubnetCIDR:   "9501::/16",
				NodeToNodeHostLocalSIDSubnetCIDR:  "9500::/16",
				NodeToNodePodPolicySIDSubnetCIDR:  "8501::/16",
				NodeToNodeHostPolicySIDSubnetCIDR: "8500::/16",
			},
		},
		NodeConfig: []config.NodeConfig{
			noDHCPNodeConfig,
		},
	}

	/*
		configVethL2NoTCP = &contivconf.Config{
			RoutingConfig: contivconf.RoutingConfig{
				NodeToNodeTransport: contivconf.NoOverlayTransport,
			},
			IPAMConfig: contivconf.IPAMConfig{
				PodSubnetCIDR:                 "10.1.0.0/16",
				PodSubnetOneNodePrefixLen:     24,
				VPPHostSubnetCIDR:             "172.30.0.0/16",
				VPPHostSubnetOneNodePrefixLen: 24,
				NodeInterconnectCIDR:          "192.168.16.0/24",
				VxlanCIDR:                     "192.168.30.0/24",
			},
		}
	*/
)

type Fixture struct {
	Logger       logging.Logger
	EventLoop    *MockEventLoop
	Datasync     *MockDataSync
	ServiceLabel *MockServiceLabel
	NodeSync     *MockNodeSync
	PodManager   *MockPodManager
	GoVPP        *MockGoVPP
	VppIfPlugin  *MockVppIfPlugin
	TxnCount     int
}

type TunnelTestingFixture struct {
	*Fixture
	TxnTracker   *localclient.TxnTracker
	ContivConf   *contivconf.ContivConf
	Srv6Handler  *handler.SRv6MockHandler
	RouteHandler *handler.RouteMockHandler
	Ipam         *ipam.IPAM
}

func TestBasicStuff(t *testing.T) {
	RegisterTestingT(t)
	fixture := newCommonFixture("TestBasicStuff")

	// DHCP
	dhcpIndexes := idxmap_mem.NewNamedMapping(logrus.DefaultLogger(), "test-dhcp_indexes", nil)

	// DPDK interfaces
	dpdkIfaces := []string{Gbe8, Gbe9}

	// txnTracker
	txnTracker := localclient.NewTxnTracker(nil)

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

	// contivConf plugin
	contivConf := &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: configTapVxlanDHCP,
				DumpDPDKInterfacesClb: func() ([]string, error) {
					return dpdkIfaces, nil
				},
				RequestSTNInfoClb: requestSTNInfo("eth0", stnReply),
			},
		},
	}
	Expect(contivConf.Init()).To(BeNil())

	// IPAM real plugin
	ipam := &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: contivConf,
		},
	}
	Expect(ipam.Init()).To(BeNil())

	// ipNet plugin
	externalState := &externalState{
		test:      true,
		dhcpIndex: dhcpIndexes,
		hostLinkIPsDump: func() ([]net.IP, error) {
			return hostIPs, nil
		},
	}
	deps := Deps{
		PluginDeps: infra.PluginDeps{
			Log: logging.ForPlugin("ipnet"),
		},
		EventLoop:    fixture.EventLoop,
		ServiceLabel: fixture.ServiceLabel,
		ContivConf:   contivConf,
		IPAM:         ipam,
		NodeSync:     fixture.NodeSync,
		PodManager:   fixture.PodManager,
	}
	plugin := IPNet{
		Deps: deps,
		internalState: &internalState{
			pendingAddPodCustomIf: map[podmodel.ID]bool{},
		},
		externalState: externalState,
	}

	// resync against empty K8s state data
	emptyK8SResync(txnTracker, ipam, contivConf, fixture, &plugin)

	fmt.Println("Resync after DHCP event ----------------------------------")

	// simulate DHCP event
	dhcpIndexes.Put(Gbe8, &vpp_interfaces.DHCPLease{InterfaceName: Gbe8, HostIpAddress: Gbe8IP, RouterIpAddress: GwIPWithPrefix})
	Eventually(fixture.EventLoop.EventQueue).Should(HaveLen(1))
	event := fixture.EventLoop.EventQueue[0]
	nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change)
	Expect(isNodeIPv4Change).To(BeTrue())
	nodeIP := &net.IPNet{IP: nodeIPv4Change.NodeIP, Mask: nodeIPv4Change.NodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))
	gwIP := strings.Split(GwIPWithPrefix, "/")[0]
	Expect(nodeIPv4Change.DefaultGw.String()).To(Equal(gwIP))

	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(nodeIPv4Change, resyncEv.KubeState, resyncCount, txn)
	Expect(err).ShouldNot(HaveOccurred())
	err = commitTransaction(txn, true)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))
	nodeIP = &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, mgmt := addOtherNode(txnTracker, ipam, fixture, &plugin, node2ID, node2Name, node2MgmtIP)

	fmt.Println("Other node Mgmt IP update --------------------------------")

	// update another node
	mgmt = net.ParseIP(node2MgmtIPUpdated)
	node2Update := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2Update)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("update node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	fmt.Println("Add pod --------------------------------------------------")

	// add pod
	pod1ID := k8sPod.ID{Name: pod1Name, Namespace: pod1Namespace}
	addPodEvent := fixture.PodManager.AddPod(&podmanager.LocalPod{
		ID:               pod1ID,
		ContainerID:      pod1Container,
		NetworkNamespace: pod1Ns,
	})
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(addPodEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("configure IP connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	fmt.Println("Resync with non-empty K8s state --------------------------")

	// resync now with the IP from DHCP, new pod and the other node
	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).ShouldNot(HaveOccurred())
	err = commitTransaction(txn, true)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	// add pod entry into the mock DB
	fixture.Datasync.Put(k8sPod.Key(pod1Name, pod1Namespace), &k8sPod.Pod{
		Namespace: pod1Namespace,
		Name:      pod1Name,
		IpAddress: ipam.GetPodIP(pod1ID).IP.String(),
	})

	fmt.Println("Restart (without node IP) --------------------------------")

	// restart
	plugin = IPNet{
		Deps:          deps,
		internalState: &internalState{},
		externalState: externalState,
	}
	fixture.Datasync.RestartResyncCount()
	// resync
	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).ShouldNot(HaveOccurred())
	err = commitTransaction(txn, true)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))
	Expect(plugin.nodeIP).To(BeEmpty())
	Expect(plugin.nodeIPNet).To(BeNil())

	fmt.Println("Delete pod -----------------------------------------------")

	// delete pod
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(&podmanager.DeletePod{Pod: pod1ID}, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("un-configure IP connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	// remove the pod entry from mock podmanager and DB
	fixture.PodManager.DeletePod(pod1ID)
	fixture.Datasync.Delete(k8sPod.Key(pod1Name, pod1Namespace))

	fmt.Println("Delete node ----------------------------------------------")

	// delete the other node
	nodeUpdateEvent = fixture.NodeSync.DeleteNode(node2Name)
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(nodeUpdateEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("disconnect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	fmt.Println("Resync just before Close ---------------------------------")

	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).ShouldNot(HaveOccurred())
	err = commitTransaction(txn, true)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	fmt.Println("Close ----------------------------------------------------")

	shutdownEvent := &controller.Shutdown{}
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(shutdownEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	// nothing needs to be cleaned up for TAPs
	Expect(change).To(Equal(""))
	Expect(txn.Values).To(BeEmpty())
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))
}

func TestCreatePodTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreatePodTunnelIPv4PodConfig", 4)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedPodTunnelSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeletePodTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeletePodTunnelIPv4PodConfig", 4)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedPodTunnelSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestCreatePodTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreatePodTunnelIPv6", 6)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedPodTunnelSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeletePodTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeletePodTunnelIPv6", 6)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedPodTunnelSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestCreateHostTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreateHostTunnelIPv4PodConfig", 4)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedHostTunnelSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeleteHostTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeleteHostTunnelIPv4PodConfig", 4)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedHostTunnelSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestCreateHostTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreateHostTunnelIPv6", 6)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedHostTunnelSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeleteHostTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeleteHostTunnelIPv6", 6)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedHostTunnelSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestCreateIntermServiceTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreateIntermServiceTunnelIPv4PodConfig", 4)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedNodeToNodeSegmentSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeleteIntermServiceTunnelIPv4PodConfig(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeleteIntermServiceTunnelIPv4PodConfig", 4)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedNodeToNodeSegmentSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestCreateIntermServiceTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestCreateIntermServiceTunnelIPv6", 6)

	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedNodeToNodeSegmentSetup(nodeIP.IP, fixture, plugin)
	assertEgress(true, expectedTunnelSetup.egress, fixture.Srv6Handler)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)

	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)
	assertIngress(true, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func TestDeleteIntermServiceTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	fixture, plugin := newTunnelTestingFixture("TestDeleteIntermServiceTunnelIPv6", 6)
	nodeIP := emptyK8SResync(fixture.TxnTracker, fixture.Ipam, fixture.ContivConf, fixture.Fixture, plugin)
	expectedTunnelSetup := getExpectedNodeToNodeSegmentSetup(nodeIP.IP, fixture, plugin)
	addOtherNode(fixture.TxnTracker, fixture.Ipam, fixture.Fixture, plugin, node2ID, node2Name, node2MgmtIP)

	deleteOtherNode(fixture.TxnTracker, fixture.Fixture, plugin, node2Name)
	assertIngress(false, expectedTunnelSetup.ingress, fixture.Srv6Handler, fixture.RouteHandler)
}

func (fixture *TunnelTestingFixture) ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	err := fixture.Srv6Handler.ApplyTxn(txn, latestRevs)
	Expect(err).ShouldNot(HaveOccurred())
	err = fixture.RouteHandler.ApplyTxn(txn, latestRevs)
	Expect(err).ShouldNot(HaveOccurred())

	return nil
}

// newCommonFixture inits and composes together plugins needed for proper rendering unit testing
func newCommonFixture(testName string) *Fixture {
	fixture := &Fixture{}

	// Logger
	fixture.Logger = logrus.DefaultLogger()
	fixture.Logger.SetLevel(logging.DebugLevel)
	fixture.Logger.Debug(testName)

	// event loop
	fixture.EventLoop = &MockEventLoop{}

	// Datasync
	fixture.Datasync = NewMockDataSync()

	// mock service label
	fixture.ServiceLabel = NewMockServiceLabel()
	fixture.ServiceLabel.SetAgentLabel(node1)

	// nodesync
	fixture.NodeSync = NewMockNodeSync(node1)
	fixture.NodeSync.UpdateNode(&nodesync.Node{
		ID:   node1ID,
		Name: node1,
	})
	Expect(fixture.NodeSync.GetNodeID()).To(BeEquivalentTo(1))

	// podmanager
	fixture.PodManager = NewMockPodManager()

	// govpp
	fixture.GoVPP = NewMockGoVPP()

	// vpp iface plugin
	fixture.VppIfPlugin = NewMockVppPlugin()

	return fixture
}

func newTunnelTestingFixture(testName string, ipVer uint8) (*TunnelTestingFixture, *IPNet) {

	fixture := newCommonFixture(testName)

	data := &TunnelTestingFixture{
		Fixture:      fixture,
		Srv6Handler:  handler.NewSRv6Mock(logrus.DefaultLogger()),
		RouteHandler: handler.NewRouteMock(logrus.DefaultLogger()),
	}
	data.TxnTracker = localclient.NewTxnTracker(data.ApplyTxn)

	// contivConf plugin
	data.ContivConf = &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: ipVer4Srv6NodeToNodeConfig,
			},
		},
	}
	if ipVer == 4 {
		data.ContivConf.UnitTestDeps = &contivconf.UnitTestDeps{
			Config: ipVer4Srv6NodeToNodeConfig,
		}
	} else {
		data.ContivConf.UnitTestDeps = &contivconf.UnitTestDeps{
			Config: ipVer6TunnelTestingContivConf,
		}
	}

	Expect(data.ContivConf.Init()).To(BeNil())
	resyncEv, _ := data.Datasync.ResyncEvent()
	Expect(data.ContivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// IPAM real plugin
	data.Ipam = &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: data.ContivConf,
		},
	}
	Expect(data.Ipam.Init()).ShouldNot(HaveOccurred())
	Expect(data.Ipam.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// ipNet plugin
	deps := Deps{
		PluginDeps: infra.PluginDeps{
			Log: logging.ForPlugin("ipnet"),
		},
		EventLoop:    fixture.EventLoop,
		ServiceLabel: fixture.ServiceLabel,
		ContivConf:   data.ContivConf,
		IPAM:         data.Ipam,
		NodeSync:     fixture.NodeSync,
		PodManager:   fixture.PodManager,
		GoVPP:        fixture.GoVPP,
		VPPIfPlugin:  fixture.VppIfPlugin,
	}
	ipNet := &IPNet{
		Deps: deps,
		internalState: &internalState{
			pendingAddPodCustomIf: map[podmodel.ID]bool{},
		},
	}
	Expect(ipNet.Init()).To(BeNil())

	ipNet.externalState = &externalState{
		test: true,
		hostLinkIPsDump: func() ([]net.IP, error) {
			return hostIPs, nil
		},
	}

	data.Datasync.RestartResyncCount()
	return data, ipNet
}

func addOtherNode(txnTracker *localclient.TxnTracker, ipam *ipam.IPAM, fixture *Fixture, plugin *IPNet, otherNodeID uint32, otherNodeName string, otherNodeMgmtIP string) (addr net.IP, network *net.IPNet, mgmt net.IP) {
	fmt.Println("Add another node -----------------------------------------")

	addr, network, _ = ipam.NodeIPAddress(otherNodeID)
	mgmt = net.ParseIP(otherNodeMgmtIP)
	node2 := &nodesync.Node{
		Name:            otherNodeName,
		ID:              otherNodeID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn := txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	return
}

func emptyK8SResync(txnTracker *localclient.TxnTracker, ipam *ipam.IPAM, contivConf *contivconf.ContivConf, fixture *Fixture, plugin *IPNet) *net.IPNet {
	fmt.Println("Resync against empty K8s state ---------------------------")

	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).ShouldNot(HaveOccurred())
	err = commitTransaction(txn, true)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))

	if plugin.nodeIP == nil {
		Expect(plugin.nodeIP).To(BeEmpty())
		Expect(plugin.nodeIPNet).To(BeNil())
		return nil
	}

	ip, ipNet, _ := ipam.NodeIPAddress(node1ID)
	expectedIP := &net.IPNet{IP: ip, Mask: ipNet.Mask}
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(expectedIP.String()))

	return nodeIP
}

func deleteOtherNode(txnTracker *localclient.TxnTracker, fixture *Fixture, plugin *IPNet, nodeName string) {
	fmt.Println("Delete node ----------------------------------------------")

	nodeUpdateEvent := fixture.NodeSync.DeleteNode(nodeName)
	txn := txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(change).To(Equal("disconnect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).ShouldNot(HaveOccurred())
	fixture.TxnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(fixture.TxnCount))
}

type Ingress struct {
	policy    *vpp_srv6.Policy
	steerings []*vpp_srv6.Steering
	route     *vpp_l3.Route
}

type TunnelSetup struct {
	ingress *Ingress
	egress  *vpp_srv6.LocalSID
}

func assertEgress(exists bool, egress *vpp_srv6.LocalSID, srv6Handler *handler.SRv6MockHandler) {
	if egress != nil {
		if exists {
			Expect(srv6Handler.LocalSids).To(ContainElement(egress))
		} else {
			Expect(srv6Handler.LocalSids).ToNot(ContainElement(egress))
		}
	}
}

func assertIngress(exists bool, ingress *Ingress, srv6Handler *handler.SRv6MockHandler, routeHandler *handler.RouteMockHandler) {
	if ingress.policy != nil {
		Expect(hasPolicy(ingress.policy, srv6Handler.Policies)).To(Equal(exists))
	}

	if ingress.route != nil {
		if exists {
			Expect(routeHandler.Route).To(ContainElement(ingress.route))
		} else {
			Expect(routeHandler.Route).ToNot(ContainElement(ingress.route))
		}
	}
	for _, steering := range ingress.steerings {
		if exists {
			Expect(srv6Handler.Steerings).To(ContainElement(steering))
		} else {
			Expect(srv6Handler.Steerings).ToNot(ContainElement(steering))
		}
	}
}

func getExpectedPodTunnelSetup(nodeIP net.IP, fixture *TunnelTestingFixture, plugin *IPNet) TunnelSetup {
	expectedSetup := TunnelSetup{
		ingress: &Ingress{},
	}

	// policy
	node2IP, _, err := fixture.Ipam.NodeIPAddress(node2ID)
	Expect(err).ShouldNot(HaveOccurred())

	sid := fixture.Ipam.SidForNodeToNodePodLocalsid(node2IP)
	bsid := fixture.Ipam.BsidForNodeToNodePodPolicy(node2IP)
	expectedSetup.ingress.policy = &vpp_srv6.Policy{
		Bsid:              bsid.String(),
		InstallationVrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
		SrhEncapsulation:  true,
		SprayBehaviour:    false,
		SegmentLists: []*vpp_srv6.Policy_SegmentList{
			{
				Weight: 1,
				Segments: []string{
					sid.String(),
				},
			},
		},
	}

	// steering
	podNetwork, err := fixture.Ipam.PodSubnetOtherNode(node2ID)
	Expect(err).ShouldNot(HaveOccurred())
	expectedSetup.ingress.steerings = []*vpp_srv6.Steering{
		getSteering(podNetwork, bsid, "lookupInPodVRF", fixture.ContivConf.GetRoutingConfig().MainVRFID),
	}

	//route
	_, ipNet, err := net.ParseCIDR(sid.To16().String() + "/128")
	Expect(err).ShouldNot(HaveOccurred())
	expectedSetup.ingress.route = &vpp_l3.Route{
		DstNetwork:  ipNet.String(),
		NextHopAddr: node2IP.String(),
		VrfId:       fixture.ContivConf.GetRoutingConfig().MainVRFID,
	}

	// egress
	expectedSetup.egress = &vpp_srv6.LocalSID{
		Sid:               fixture.Ipam.SidForNodeToNodePodLocalsid(nodeIP).String(),
		InstallationVrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
	}
	if fixture.ContivConf.GetIPAMConfig().UseIPv6 {
		expectedSetup.egress.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT6{
			EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
				VrfId: fixture.ContivConf.GetRoutingConfig().PodVRFID,
			},
		}
	} else {
		expectedSetup.egress.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT4{
			EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
				VrfId: fixture.ContivConf.GetRoutingConfig().PodVRFID,
			},
		}
	}

	return expectedSetup
}

func getExpectedHostTunnelSetup(nodeIP net.IP, fixture *TunnelTestingFixture, plugin *IPNet) TunnelSetup {
	expectedSetup := TunnelSetup{
		ingress: &Ingress{},
	}

	node2IP, _, err := fixture.Ipam.NodeIPAddress(node2ID)
	Expect(err).ShouldNot(HaveOccurred())

	// policy
	sid := fixture.Ipam.SidForNodeToNodeHostLocalsid(node2IP)
	bsid := fixture.Ipam.BsidForNodeToNodeHostPolicy(node2IP)
	expectedSetup.ingress.policy = &vpp_srv6.Policy{
		Bsid:              bsid.String(),
		InstallationVrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
		SrhEncapsulation:  true,
		SprayBehaviour:    false,
		SegmentLists: []*vpp_srv6.Policy_SegmentList{
			{
				Weight: 1,
				Segments: []string{
					sid.String(),
				},
			},
		},
	}

	// steerings
	hostNetwork, err := fixture.Ipam.HostInterconnectSubnetOtherNode(node2ID)
	mgmtIP := net.ParseIP(node2MgmtIP)
	_, mgmtNetwork, err := net.ParseCIDR(mgmtIP.String() + fullPrefixForAF(mgmtIP))
	expectedSetup.ingress.steerings = []*vpp_srv6.Steering{
		getSteering(hostNetwork, bsid, "lookupInMainVRF", fixture.ContivConf.GetRoutingConfig().MainVRFID),
		getSteering(mgmtNetwork, bsid, "managementIP-"+node2MgmtIP, fixture.ContivConf.GetRoutingConfig().MainVRFID),
	}

	// route
	_, ipNet, err := net.ParseCIDR(sid.To16().String() + "/128")
	Expect(err).ShouldNot(HaveOccurred())
	expectedSetup.ingress.route = &vpp_l3.Route{
		DstNetwork:  ipNet.String(),
		NextHopAddr: node2IP.String(),
		VrfId:       fixture.ContivConf.GetRoutingConfig().MainVRFID,
	}

	// egress
	expectedSetup.egress = &vpp_srv6.LocalSID{
		Sid:               fixture.Ipam.SidForNodeToNodeHostLocalsid(nodeIP).String(),
		InstallationVrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
	}
	if fixture.ContivConf.GetIPAMConfig().UseIPv6 {
		expectedSetup.egress.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT6{
			EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
				VrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
			},
		}
	} else {
		expectedSetup.egress.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT4{
			EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
				VrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
			},
		}
	}

	return expectedSetup
}

func getExpectedNodeToNodeSegmentSetup(nodeIP net.IP, fixture *TunnelTestingFixture, plugin *IPNet) TunnelSetup {
	expectedSetup := TunnelSetup{
		ingress: &Ingress{},
	}

	node2IP, _, err := fixture.Ipam.NodeIPAddress(node2ID)
	Expect(err).ShouldNot(HaveOccurred())
	sid := fixture.Ipam.SidForServiceNodeLocalsid(node2IP)
	_, ipNet, err := net.ParseCIDR(sid.To16().String() + "/128")
	Expect(err).ShouldNot(HaveOccurred())

	expectedSetup.ingress = &Ingress{
		route: &vpp_l3.Route{
			DstNetwork:  ipNet.String(),
			NextHopAddr: node2IP.String(),
			VrfId:       fixture.ContivConf.GetRoutingConfig().MainVRFID,
		},
	}
	expectedSetup.egress = &vpp_srv6.LocalSID{
		Sid:               fixture.Ipam.SidForServiceNodeLocalsid(nodeIP).String(),
		InstallationVrfId: fixture.ContivConf.GetRoutingConfig().MainVRFID,
		EndFunction:       &vpp_srv6.LocalSID_BaseEndFunction{BaseEndFunction: &vpp_srv6.LocalSID_End{}},
	}

	return expectedSetup
}

func hasPolicy(policy *vpp_srv6.Policy, policies map[string]*vpp_srv6.Policy) bool {

	for _, curPolicy := range policies {
		match := true
		match = match && curPolicy.Bsid == policy.Bsid // order of segments in SegmentList flip sometimes = unstable test -> compare by attributes
		match = match && curPolicy.SprayBehaviour == policy.SprayBehaviour
		match = match && curPolicy.SrhEncapsulation == policy.SrhEncapsulation
		match = match && curPolicy.InstallationVrfId == policy.InstallationVrfId

		match = match && len(curPolicy.SegmentLists) == len(policy.SegmentLists)
		for _, sl := range policy.SegmentLists {
			hasSl := false
			for _, currentSl := range curPolicy.SegmentLists {
				weightEqual := sl.Weight == currentSl.Weight
				segmentsEqual := reflect.DeepEqual(sl.Segments, currentSl.Segments)
				hasSl = hasSl || (weightEqual && segmentsEqual)
			}
			match = match && hasSl
		}

		if match {
			return true
		}
	}
	return false
}

func getSteering(networkToSteer *net.IPNet, bsid net.IP, nameSuffix string, mainVrfID uint32) *vpp_srv6.Steering {
	return &vpp_srv6.Steering{
		Name: fmt.Sprintf("forNodeToNodeTunneling-usingPolicyWithBSID-%v-and-%v", bsid.String(), nameSuffix),
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				PrefixAddress:     networkToSteer.String(),
				InstallationVrfId: mainVrfID,
			},
		},
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
	}
}

func commitTransaction(txn controller.Transaction, isResync bool) error {
	ctx := context.Background()
	if isResync {
		ctx = scheduler.WithResync(ctx, scheduler.FullResync, true)
	}
	_, err := txn.Commit(ctx)
	return err
}

// requestSTNInfo is a factory for contivconf.RequestSTNInfoClb
func requestSTNInfo(expInterface string, reply *stn_grpc.STNReply) contivconf.RequestSTNInfoClb {
	return func(ifName string) (*stn_grpc.STNReply, error) {
		if ifName != expInterface {
			return nil, errors.New("not the expected stolen interface")
		}
		return reply, nil
	}
}
