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
	"strings"
	"testing"

	"github.com/go-errors/errors"
	. "github.com/onsi/gomega"

	idxmap_mem "github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/eventloop"
	"github.com/contiv/vpp/mock/localclient"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/ipam"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
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

	nodeDHCPConfig = &contivconf.NodeConfig{
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

	configTapVxlanDHCP = &contivconf.Config{
		InterfaceConfig: contivconf.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		IPAMConfig: contivconf.IPAMConfigForJSON{
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectDHCP:          true,
			VxlanCIDR:                     "192.168.30.0/24",
		},
	}

	/*
		configVethL2NoTCP = &contivconf.Config{
			RoutingConfig: contivconf.RoutingConfig{
				UseNoOverlay: true,
			},
			IPAMConfig: contivconf.IPAMConfigForJSON{
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

	// service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(node1)

	// DHCP
	dhcpIndexes := idxmap_mem.NewNamedMapping(logrus.DefaultLogger(), "test-dhcp_indexes", nil)

	// DPDK interfaces
	dpdkIfaces := []string{Gbe8, Gbe9}

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

	// event loop
	eventLoop := &MockEventLoop{}

	// datasync
	datasync := NewMockDataSync()

	// nodesync
	nodeSync := NewMockNodeSync(node1)
	nodeSync.UpdateNode(&nodesync.Node{
		ID:   node1ID,
		Name: node1,
	})

	// podmanager
	podManager := NewMockPodManager()

	// transactions
	txnTracker := localclient.NewTxnTracker(nil)

	// config
	config := configTapVxlanDHCP

	// contivConf plugin
	contivConfPlugin := &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: serviceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: config,
				DumpDPDKInterfacesClb: func() ([]string, error) {
					return dpdkIfaces, nil
				},
				RequestSTNInfoClb: requestSTNInfo("eth0", stnReply),
			},
		},
	}
	Expect(contivConfPlugin.Init()).To(BeNil())

	// IPAM plugin
	ipamPlugin := &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("ipam"),
			},
			NodeSync:   nodeSync,
			ContivConf: contivConfPlugin,
		},
	}
	Expect(ipamPlugin.Init()).To(BeNil())

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
		EventLoop:    eventLoop,
		ServiceLabel: serviceLabel,
		ContivConf:   contivConfPlugin,
		IPAM:         ipamPlugin,
		NodeSync:     nodeSync,
		PodManager:   podManager,
	}
	plugin := IPNet{
		Deps:          deps,
		internalState: &internalState{},
		externalState: externalState,
	}

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConfPlugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipamPlugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	Expect(plugin.nodeIP).To(BeEmpty())
	Expect(plugin.nodeIPNet).To(BeNil())

	fmt.Println("Resync after DHCP event ----------------------------------")

	// simulate DHCP event
	dhcpIndexes.Put(Gbe8, &vpp_interfaces.DHCPLease{InterfaceName: Gbe8, HostIpAddress: Gbe8IP, RouterIpAddress: GwIPWithPrefix})
	Eventually(eventLoop.EventQueue).Should(HaveLen(1))
	event := eventLoop.EventQueue[0]
	nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change)
	Expect(isNodeIPv4Change).To(BeTrue())
	nodeIP := &net.IPNet{IP: nodeIPv4Change.NodeIP, Mask: nodeIPv4Change.NodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))
	gwIP := strings.Split(GwIPWithPrefix, "/")[0]
	Expect(nodeIPv4Change.DefaultGw.String()).To(Equal(gwIP))

	resyncEv, resyncCount = datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(nodeIPv4Change, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP = &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := net.ParseCIDR(node2IP)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := nodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Other node Mgmt IP update --------------------------------")

	// update another node
	mgmt = net.ParseIP(node2MgmtIPUpdated)
	node2Update := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent = nodeSync.UpdateNode(node2Update)
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("update node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Add pod --------------------------------------------------")

	// add pod
	pod1ID := k8sPod.ID{Name: pod1Name, Namespace: pod1Namespace}
	addPodEvent := podManager.AddPod(&podmanager.LocalPod{
		ID:               pod1ID,
		ContainerID:      pod1Container,
		NetworkNamespace: pod1Ns,
	})
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(addPodEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("configure IP connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync with non-empty K8s state --------------------------")

	// resync now with the IP from DHCP, new pod and the other node
	resyncEv, resyncCount = datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// add pod entry into the mock DB
	datasync.Put(k8sPod.Key(pod1Name, pod1Namespace), &k8sPod.Pod{
		Namespace: pod1Namespace,
		Name:      pod1Name,
		IpAddress: ipamPlugin.GetPodIP(pod1ID).IP.String(),
	})

	fmt.Println("Restart (without node IP) --------------------------------")

	// restart
	plugin = IPNet{
		Deps:          deps,
		internalState: &internalState{},
		externalState: externalState,
	}
	datasync.RestartResyncCount()
	// resync
	resyncEv, resyncCount = datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	Expect(plugin.nodeIP).To(BeEmpty())
	Expect(plugin.nodeIPNet).To(BeNil())

	fmt.Println("Delete pod -----------------------------------------------")

	// delete pod
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(&podmanager.DeletePod{Pod: pod1ID}, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("un-configure IPv4 connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// remove the pod entry from mock podmanager and DB
	podManager.DeletePod(pod1ID)
	datasync.Delete(k8sPod.Key(pod1Name, pod1Namespace))

	fmt.Println("Delete node ----------------------------------------------")

	// delete the other node
	nodeUpdateEvent = nodeSync.DeleteNode(node2Name)
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("disconnect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync just before Close ---------------------------------")

	resyncEv, resyncCount = datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Close ----------------------------------------------------")

	shutdownEvent := &controller.Shutdown{}
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(shutdownEvent, txn)
	Expect(err).To(BeNil())
	// nothing needs to be cleaned up for TAPs
	Expect(change).To(Equal(""))
	Expect(txn.Values).To(BeEmpty())
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
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
