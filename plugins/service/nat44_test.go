// Copyright (c) 2018 Cisco and/or its affiliates.
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

package service

import (
	"context"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/ipv4net"
	. "github.com/contiv/vpp/mock/natplugin"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"

	"github.com/contiv/vpp/mock/localclient"
	controller "github.com/contiv/vpp/plugins/controller/api"
	svc_processor "github.com/contiv/vpp/plugins/service/processor"
	svc_renderer "github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/service/renderer/nat44"

	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

const (
	masterLabel = "master"
	workerLabel = "worker"

	// master
	mainIfName      = "GbE"
	OtherIfName     = "GbE2"
	OtherIfName2    = "GbE3"
	vxlanIfName     = "VXLAN-BVI"
	hostInterIfName = "VPP-Host"

	podNetwork    = "10.1.0.0/16"
	natLoopbackIP = "10.1.255.254"
	namespace1    = "default"
	namespace2    = "another-ns"

	mainVrfID = 1
	podVrfID  = 2
)

var (
	// master
	nodeIP, nodeIPAddr, nodeIPNet = ipNet("192.168.16.10/24")
	mgmtIP                        = net.ParseIP("172.30.1.1")

	// workers
	workerIP, workerIPAddr, workerIPNet = ipNet("192.168.16.20/24")
	otherIfIP                           = net.ParseIP("192.168.17.10")
	workerMgmtIP                        = net.ParseIP("172.30.1.2")

	// pods
	pod1 = podmodel.ID{Name: "pod1", Namespace: namespace1}
	pod2 = podmodel.ID{Name: "pod2", Namespace: namespace1}
	pod3 = podmodel.ID{Name: "pod3", Namespace: namespace2}

	pod1IP = net.ParseIP("10.1.1.3")
	pod2IP = net.ParseIP("10.1.1.4")
	pod3IP = net.ParseIP("10.2.1.1")

	pod1If = "master-tap1"
	pod2If = "master-tap2"
)

var (
	keyPrefixes = []string{epmodel.KeyPrefix(), svcmodel.KeyPrefix()}
)

// ongoing transaction
var (
	isResync bool
	vppTxn   controller.Transaction
	changes  string
)

func commitTxn() error {
	if vppTxn == nil {
		return nil
	}
	ctx := context.Background()
	if isResync {
		ctx = scheduler.WithResync(ctx, scheduler.FullResync, true)
	}
	err := vppTxn.Commit(ctx)
	vppTxn = nil
	changes = ""
	return err
}

func resyncTxnFactory(txnTracker *localclient.TxnTracker) func() controller.ResyncOperations {
	return func() controller.ResyncOperations {
		if vppTxn != nil {
			return vppTxn
		}
		vppTxn = txnTracker.NewControllerTxn(true)
		isResync = true
		return vppTxn
	}
}

func updateTxnFactory(txnTracker *localclient.TxnTracker) func(change string) controller.UpdateOperations {
	return func(change string) controller.UpdateOperations {
		if change != "" {
			if changes != "" {
				changes += ", "
			}
			changes += change
		}
		if vppTxn != nil {
			return vppTxn
		}
		vppTxn = txnTracker.NewControllerTxn(false)
		isResync = false
		return vppTxn
	}
}

func ipNet(address string) (combined *net.IPNet, addrOnly net.IP, network *net.IPNet) {
	addrOnly, network, _ = net.ParseCIDR(address)
	combined = &net.IPNet{IP: addrOnly, Mask: network.Mask}
	return combined, addrOnly, network
}

func TestResyncAndSingleService(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestResyncAndSingleService")

	// Prepare mocks.
	//  -> IPv4Net plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	const localEndpointWeight uint8 = 1
	ipv4Net.SetServiceLocalEndpointWeight(localEndpointWeight)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Test resync with empty VPP configuration.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
		},
	}

	updateEv1 := datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// No change in the NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	updateEv4 := datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1 := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = true
	Expect(natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Change port number for pod2.
	eps2 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     9080, // 8080 -> 9080
						Protocol: "TCP",
					},
				},
			},
		},
	}

	updateEv5 := datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New static mappings.
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1.Locals[1].Port = 9080
	staticMapping2.Locals[1].Port = 9080
	Expect(natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// NAT configuration without the service.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestMultipleServicesWithMultiplePortsAndResync(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleServicesWithMultiplePortsAndResync")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	const localEndpointWeight uint8 = 2
	ipv4Net.SetServiceLocalEndpointWeight(localEndpointWeight)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	// ID and IPs of this node are propagated later (see below)

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	// Initialize and resync.
	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Add pods.
	updateEv1 := podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv2 := podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := podManager.AddPod(&podmanager.LocalPod{ID: pod3})
	Expect(svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Service1: http + https with nodePort.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
			{
				Name:     "https",
				Protocol: "TCP",
				Port:     443,
				NodePort: 30443,
			},
		},
	}

	// Service2: DNS.
	service2 := &svcmodel.Service{
		Name:                  "service2",
		Namespace:             namespace2,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.10",
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "dns-tcp",
				Protocol: "TCP",
				Port:     53,
				NodePort: 0,
			},
			{
				Name:     "dns-udp",
				Protocol: "UDP",
				Port:     53,
				NodePort: 0,
			},
		},
	}

	updateEv4 := datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv5 := datasync.PutEvent(svcmodel.Key(service2.Name, service2.Namespace), service2)
	Expect(svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Name:     "https",
						Port:     8443,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	eps2 := &epmodel.Endpoints{
		Name:      "service2",
		Namespace: namespace2,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "dns-tcp",
						Port:     10053,
						Protocol: "TCP",
					},
					{
						Name:     "dns-udp",
						Port:     10053,
						Protocol: "UDP",
					},
				},
			},
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod3IP.String(),
						NodeName: workerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "dns-tcp",
						Port:     53,
						Protocol: "TCP",
					},
					{
						Name:     "dns-udp",
						Port:     53,
						Protocol: "UDP",
					},
				},
			},
		},
	}

	updateEv6 := datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv7 := datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(svcProcessor.Update(updateEv7)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	// -> service 1
	staticMappingHTTP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
		},
	}
	staticMappingHTTPS := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())

	// -> service 2
	staticMappingDNSTCP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.10"),
		ExternalPort: 53,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        10053,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod3IP,
				Port:        53,
				Probability: 1,
			},
		},
	}
	staticMappingDNSUDP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.10"),
		ExternalPort: 53,
		Protocol:     svc_renderer.UDP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        10053,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod3IP,
				Port:        53,
				Probability: 1,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

	// -> total
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Propagate NodeIP and Node Mgmt IP of the master.
	event := nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	Expect(svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

	// New static mappings for the https nodeport.
	staticMappingHTTPSNodeIP := &StaticMapping{
		ExternalIP:   nodeIP.IP,
		ExternalPort: 30443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
		},
	}
	staticMappingHTTPSNodeMgmtIP := &StaticMapping{
		ExternalIP:   mgmtIP,
		ExternalPort: 30443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
		},
	}

	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Propagate NodeIP and Node Mgmt IP of the worker.
	event = nodeSync.UpdateNode(&nodesync.Node{
		Name:            workerLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{workerMgmtIP},
	})
	Expect(svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())

	// New static mappings for the https nodeport - worker.
	staticMappingHTTPSWorkerNodeIP := staticMappingHTTPSNodeIP.Copy()
	staticMappingHTTPSWorkerNodeIP.ExternalIP = workerIP.IP
	staticMappingHTTPSWorkerNodeMgmtIP := staticMappingHTTPSNodeMgmtIP.Copy()
	staticMappingHTTPSWorkerNodeMgmtIP.ExternalIP = workerMgmtIP
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeMgmtIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(10))

	// Remove worker mgmt IP.
	event = nodeSync.UpdateNode(&nodesync.Node{
		Name:            workerLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{}, // removed
	})
	Expect(svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that the static mapping for worker mgmt IP was removed.
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(9))

	// Remove worker node completely.
	event = nodeSync.DeleteNode(workerLabel)
	Expect(svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that the static mapping for worker IP was removed.
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Simulate Resync.
	// -> simulate restart of the service plugin components
	svcProcessor = &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}
	renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}
	// -> let's simulate that during downtime the service1 was removed
	datasync.Delete(svcmodel.Key(service1.Name, service1.Namespace))
	// -> initialize and resync
	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())
	resyncEv2, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv2.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))

	// Simulate run-time resync.
	// -> let's simulate that while the agent was out-of-sync, the service1 was re-added, while service2 was removed.
	datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)
	datasync.Delete(svcmodel.Key(service2.Name, service2.Namespace))
	resyncEv3, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv3.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	// -> service1 was re-added.
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestWithVXLANButNoGateway(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestWithVXLANButNoGateway")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)
	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Resync from empty VPP.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestWithoutVXLAN(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestWithoutVXLAN")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Resync from empty VPP.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(2))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestWithOtherInterfaces(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestWithOtherInterfaces")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(OtherIfName, otherIfIP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetOtherPhysicalIfNames([]string{OtherIfName, OtherIfName2})
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Resync from empty VPP.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is configured.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(otherIfIP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(OtherIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(OtherIfName2)).To(Equal(NewNatFeatures(OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       otherIfIP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       otherIfIP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       otherIfIP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestWithoutNodeIP(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestWithoutNodeIP")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Resync from empty VPP.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestServiceUpdates(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestServiceUpdates")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	const localEndpointWeight uint8 = 4
	ipv4Net.SetServiceLocalEndpointWeight(localEndpointWeight)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	// Initialize and resync.
	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Add pods.
	updateEv1 := podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv2 := podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := podManager.AddPod(&podmanager.LocalPod{ID: pod3})
	Expect(svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Service1: http only (not https yet).
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
		},
	}

	updateEv4 := datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					{
						Ip:       pod3IP.String(),
						NodeName: workerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod3.Namespace,
							Name:      pod3.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	updateEv5 := datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod3IP,
				Port:        8080,
				Probability: 1,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove pod2.
	updateEv6 := podManager.DeletePod(pod2)
	Expect(svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Update endpoints accordingly (also add https port)
	eps1 = &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Name:     "https",
						Port:     8443,
						Protocol: "TCP",
					},
				},
			},
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod3IP.String(),
						NodeName: workerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod3.Namespace,
							Name:      pod3.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Name:     "https",
						Port:     443,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	updateEv7 := datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(svcProcessor.Update(updateEv7)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTP = &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod3IP,
				Port:        8080,
				Probability: 1,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 = staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Update service - add https.
	service1 = &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
			{
				Name:     "https",
				Protocol: "TCP",
				Port:     443,
				NodePort: 0,
			},
		},
	}

	updateEv8 := datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(svcProcessor.Update(updateEv8)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTPS := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod3IP,
				Port:        443,
				Probability: 1,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(4))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove all endpoints.
	updateEv9 := podManager.DeletePod(pod1)
	Expect(svcProcessor.Update(updateEv9)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv10 := datasync.DeleteEvent(epmodel.Key(eps1.Name, eps1.Namespace))
	Expect(svcProcessor.Update(updateEv10)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
}

func TestWithSNATOnly(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestWithSNATOnly")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	const localEndpointWeight uint8 = 1
	ipv4Net.SetServiceLocalEndpointWeight(localEndpointWeight)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(true)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Prepare configuration before resync.

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
		},
	}
	datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)

	// Add pods.
	podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	podManager.AddPod(&podmanager.LocalPod{ID: pod2})

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
		},
	}
	datasync.Put(epmodel.Key(eps1.Name, eps1.Namespace), eps1)

	// Resync.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is configured, but service-related configuration
	// was ignored.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(0))

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(1))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}

func TestLocalServicePolicy(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLocalServicePolicy")

	// Prepare mocks.
	//  -> Contiv plugin
	ipv4Net := NewMockIPv4Net()
	ipv4Net.SetNatExternalTraffic(true)
	const localEndpointWeight uint8 = 1
	ipv4Net.SetServiceLocalEndpointWeight(localEndpointWeight)
	ipv4Net.SetSTNMode(false)
	ipv4Net.SetNodeIP(nodeIP)
	ipv4Net.SetDefaultInterface(mainIfName, nodeIP.IP)
	ipv4Net.SetMainPhysicalIfName(mainIfName)
	ipv4Net.SetVxlanBVIIfName(vxlanIfName)
	ipv4Net.SetHostInterconnectIfName(hostInterIfName)
	ipv4Net.SetPodSubnet(podNetwork)
	ipv4Net.SetNatLoopbackIP(natLoopbackIP)
	ipv4Net.SetPodIfName(pod1, pod1If)
	ipv4Net.SetPodIfName(pod2, pod2If)
	ipv4Net.SetMainVrfID(mainVrfID)
	ipv4Net.SetPodVrfID(podVrfID)
	ipv4Net.SetHostIPs([]net.IP{mgmtIP})

	// -> nodesync
	nodeSync := NewMockNodeSync(masterLabel)
	nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		VppIPAddresses:  []*nodesync.IPWithNetwork{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	// -> podmanager
	podManager := NewMockPodManager()

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(masterLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare processor.
	svcProcessor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			IPv4Net:      ipv4Net,
			NodeSync:     nodeSync,
			PodManager:   podManager,
		},
	}

	// Prepare NAT44 Renderer.
	renderer := &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              logger,
			IPv4Net:          ipv4Net,
			ResyncTxnFactory: resyncTxnFactory(txnTracker),
			UpdateTxnFactory: updateTxnFactory(txnTracker),
		},
	}

	Expect(svcProcessor.Init()).To(BeNil())
	Expect(renderer.Init(false)).To(BeNil())
	Expect(svcProcessor.RegisterRenderer(renderer)).To(BeNil())

	// Test resync with empty VPP configuration.
	resyncEv, _ := datasync.ResyncEvent(keyPrefixes...)
	Expect(svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Local",
		ClusterIp:             "10.96.0.1",
		ExternalIps:           []string{"20.20.20.20"},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				NodePort: 0,
			},
		},
	}

	updateEv1 := datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// No change in the NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: masterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					{
						Ip:       pod3IP.String(),
						NodeName: workerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod3.Namespace,
							Name:      pod3.Name,
						},
					},
				},
				Ports: []*epmodel.EndpointSubset_EndpointPort{
					{
						Name:     "http",
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	updateEv4 := datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1 := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       podVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       podVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			// no pod3 - deployed on the worker node
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = false // local service policy
	Expect(natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// NAT configuration without the service.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(svcProcessor.Close()).To(BeNil())
	Expect(renderer.Close()).To(BeNil())
}
