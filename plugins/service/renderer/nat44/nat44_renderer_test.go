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

package nat44_test

import (
	"net"
	"testing"

	. "github.com/contiv/vpp/mock/natplugin"
	. "github.com/onsi/gomega"

	"github.com/contiv/vpp/mock/ipnet"
	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	svc_config "github.com/contiv/vpp/plugins/service/config"
	svc_processor "github.com/contiv/vpp/plugins/service/processor"
	svc_renderer "github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/service/renderer/nat44"
	renderer_testing "github.com/contiv/vpp/plugins/service/renderer/testing"
)

const (
	// master
	mainIfName      = "GbE"
	OtherIfName     = "GbE2"
	OtherIfName2    = "GbE3"
	vxlanIfName     = "VXLAN-BVI"
	hostInterIfName = "VPP-Host"

	// extected NAT loopback IP for master based on default config
	natLoopbackIP = "10.1.1.254"
)

var (
	// master
	nodeIP, nodeIPAddr, nodeIPNet = renderer_testing.IPNet("192.168.16.10/24")
	mgmtIP                        = net.ParseIP("172.30.1.1")

	// workers
	workerIP, workerIPAddr, workerIPNet = renderer_testing.IPNet("192.168.16.20/24")
	otherIfIP, otherIfAddr, otherIfNet  = renderer_testing.IPNet("192.168.17.10/24")
	workerMgmtIP                        = net.ParseIP("172.30.1.2")

	gateway      = net.ParseIP("192.168.16.1")
	otherGateway = net.ParseIP("192.168.17.4")

	// pods
	pod1IP = net.ParseIP("10.1.1.3")
	pod2IP = net.ParseIP("10.1.1.4")
	pod3IP = net.ParseIP("10.2.1.1")
)

var (
	keyPrefixes = []string{epmodel.KeyPrefix(), svcmodel.KeyPrefix()}
)

func defaultConfig(withOtherIfaces bool) *config.Config {
	config := &config.Config{
		NatExternalTraffic: true,
		RoutingConfig: config.RoutingConfig{
			MainVRFID: renderer_testing.MainVrfID,
			PodVRFID:  renderer_testing.PodVrfID,
		},
		NodeConfig: []config.NodeConfig{
			{
				NodeName: renderer_testing.MasterLabel,
				NodeConfigSpec: nodeconfigcrd.NodeConfigSpec{
					MainVPPInterface: nodeconfigcrd.InterfaceConfig{
						InterfaceName: mainIfName,
						IP:            nodeIP.String(),
					},
					Gateway: gateway.String(),
				},
			},
		},
	}
	if withOtherIfaces {
		config.NodeConfig[0].OtherVPPInterfaces = []nodeconfigcrd.InterfaceConfig{
			{
				InterfaceName: OtherIfName,
				IP:            otherIfIP.String(),
			},
			{
				InterfaceName: OtherIfName2,
			}}
	}
	return config
}

// data is holder of all test related data (fixture, tested renderer, result catching natPlugin mock)
type data struct {
	*renderer_testing.Fixture
	renderer   *nat44.Renderer
	txnTracker *localclient.TxnTracker
	natPlugin  *MockNatPlugin
}

func initTest(testName string, config *config.Config, localEndpointWeight uint8, snatOnly bool, withoutMasterIPs ...bool) *data {
	fixture := renderer_testing.NewFixture(testName, config, newMockIPNet(), nodeIPAddr, nodeIPNet, mgmtIP, withoutMasterIPs...)
	data := &data{Fixture: fixture}

	// additional checks of base fixture creation
	Expect(data.IPAM.NatLoopbackIP().String()).To(Equal(natLoopbackIP))

	// NAT plugin
	data.natPlugin = NewMockNatPlugin(data.Logger)

	// transactions
	data.txnTracker = localclient.NewTxnTracker(data.natPlugin.ApplyTxn)

	// Prepare NAT44 Renderer.
	data.renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              data.Logger,
			Config:           &svc_config.Config{ServiceLocalEndpointWeight: localEndpointWeight},
			ContivConf:       data.ContivConf,
			IPAM:             data.IPAM,
			IPNet:            data.IPNet,
			ResyncTxnFactory: data.Txn.ResyncFactory(data.txnTracker),
			UpdateTxnFactory: data.Txn.UpdateFactory(data.txnTracker),
		},
	}

	Expect(data.renderer.Init(snatOnly)).To(BeNil())
	Expect(data.SVCProcessor.RegisterRenderer(data.renderer)).To(BeNil())
	return data
}

func newMockIPNet() *ipnet.MockIPNet {
	ipNet := ipnet.NewMockIPNet()
	ipNet.SetNodeIP(nodeIP)
	ipNet.SetVxlanBVIIfName(vxlanIfName)
	ipNet.SetHostInterconnectIfName(hostInterIfName)
	ipNet.SetPodIfName(renderer_testing.Pod1, renderer_testing.Pod1If)
	ipNet.SetPodIfName(renderer_testing.Pod2, renderer_testing.Pod2If)
	ipNet.SetHostIPs([]net.IP{mgmtIP})
	return ipNet
}

func TestResyncAndSingleService(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	data := initTest("TestResyncAndSingleService", config, localEndpointWeight, false)

	// Test resync with empty VPP configuration.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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

	updateEv1 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv1)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// No change in the NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod1})
	Expect(data.SVCProcessor.Update(updateEv2)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv3 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod2})
	Expect(data.SVCProcessor.Update(updateEv3)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
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

	updateEv4 := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv4)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1 := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = true
	Expect(data.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Change port number for renderer_testing.Pod2.
	eps2 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
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
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
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

	updateEv5 := data.Datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(data.SVCProcessor.Update(updateEv5)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New static mappings.
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1.Locals[1].Port = 9080
	staticMapping2.Locals[1].Port = 9080
	Expect(data.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := data.Datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(data.SVCProcessor.Update(updateEv6)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// NAT configuration without the service.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestMultipleServicesWithMultiplePortsAndResync(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 2
	config := defaultConfig(false)
	data := initTest("TestMultipleServicesWithMultiplePortsAndResync", config, localEndpointWeight, false, true)

	// startup resync
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Add pods.
	updateEv1 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod1})
	Expect(data.SVCProcessor.Update(updateEv1)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv2 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod2})
	Expect(data.SVCProcessor.Update(updateEv2)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv3 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod3})
	Expect(data.SVCProcessor.Update(updateEv3)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Service1: http + https with nodePort.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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
		Namespace:             renderer_testing.Namespace2,
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

	updateEv4 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv4)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv5 := data.Datasync.PutEvent(svcmodel.Key(service2.Name, service2.Namespace), service2)
	Expect(data.SVCProcessor.Update(updateEv5)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
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
		Namespace: renderer_testing.Namespace2,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
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
						NodeName: renderer_testing.WorkerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
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

	updateEv6 := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv6)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv7 := data.Datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(data.SVCProcessor.Update(updateEv7)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	// -> service 1
	staticMappingHTTP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
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
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod2IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())

	// -> service 2
	staticMappingDNSTCP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.10"),
		ExternalPort: 53,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        10053,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
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
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        10053,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod3IP,
				Port:        53,
				Probability: 1,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

	// -> total
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Propagate NodeIP and Node Mgmt IP of the master.
	event := data.NodeSync.UpdateNode(&nodesync.Node{
		Name:            renderer_testing.MasterLabel,
		ID:              renderer_testing.MasterID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	Expect(data.SVCProcessor.Update(event)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

	// New static mappings for the https nodeport.
	staticMappingHTTPSNodeIP := &StaticMapping{
		ExternalIP:   nodeIP.IP,
		ExternalPort: 30443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
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
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod2IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
		},
	}

	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Propagate NodeIP and Node Mgmt IP of the worker.
	event = data.NodeSync.UpdateNode(&nodesync.Node{
		Name:            renderer_testing.WorkerLabel,
		ID:              renderer_testing.WorkerID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{workerMgmtIP},
	})
	Expect(data.SVCProcessor.Update(event)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())

	// New static mappings for the https nodeport - worker.
	staticMappingHTTPSWorkerNodeIP := staticMappingHTTPSNodeIP.Copy()
	staticMappingHTTPSWorkerNodeIP.ExternalIP = workerIP.IP
	staticMappingHTTPSWorkerNodeMgmtIP := staticMappingHTTPSNodeMgmtIP.Copy()
	staticMappingHTTPSWorkerNodeMgmtIP.ExternalIP = workerMgmtIP
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeMgmtIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(10))

	// Remove worker mgmt IP.
	event = data.NodeSync.UpdateNode(&nodesync.Node{
		Name:            renderer_testing.WorkerLabel,
		ID:              renderer_testing.WorkerID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{}, // removed
	})
	Expect(data.SVCProcessor.Update(event)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that the static mapping for worker mgmt IP was removed.
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(9))

	// Remove worker node completely.
	event = data.NodeSync.DeleteNode(renderer_testing.WorkerLabel)
	Expect(data.SVCProcessor.Update(event)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that the static mapping for worker IP was removed.
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Simulate Resync.
	// -> simulate restart of the service plugin components
	data.SVCProcessor = &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          data.Logger,
			ServiceLabel: data.ServiceLabel,
			ContivConf:   data.ContivConf,
			IPAM:         data.IPAM,
			IPNet:        data.IPNet,
			NodeSync:     data.NodeSync,
			PodManager:   data.PodManager,
		},
	}
	data.renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              data.Logger,
			Config:           &svc_config.Config{ServiceLocalEndpointWeight: localEndpointWeight},
			ContivConf:       data.ContivConf,
			IPAM:             data.IPAM,
			IPNet:            data.IPNet,
			ResyncTxnFactory: data.Txn.ResyncFactory(data.txnTracker),
			UpdateTxnFactory: data.Txn.UpdateFactory(data.txnTracker),
		},
	}
	// -> let's simulate that during downtime the service1 was removed
	data.Datasync.Delete(svcmodel.Key(service1.Name, service1.Namespace))
	// -> initialize and resync
	Expect(data.SVCProcessor.Init()).To(BeNil())
	Expect(data.renderer.Init(false)).To(BeNil())
	Expect(data.SVCProcessor.RegisterRenderer(data.renderer)).To(BeNil())
	resyncEv2, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv2.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))

	// Simulate run-time resync.
	// -> let's simulate that while the agent was out-of-sync, the service1 was re-added, while service2 was removed.
	data.Datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)
	data.Datasync.Delete(svcmodel.Key(service2.Name, service2.Namespace))
	resyncEv3, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv3.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	// -> service1 was re-added.
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestWithVXLANButNoGateway(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	config.NodeConfig[0].Gateway = ""
	data := initTest("TestWithVXLANButNoGateway", config, 1, false)

	// Resync from empty VPP.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestWithoutVXLAN(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	data := initTest("TestWithoutVXLAN", config, 1, false)
	data.IPNet.SetVxlanBVIIfName("")

	// Resync from empty VPP.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(2))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestWithOtherInterfaces(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(true)
	config.NodeConfig[0].Gateway = otherGateway.String()
	data := initTest("TestWithOtherInterfaces", config, 1, false)

	// Resync from empty VPP.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that SNAT is configured.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(otherIfAddr)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(OtherIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(OtherIfName2)).To(Equal(NewNatFeatures(OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestWithoutNodeIP(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	data := initTest("TestWithoutNodeIP", config, 1, false)
	data.IPNet.SetNodeIP(nil)

	// Resync from empty VPP.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestServiceUpdates(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	data := initTest("TestServiceUpdates", config, localEndpointWeight, false)

	// Startup resync.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Add pods.
	updateEv1 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod1})
	Expect(data.SVCProcessor.Update(updateEv1)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv2 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod2})
	Expect(data.SVCProcessor.Update(updateEv2)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv3 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod3})
	Expect(data.SVCProcessor.Update(updateEv3)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Service1: http only (not https yet).
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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

	updateEv4 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv4)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
						},
					},
					{
						Ip:       pod3IP.String(),
						NodeName: renderer_testing.WorkerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod3.Namespace,
							Name:      renderer_testing.Pod3.Name,
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

	updateEv5 := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv5)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTP := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod3IP,
				Port:        8080,
				Probability: 1,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove renderer_testing.Pod2.
	updateEv6 := data.PodManager.DeletePod(renderer_testing.Pod2)
	Expect(data.SVCProcessor.Update(updateEv6)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Update endpoints accordingly (also add https port)
	eps1 = &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
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
						NodeName: renderer_testing.WorkerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod3.Namespace,
							Name:      renderer_testing.Pod3.Name,
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

	updateEv7 := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv7)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTP = &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod3IP,
				Port:        8080,
				Probability: 1,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 = staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Update service - add https.
	service1 = &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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

	updateEv8 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv8)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

	staticMappingHTTPS := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 443,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8443,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod3IP,
				Port:        443,
				Probability: 1,
			},
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(data.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(4))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove all endpoints.
	updateEv9 := data.PodManager.DeletePod(renderer_testing.Pod1)
	Expect(data.SVCProcessor.Update(updateEv9)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv10 := data.Datasync.DeleteEvent(epmodel.Key(eps1.Name, eps1.Namespace))
	Expect(data.SVCProcessor.Update(updateEv10)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
}

func TestWithSNATOnly(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	data := initTest("TestWithSNATOnly", config, localEndpointWeight, true)

	// Prepare configuration before resync.

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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
	data.Datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)

	// Add pods.
	data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod1})
	data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod2})

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
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
	data.Datasync.Put(epmodel.Key(eps1.Name, eps1.Namespace), eps1)

	// Resync.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// Check that SNAT is configured, but service-related configuration
	// was ignored.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(0))

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(1))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func TestLocalServicePolicy(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	data := initTest("TestLocalServicePolicy", config, localEndpointWeight, false)

	// Test resync with empty VPP configuration.
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.MainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       nodeIP.IP,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    renderer_testing.PodVrfID,
	}
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add service metadata.
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
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

	updateEv1 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv1)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// No change in the NAT configuration.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod1})
	Expect(data.SVCProcessor.Update(updateEv2)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	updateEv3 := data.PodManager.AddPod(&podmanager.LocalPod{ID: renderer_testing.Pod2})
	Expect(data.SVCProcessor.Update(updateEv3)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Add endpoints.
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod1.Namespace,
							Name:      renderer_testing.Pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: renderer_testing.MasterLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod2.Namespace,
							Name:      renderer_testing.Pod2.Name,
						},
					},
					{
						Ip:       pod3IP.String(),
						NodeName: renderer_testing.WorkerLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: renderer_testing.Pod3.Namespace,
							Name:      renderer_testing.Pod3.Name,
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

	updateEv4 := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv4)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// First check what should not have changed.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1 := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_renderer.TCP,
		Locals: []*Local{
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod1IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			{
				VrfID:       renderer_testing.PodVrfID,
				IP:          pod2IP,
				Port:        8080,
				Probability: localEndpointWeight,
			},
			// no renderer_testing.Pod3 - deployed on the worker node
		},
	}
	Expect(data.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = false // local service policy
	Expect(data.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := data.Datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(data.SVCProcessor.Update(updateEv6)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// NAT configuration without the service.
	Expect(data.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(data.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(data.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(data.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(data.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(data.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(data.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(data.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(data.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(data.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(data.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(data.natPlugin.GetInterfaceFeatures(renderer_testing.Pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}
