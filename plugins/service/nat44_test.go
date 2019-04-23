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

	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/ipnet"
	. "github.com/contiv/vpp/mock/natplugin"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"

	"github.com/contiv/vpp/mock/localclient"
	controller "github.com/contiv/vpp/plugins/controller/api"
	svc_config "github.com/contiv/vpp/plugins/service/config"
	svc_processor "github.com/contiv/vpp/plugins/service/processor"
	svc_renderer "github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/service/renderer/nat44"

	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/ipam"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

const (
	masterLabel = "master"
	masterID    = uint32(1)
	workerLabel = "worker"
	workerID    = uint32(2)

	// master
	mainIfName      = "GbE"
	OtherIfName     = "GbE2"
	OtherIfName2    = "GbE3"
	vxlanIfName     = "VXLAN-BVI"
	hostInterIfName = "VPP-Host"

	// extected NAT loopback IP for master based on default config
	natLoopbackIP = "10.1.1.254"

	namespace1 = "default"
	namespace2 = "another-ns"

	mainVrfID = 1
	podVrfID  = 2
)

var (
	// master
	nodeIP, nodeIPAddr, nodeIPNet = ipNet("192.168.16.10/24")
	mgmtIP                        = net.ParseIP("172.30.1.1")

	// workers
	workerIP, workerIPAddr, workerIPNet = ipNet("192.168.16.20/24")
	otherIfIP, otherIfAddr, otherIfNet  = ipNet("192.168.17.10/24")
	workerMgmtIP                        = net.ParseIP("172.30.1.2")

	gateway      = net.ParseIP("192.168.16.1")
	otherGateway = net.ParseIP("192.168.17.4")

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
	_, err := vppTxn.Commit(ctx)
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

func defaultConfig(withOtherIfaces bool) *config.Config {
	config := &config.Config{
		NatExternalTraffic: true,
		RoutingConfig: config.RoutingConfig{
			MainVRFID: mainVrfID,
			PodVRFID:  podVrfID,
		},
		NodeConfig: []config.NodeConfig{
			{
				NodeName: masterLabel,
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

type plugins struct {
	logger       logging.Logger
	datasync     *MockDataSync
	serviceLabel *MockServiceLabel
	nodeSync     *MockNodeSync
	contivConf   *contivconf.ContivConf
	ipam         *ipam.IPAM
	podManager   *MockPodManager
	natPlugin    *MockNatPlugin
	txnTracker   *localclient.TxnTracker
	ipNet        *MockIPNet
	svcProcessor *svc_processor.ServiceProcessor
	renderer     *nat44.Renderer
}

func initPlugins(testName string, config *config.Config, localEndpointWeight uint8, snatOnly bool, withoutMasterIPs ...bool) *plugins {
	plugins := &plugins{}

	// logger
	plugins.logger = logrus.DefaultLogger()
	plugins.logger.SetLevel(logging.DebugLevel)
	plugins.logger.Debug(testName)

	// datasync
	plugins.datasync = NewMockDataSync()

	// mock service label
	plugins.serviceLabel = NewMockServiceLabel()
	plugins.serviceLabel.SetAgentLabel(masterLabel)

	// nodesync mock plugin
	plugins.nodeSync = NewMockNodeSync(masterLabel)
	if len(withoutMasterIPs) > 0 && withoutMasterIPs[0] {
		plugins.nodeSync.UpdateNode(&nodesync.Node{
			Name: masterLabel,
			ID:   masterID,
		})
	} else {
		plugins.nodeSync.UpdateNode(&nodesync.Node{
			Name:            masterLabel,
			ID:              masterID,
			VppIPAddresses:  contivconf.IPsWithNetworks{{Address: nodeIPAddr, Network: nodeIPNet}},
			MgmtIPAddresses: []net.IP{mgmtIP},
		})
	}
	Expect(plugins.nodeSync.GetNodeID()).To(BeEquivalentTo(1))

	// contivConf (real) plugin
	plugins.contivConf = &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: plugins.serviceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: config,
			},
		},
	}
	Expect(plugins.contivConf.Init()).To(BeNil())
	resyncEv, _ := plugins.datasync.ResyncEvent()
	Expect(plugins.contivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// IPAM real plugin
	plugins.ipam = &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("ipam"),
			},
			NodeSync:   plugins.nodeSync,
			ContivConf: plugins.contivConf,
		},
	}
	Expect(plugins.ipam.Init()).To(BeNil())
	Expect(plugins.ipam.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())
	Expect(plugins.ipam.NatLoopbackIP().String()).To(Equal(natLoopbackIP))
	plugins.datasync.RestartResyncCount()

	// podmanager
	plugins.podManager = NewMockPodManager()

	// NAT plugin
	plugins.natPlugin = NewMockNatPlugin(plugins.logger)

	// transactions
	plugins.txnTracker = localclient.NewTxnTracker(plugins.natPlugin.ApplyTxn)

	// IPNet plugin
	plugins.ipNet = NewMockIPNet()
	plugins.ipNet.SetNodeIP(nodeIP)
	plugins.ipNet.SetVxlanBVIIfName(vxlanIfName)
	plugins.ipNet.SetHostInterconnectIfName(hostInterIfName)
	plugins.ipNet.SetPodIfName(pod1, pod1If)
	plugins.ipNet.SetPodIfName(pod2, pod2If)
	plugins.ipNet.SetHostIPs([]net.IP{mgmtIP})

	// Prepare processor.
	plugins.svcProcessor = &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          plugins.logger,
			ServiceLabel: plugins.serviceLabel,
			ContivConf:   plugins.contivConf,
			IPAM:         plugins.ipam,
			IPNet:        plugins.ipNet,
			NodeSync:     plugins.nodeSync,
			PodManager:   plugins.podManager,
		},
	}

	// Prepare NAT44 Renderer.
	plugins.renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              plugins.logger,
			Config:           &svc_config.Config{ServiceLocalEndpointWeight: localEndpointWeight},
			ContivConf:       plugins.contivConf,
			IPAM:             plugins.ipam,
			IPNet:            plugins.ipNet,
			ResyncTxnFactory: resyncTxnFactory(plugins.txnTracker),
			UpdateTxnFactory: updateTxnFactory(plugins.txnTracker),
		},
	}

	Expect(plugins.svcProcessor.Init()).To(BeNil())
	Expect(plugins.renderer.Init(snatOnly)).To(BeNil())
	Expect(plugins.svcProcessor.RegisterRenderer(plugins.renderer)).To(BeNil())
	return plugins
}

func TestResyncAndSingleService(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	plugins := initPlugins("TestResyncAndSingleService", config, localEndpointWeight, false)

	// Test resync with empty VPP configuration.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))

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
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

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

	updateEv1 := plugins.datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(plugins.svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// No change in the NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(plugins.svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(plugins.svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

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

	updateEv4 := plugins.datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(plugins.svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))
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
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = true
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

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

	updateEv5 := plugins.datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(plugins.svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New static mappings.
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping1.Locals[1].Port = 9080
	staticMapping2.Locals[1].Port = 9080
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := plugins.datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(plugins.svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// NAT configuration without the service.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestMultipleServicesWithMultiplePortsAndResync(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 2
	config := defaultConfig(false)
	plugins := initPlugins("TestMultipleServicesWithMultiplePortsAndResync", config, localEndpointWeight, false, true)

	// startup resync
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Add pods.
	updateEv1 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(plugins.svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv2 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(plugins.svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod3})
	Expect(plugins.svcProcessor.Update(updateEv3)).To(BeNil())
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

	updateEv4 := plugins.datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(plugins.svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv5 := plugins.datasync.PutEvent(svcmodel.Key(service2.Name, service2.Namespace), service2)
	Expect(plugins.svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))

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
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

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

	updateEv6 := plugins.datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(plugins.svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv7 := plugins.datasync.PutEvent(epmodel.Key(eps2.Name, eps2.Namespace), eps2)
	Expect(plugins.svcProcessor.Update(updateEv7)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

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
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())

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
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

	// -> total
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Propagate NodeIP and Node Mgmt IP of the master.
	event := plugins.nodeSync.UpdateNode(&nodesync.Node{
		Name:            masterLabel,
		ID:              masterID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: nodeIPAddr, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})

	Expect(plugins.svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())

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

	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Propagate NodeIP and Node Mgmt IP of the worker.
	event = plugins.nodeSync.UpdateNode(&nodesync.Node{
		Name:            workerLabel,
		ID:              workerID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{workerMgmtIP},
	})
	Expect(plugins.svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())

	// New static mappings for the https nodeport - worker.
	staticMappingHTTPSWorkerNodeIP := staticMappingHTTPSNodeIP.Copy()
	staticMappingHTTPSWorkerNodeIP.ExternalIP = workerIP.IP
	staticMappingHTTPSWorkerNodeMgmtIP := staticMappingHTTPSNodeMgmtIP.Copy()
	staticMappingHTTPSWorkerNodeMgmtIP.ExternalIP = workerMgmtIP
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeMgmtIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(10))

	// Remove worker mgmt IP.
	event = plugins.nodeSync.UpdateNode(&nodesync.Node{
		Name:            workerLabel,
		ID:              workerID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: workerIPAddr, Network: workerIPNet}},
		MgmtIPAddresses: []net.IP{}, // removed
	})
	Expect(plugins.svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that the static mapping for worker mgmt IP was removed.
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSWorkerNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(9))

	// Remove worker node completely.
	event = plugins.nodeSync.DeleteNode(workerLabel)
	Expect(plugins.svcProcessor.Update(event)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that the static mapping for worker IP was removed.
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(8))

	// Simulate Resync.
	// -> simulate restart of the service plugin components
	plugins.svcProcessor = &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          plugins.logger,
			ServiceLabel: plugins.serviceLabel,
			ContivConf:   plugins.contivConf,
			IPAM:         plugins.ipam,
			IPNet:        plugins.ipNet,
			NodeSync:     plugins.nodeSync,
			PodManager:   plugins.podManager,
		},
	}
	plugins.renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:              plugins.logger,
			Config:           &svc_config.Config{ServiceLocalEndpointWeight: localEndpointWeight},
			ContivConf:       plugins.contivConf,
			IPAM:             plugins.ipam,
			IPNet:            plugins.ipNet,
			ResyncTxnFactory: resyncTxnFactory(plugins.txnTracker),
			UpdateTxnFactory: updateTxnFactory(plugins.txnTracker),
		},
	}
	// -> let's simulate that during downtime the service1 was removed
	plugins.datasync.Delete(svcmodel.Key(service1.Name, service1.Namespace))
	// -> initialize and resync
	Expect(plugins.svcProcessor.Init()).To(BeNil())
	Expect(plugins.renderer.Init(false)).To(BeNil())
	Expect(plugins.svcProcessor.RegisterRenderer(plugins.renderer)).To(BeNil())
	resyncEv2, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv2.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSTCP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingDNSUDP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))

	// Simulate run-time resync.
	// -> let's simulate that while the agent was out-of-sync, the service1 was re-added, while service2 was removed.
	plugins.datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)
	plugins.datasync.Delete(svcmodel.Key(service2.Name, service2.Namespace))
	resyncEv3, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv3.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))
	// -> service1 was re-added.
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeIP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPSNodeMgmtIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(6))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestWithVXLANButNoGateway(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	config.NodeConfig[0].Gateway = ""
	plugins := initPlugins("TestWithVXLANButNoGateway", config, 1, false)

	// Resync from empty VPP.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestWithoutVXLAN(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	plugins := initPlugins("TestWithoutVXLAN", config, 1, false)
	plugins.ipNet.SetVxlanBVIIfName("")

	// Resync from empty VPP.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(2))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestWithOtherInterfaces(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(true)
	config.NodeConfig[0].Gateway = otherGateway.String()
	plugins := initPlugins("TestWithOtherInterfaces", config, 1, false)

	// Resync from empty VPP.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is configured.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(otherIfAddr)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(OtherIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(OtherIfName2)).To(Equal(NewNatFeatures(OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))

	vxlanID := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     4789,
		VrfID:    mainVrfID,
	}
	mainIfID1 := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    mainVrfID,
	}
	mainIfID2 := &IdentityMapping{
		IP:       otherIfAddr,
		Protocol: svc_renderer.UDP,
		Port:     0,
		VrfID:    podVrfID,
	}
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestWithoutNodeIP(t *testing.T) {
	RegisterTestingT(t)
	config := defaultConfig(false)
	plugins := initPlugins("TestWithoutNodeIP", config, 1, false)
	plugins.ipNet.SetNodeIP(nil)

	// Resync from empty VPP.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is NOT configured.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeFalse())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(0))
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestServiceUpdates(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	plugins := initPlugins("TestServiceUpdates", config, localEndpointWeight, false)

	// Startup resync.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Add pods.
	updateEv1 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(plugins.svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv2 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(plugins.svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod3})
	Expect(plugins.svcProcessor.Update(updateEv3)).To(BeNil())
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

	updateEv4 := plugins.datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(plugins.svcProcessor.Update(updateEv4)).To(BeNil())
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

	updateEv5 := plugins.datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(plugins.svcProcessor.Update(updateEv5)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

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
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 := staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))

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
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove pod2.
	updateEv6 := plugins.podManager.DeletePod(pod2)
	Expect(plugins.svcProcessor.Update(updateEv6)).To(BeNil())
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

	updateEv7 := plugins.datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(plugins.svcProcessor.Update(updateEv7)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

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
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	staticMappingHTTP2 = staticMappingHTTP.Copy()
	staticMappingHTTP2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTP2.TwiceNAT = true
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

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

	updateEv8 := plugins.datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(plugins.svcProcessor.Update(updateEv8)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(4))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))

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
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS)).To(BeTrue())
	staticMappingHTTPS2 := staticMappingHTTPS.Copy()
	staticMappingHTTPS2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMappingHTTPS2.TwiceNAT = true
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTP2)).To(BeTrue())
	Expect(plugins.natPlugin.HasStaticMapping(staticMappingHTTPS2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(4))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Remove all endpoints.
	updateEv9 := plugins.podManager.DeletePod(pod1)
	Expect(plugins.svcProcessor.Update(updateEv9)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv10 := plugins.datasync.DeleteEvent(epmodel.Key(eps1.Name, eps1.Namespace))
	Expect(plugins.svcProcessor.Update(updateEv10)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
}

func TestWithSNATOnly(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	plugins := initPlugins("TestWithSNATOnly", config, localEndpointWeight, true)

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
	plugins.datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)

	// Add pods.
	plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod2})

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
	plugins.datasync.Put(epmodel.Key(eps1.Name, eps1.Namespace), eps1)

	// Resync.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// Check that SNAT is configured, but service-related configuration
	// was ignored.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(0))

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(1))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))

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
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}

func TestLocalServicePolicy(t *testing.T) {
	RegisterTestingT(t)
	const localEndpointWeight uint8 = 1
	config := defaultConfig(false)
	plugins := initPlugins("TestLocalServicePolicy", config, localEndpointWeight, false)

	// Test resync with empty VPP configuration.
	resyncEv, _ := plugins.datasync.ResyncEvent(keyPrefixes...)
	Expect(plugins.svcProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))

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
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

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

	updateEv1 := plugins.datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(plugins.svcProcessor.Update(updateEv1)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// No change in the NAT configuration.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())

	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Add pods.
	updateEv2 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod1})
	Expect(plugins.svcProcessor.Update(updateEv2)).To(BeNil())
	Expect(commitTxn()).To(BeNil())
	updateEv3 := plugins.podManager.AddPod(&podmanager.LocalPod{ID: pod2})
	Expect(plugins.svcProcessor.Update(updateEv3)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// Interface attaching pods should have NAT/OUT enabled.
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

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

	updateEv4 := plugins.datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(plugins.svcProcessor.Update(updateEv4)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// First check what should not have changed.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())

	// New interfaces with enabled NAT features.
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(2))
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
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping1)).To(BeTrue())
	staticMapping2 := staticMapping1.Copy()
	staticMapping2.ExternalIP = net.ParseIP("20.20.20.20")
	staticMapping2.TwiceNAT = false // local service policy
	Expect(plugins.natPlugin.HasStaticMapping(staticMapping2)).To(BeTrue())

	// Finally remove the service.
	updateEv6 := plugins.datasync.DeleteEvent(svcmodel.Key(service1.Name, service1.Namespace))
	Expect(plugins.svcProcessor.Update(updateEv6)).To(BeNil())
	Expect(commitTxn()).To(BeNil())

	// NAT configuration without the service.
	Expect(plugins.natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(plugins.natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.PoolContainsAddress(nodeIP.IP)).To(BeTrue())
	Expect(plugins.natPlugin.TwiceNatPoolSize()).To(Equal(1))
	Expect(plugins.natPlugin.TwiceNatPoolContainsAddress(natLoopbackIP)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(plugins.natPlugin.NumOfIdentityMappings()).To(Equal(3))
	Expect(plugins.natPlugin.HasIdentityMapping(vxlanID)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID1)).To(BeTrue())
	Expect(plugins.natPlugin.HasIdentityMapping(mainIfID2)).To(BeTrue())
	Expect(plugins.natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(plugins.natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(OUT)))
	Expect(plugins.natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(OUT)))

	// Cleanup
	Expect(plugins.svcProcessor.Close()).To(BeNil())
	Expect(plugins.renderer.Close()).To(BeNil())
}
