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
	. "github.com/onsi/gomega"
	"net"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"

	. "github.com/contiv/vpp/mock/contiv"
	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/defaultplugins"
	. "github.com/contiv/vpp/mock/natplugin"
	. "github.com/contiv/vpp/mock/servicelabel"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv"
	svc_configurator "github.com/contiv/vpp/plugins/service/configurator"
	svc_processor "github.com/contiv/vpp/plugins/service/processor"

	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

const (
	agentLabel      = "master"
	mainIfName      = "GbE"
	vxlanIfName     = "VXLAN-BVI"
	hostInterIfName = "VPP-Host"
	nodeIP          = "192.168.16.10"
	nodePrefix      = "/24"
	defaultGwIP     = "192.168.16.1"
	podNetwork      = "10.1.0.0/16"
	namespace1      = "default"
)

var (
	pod1 = podmodel.ID{Name: "pod1", Namespace: namespace1}
	pod2 = podmodel.ID{Name: "pod2", Namespace: namespace1}

	pod1IP = "10.1.1.3"
	pod2IP = "10.1.1.4"

	pod1If = "master-tap1"
	pod2If = "master-tap2"

	pod1Model = &podmodel.Pod{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
		IpAddress: pod1IP,
	}

	pod2Model = &podmodel.Pod{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
		IpAddress: pod2IP,
	}
)

var (
	keyPrefixes = []string{epmodel.KeyPrefix(), podmodel.KeyPrefix(), svcmodel.KeyPrefix(), contiv.AllocatedIDsKeyPrefix}
)

func TestResyncAndSingleService(t *testing.T) {
	RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSomething")

	// Prepare mocks.
	//  -> Contiv plugin
	contiv := NewMockContiv()
	contiv.SetNatExternalTraffic(true)
	contiv.SetNodeIP(nodeIP + nodePrefix)
	contiv.SetDefaultGatewayIP(net.ParseIP(defaultGwIP))
	contiv.SetMainPhysicalIfName(mainIfName)
	contiv.SetVxlanBVIIfName(vxlanIfName)
	contiv.SetHostInterconnectIfName(hostInterIfName)
	contiv.SetPodNetwork(podNetwork)
	contiv.SetPodIfName(pod1, pod1If)
	contiv.SetPodIfName(pod2, pod2If)

	// -> NAT plugin
	natPlugin := NewMockNatPlugin(logger)

	// -> localclient
	txnTracker := localclient.NewTxnTracker(natPlugin.ApplyTxn)

	// -> default VPP plugins
	vppPlugins := NewMockVppPlugin()
	vppPlugins.SetNat44Dnat(&nat.Nat44DNat{})

	// -> service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(agentLabel)

	// -> datasync
	datasync := NewMockDataSync()

	// Prepare configurator.
	configurator := &svc_configurator.ServiceConfigurator{
		Deps: svc_configurator.Deps{
			Log:           logger,
			VPP:           vppPlugins,
			NATTxnFactory: txnTracker.NewLinuxDataChangeTxn,
		},
	}

	// Prepare processor.
	processor := &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          logger,
			ServiceLabel: serviceLabel,
			Contiv:       contiv,
			Configurator: configurator,
		},
	}

	Expect(configurator.Init()).To(BeNil())
	Expect(processor.Init()).To(BeNil())

	// Test resync with empty VPP configuration.
	resyncEv := datasync.Resync(keyPrefixes...)
	Expect(processor.Resync(resyncEv)).To(BeNil())

	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

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

	dataChange1 := datasync.Put(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(processor.Update(dataChange1)).To(BeNil())

	// No change in the NAT configuration.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())

	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP)).To(BeTrue())

	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(3))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))

	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// Add pods.
	dataChange2 := datasync.Put(podmodel.Key(pod1.Name, pod1.Namespace), pod1Model)
	Expect(processor.Update(dataChange2)).To(BeNil())
	dataChange3 := datasync.Put(podmodel.Key(pod2.Name, pod2.Namespace), pod2Model)
	Expect(processor.Update(dataChange3)).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP)).To(BeTrue())
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(0))
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

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
						Ip:       pod1IP,
						NodeName: agentLabel,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP,
						NodeName: agentLabel,
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

	dataChange4 := datasync.Put(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(processor.Update(dataChange4)).To(BeNil())

	// First check what should not have changed.
	Expect(natPlugin.IsForwardingEnabled()).To(BeTrue())
	Expect(natPlugin.AddressPoolSize()).To(Equal(1))
	Expect(natPlugin.PoolContainsAddress(nodeIP)).To(BeTrue())
	Expect(natPlugin.NumOfIdentityMappings()).To(Equal(0))

	// New interfaces with enabled NAT features.
	Expect(natPlugin.NumOfIfsWithFeatures()).To(Equal(5))
	Expect(natPlugin.GetInterfaceFeatures(mainIfName)).To(Equal(NewNatFeatures(OUTPUT_OUT)))
	Expect(natPlugin.GetInterfaceFeatures(vxlanIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(hostInterIfName)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod1If)).To(Equal(NewNatFeatures(IN, OUT)))
	Expect(natPlugin.GetInterfaceFeatures(pod2If)).To(Equal(NewNatFeatures(IN, OUT)))

	// New static mappings.
	Expect(natPlugin.NumOfStaticMappings()).To(Equal(2))
	staticMapping := &StaticMapping{
		ExternalIP:   net.ParseIP("10.96.0.1"),
		ExternalPort: 80,
		Protocol:     svc_configurator.TCP,
		Locals: []*Local{
			{
				IP:          net.ParseIP(pod1IP),
				Port:        8080,
				Probability: 2,
			},
			{
				IP:          net.ParseIP(pod2IP),
				Port:        8080,
				Probability: 2,
			},
		},
	}
	Expect(natPlugin.HasStaticMapping(staticMapping)).To(BeTrue())
	staticMapping.ExternalIP = net.ParseIP("20.20.20.20")
	Expect(natPlugin.HasStaticMapping(staticMapping)).To(BeTrue())

	// Cleanup
	Expect(processor.Close()).To(BeNil())
	Expect(configurator.Close()).To(BeNil())
}
