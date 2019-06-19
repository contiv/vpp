// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
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

package srv6_test

import (
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/contiv/vpp/mock/configRetriever"
	"github.com/contiv/vpp/mock/ipnet"
	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/mock/vppagent"
	"github.com/contiv/vpp/mock/vppagent/handler"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/renderer/srv6"
	renderer_testing "github.com/contiv/vpp/plugins/service/renderer/testing"
	linux_interfaces "github.com/ligato/vpp-agent/api/models/linux/interfaces"
	linux_iptables "github.com/ligato/vpp-agent/api/models/linux/iptables"
	linux_namespace "github.com/ligato/vpp-agent/api/models/linux/namespace"
	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
)

const (
	defaultPort          = 80 // default port for service and backend
	differentBackendPort = 8080
)

var (
	// master
	nodeIP, nodeIPAddr, nodeIPNet = renderer_testing.IPNet("2005:0:0:0:0:0:16:10/112")
	mgmtIP                        = net.ParseIP("2002:0:0:0:0:0:1:1")
	gateway                       = net.ParseIP("2005:0:0:0:0:0:16:1")

	// interfaces
	mainIfName      = "GbE"
	hostInterIfName = "VPP-Host"

	keyPrefixes = []string{epmodel.KeyPrefix(), svcmodel.KeyPrefix()}

	// worker
	workerIP = net.ParseIP("fe10:f00d::3")
	pod3IP   = net.ParseIP("2001:0:0:2::1")
)

// data is holder all test related data (fixture, tested renderer, result catching srv6Handler mock)
type data struct {
	*renderer_testing.Fixture
	renderer         *srv6.Renderer
	txnTracker       *localclient.TxnTracker
	srv6Handler      *handler.SRv6MockHandler
	routeHandler     *handler.RouteMockHandler
	interfaceHandler *handler.InterfaceMockHandler
	ruleChainHandler *handler.RuleChainMockHandler
}

func TestBasicService(t *testing.T) {
	RegisterTestingT(t)
	retriever := configRetriever.NewMockConfigRetriever()
	data := initTest("TestBasicService", defaultConfig(), retriever, false)

	// setup service
	emptyResync(data)
	service1 := addServiceMetadata(data, defaultPort)
	pod1IP := addLocalPod(renderer_testing.Pod1, data, retriever)
	pod2IP := addLocalPod(renderer_testing.Pod2, data, retriever)
	assertEmptyVPPAgentConfiguration(data) // checking that nothing gets configured without service having properly set backends
	addServiceEndpoints(renderer_testing.Pod1, pod1IP, renderer_testing.Pod2, pod2IP, defaultPort, data)

	// check locasids/policy/steering on VPP-agent side
	localsidForPod1 := assertLocalSid(data.IPAM.SidForServicePodLocalsid(pod1IP), renderer_testing.PodVrfID, pod1IP, renderer_testing.Pod1If, data)
	localsidForPod2 := assertLocalSid(data.IPAM.SidForServicePodLocalsid(pod2IP), renderer_testing.PodVrfID, pod2IP, renderer_testing.Pod2If, data)
	Expect(data.srv6Handler.LocalSids).To(HaveLen(2))
	bsid := assertPolicy(service1, [][]string{
		{data.IPAM.SidForServicePodLocalsid(pod1IP).String()},
		{data.IPAM.SidForServicePodLocalsid(pod2IP).String()},
	}, data)
	assertSteering(service1, bsid, data)

	// checking redirection routes that moves packet from main vrf to pod vrf (to pod1 backend)
	routeForPod1 := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  localsidForPod1.Sid + "/128",
		VrfId:       renderer_testing.MainVrfID,
		ViaVrfId:    renderer_testing.PodVrfID,
		NextHopAddr: "::",
	}
	routeForPod2 := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  localsidForPod2.Sid + "/128",
		VrfId:       renderer_testing.MainVrfID,
		ViaVrfId:    renderer_testing.PodVrfID,
		NextHopAddr: "::",
	}
	Expect(data.routeHandler.Route).To(ContainElement(routeForPod1))
	Expect(data.routeHandler.Route).To(ContainElement(routeForPod2))
	Expect(data.routeHandler.Route).To(HaveLen(2))

	// check loop interface for pods
	loopInterface := &linux_interfaces.Interface{
		IpAddresses: []string{service1.ClusterIp + "/128"},
	}
	Expect(data.interfaceHandler.Interfaces).Should(HaveKeyWithValue("linux-loop-"+renderer_testing.Pod1.Name+"-"+renderer_testing.Pod1.Namespace, loopInterface))
	Expect(data.interfaceHandler.Interfaces).Should(HaveKeyWithValue("linux-loop-"+renderer_testing.Pod2.Name+"-"+renderer_testing.Pod2.Namespace, loopInterface))
	Expect(data.interfaceHandler.Interfaces).To(HaveLen(2))

	// check not used port forwarding (service port = backend port)
	Expect(data.ruleChainHandler.RuleChains).To(BeEmpty())

	// finally remove the service.
	removeService(data, service1)

	// check service removal on vpp-agent side
	assertEmptyVPPAgentConfiguration(data)

	// cleanup
	closeResources(data)
}

func TestServiceWithBackendPortForwarding(t *testing.T) {
	RegisterTestingT(t)
	retriever := configRetriever.NewMockConfigRetriever()
	data := initTest("TestServiceWithBackendPortForwarding", defaultConfig(), retriever, false)

	// setup service
	emptyResync(data)
	service1 := addServiceMetadata(data, defaultPort)
	pod1IP := addLocalPod(renderer_testing.Pod1, data, retriever)
	pod2IP := addLocalPod(renderer_testing.Pod2, data, retriever)
	addServiceEndpoints(renderer_testing.Pod1, pod1IP, renderer_testing.Pod2, pod2IP, differentBackendPort, data)

	// check port forwarding
	ruleChain1 := createRuleChain(linux_iptables.RuleChain_PREROUTING, service1.ClusterIp, defaultPort, differentBackendPort)
	ruleChain2 := createRuleChain(linux_iptables.RuleChain_OUTPUT, service1.ClusterIp, defaultPort, differentBackendPort)
	Expect(data.ruleChainHandler.RuleChains).To(ContainElement(ruleChain1))
	Expect(data.ruleChainHandler.RuleChains).To(ContainElement(ruleChain2))
	Expect(data.ruleChainHandler.RuleChains).To(HaveLen(2))

	// cleanup
	removeService(data, service1)
	//assertEmptyVPPAgentConfiguration(data)  //FIXME what triggers rule chain delete? service removal, pod removal or service endpoint removal does not (according to test run)
	closeResources(data)
}

func TestServiceWithHostLocalBackend(t *testing.T) {
	RegisterTestingT(t)
	retriever := configRetriever.NewMockConfigRetriever()
	data := initTest("TestServiceWithHostLocalBackend", defaultConfig(), retriever, false)

	// setup service
	emptyResync(data)
	service1 := addServiceMetadata(data, defaultPort)
	pod2IP := addLocalPod(renderer_testing.Pod2, data, retriever)
	addServiceEndpoints(renderer_testing.Pod1, mgmtIP, renderer_testing.Pod2, pod2IP, defaultPort, data)

	// check locasids/policy/steering on VPP-agent side
	assertLocalSid(data.IPAM.SidForServiceHostLocalsid(), renderer_testing.MainVrfID, data.IPAM.HostInterconnectIPInLinux(), hostInterIfName, data)
	assertLocalSid(data.IPAM.SidForServicePodLocalsid(pod2IP), renderer_testing.PodVrfID, pod2IP, renderer_testing.Pod2If, data)
	Expect(data.srv6Handler.LocalSids).To(HaveLen(2))
	bsid := assertPolicy(service1, [][]string{
		{data.IPAM.SidForServiceHostLocalsid().String()},
		{data.IPAM.SidForServicePodLocalsid(pod2IP).String()},
	}, data)
	assertSteering(service1, bsid, data)

	// cleanup
	removeService(data, service1)
	assertEmptyVPPAgentConfiguration(data)
	closeResources(data)
}

func TestServiceWithRemoteBackend(t *testing.T) {
	RegisterTestingT(t)
	retriever := configRetriever.NewMockConfigRetriever()
	data := initTest("TestServiceWithRemoteBackend", defaultConfig(), retriever, false)

	// setup service
	emptyResync(data)
	service1 := addServiceMetadata(data, defaultPort)
	pod2IP := addLocalPod(renderer_testing.Pod2, data, retriever)
	addServiceEndpointsInMultipleNodes(renderer_testing.Pod3, pod3IP, renderer_testing.WorkerLabel, renderer_testing.Pod2, pod2IP, renderer_testing.MasterLabel, defaultPort, data)

	// check locasids/policy/steering on VPP-agent side
	assertLocalSid(data.IPAM.SidForServicePodLocalsid(pod2IP), renderer_testing.PodVrfID, pod2IP, renderer_testing.Pod2If, data)
	Expect(data.srv6Handler.LocalSids).To(HaveLen(1))
	bsid := assertPolicy(service1, [][]string{
		{data.IPAM.SidForServiceNodeLocalsid(workerIP).String(), data.IPAM.SidForServicePodLocalsid(pod3IP).String()}, // path to pod on remote node
		{data.IPAM.SidForServicePodLocalsid(pod2IP).String()},
	}, data)
	assertSteering(service1, bsid, data)

	// cleanup
	removeService(data, service1)
	assertEmptyVPPAgentConfiguration(data)
	closeResources(data)
}

func assertEmptyVPPAgentConfiguration(data *data) {
	Expect(data.srv6Handler.LocalSids).To(BeEmpty())
	Expect(data.srv6Handler.Policies).To(BeEmpty())
	Expect(data.srv6Handler.Steerings).To(BeEmpty())
	Expect(data.routeHandler.Route).To(BeEmpty())
	Expect(data.ruleChainHandler.RuleChains).To(BeEmpty())
	for _, intf := range data.interfaceHandler.Interfaces {
		Expect(intf.IpAddresses).To(BeEmpty()) // empty configuration is equal with empty interface => interface without added service IP to loop addresses
	}
}

func assertLocalSid(sid net.IP, installationVrfId uint32, destIP net.IP, outgoingInterface string, data *data) *vpp_srv6.LocalSID {
	localsid := &vpp_srv6.LocalSID{
		Sid:               sid.String(),
		InstallationVrfId: installationVrfId,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
			OutgoingInterface: outgoingInterface,
			NextHop:           destIP.String(),
		}},
	}
	Expect(data.srv6Handler.LocalSids).To(ContainElement(localsid))
	return localsid
}

func assertPolicy(service1 *svcmodel.Service, segmentLists [][]string, data *data) string {
	sls := make([]*vpp_srv6.Policy_SegmentList, 0)
	for _, sl := range segmentLists {
		sls = append(sls, &vpp_srv6.Policy_SegmentList{
			Weight:   1,
			Segments: sl,
		})
	}
	bsid := data.IPAM.BsidForServicePolicy([]net.IP{net.ParseIP(service1.ClusterIp)}).String()
	policy := &vpp_srv6.Policy{
		Bsid:              bsid,
		InstallationVrfId: renderer_testing.MainVrfID,
		SrhEncapsulation:  true,
		SprayBehaviour:    false,
		SegmentLists:      sls,
	}
	Expect(data.srv6Handler.Policies).To(HaveLen(1))
	for _, retrieved := range data.srv6Handler.Policies { // only 1 policy
		Expect(retrieved.Bsid).To(Equal(policy.Bsid)) // order of segments in SegmentList flip sometimes = unstable test -> compare by attributes
		Expect(retrieved.SprayBehaviour).To(Equal(policy.SprayBehaviour))
		Expect(retrieved.SrhEncapsulation).To(Equal(policy.SrhEncapsulation))
		Expect(retrieved.InstallationVrfId).To(Equal(policy.InstallationVrfId))

		Expect(retrieved.SegmentLists).To(HaveLen(len(policy.SegmentLists)))
		for _, sl := range policy.SegmentLists {
			Expect(retrieved.SegmentLists).Should(ContainElement(sl))
		}
	}
	return bsid
}

func assertSteering(service1 *svcmodel.Service, bsid string, data *data) {
	steering := &vpp_srv6.Steering{
		Name: "forK8sService-" + service1.Namespace + "-" + service1.Name,
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				PrefixAddress:     service1.ClusterIp + "/128",
				InstallationVrfId: renderer_testing.PodVrfID,
			},
		},
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid,
		},
	}
	Expect(data.srv6Handler.Steerings).To(ContainElement(steering))
	Expect(data.srv6Handler.Steerings).To(HaveLen(1))
}

func closeResources(data *data) {
	Expect(data.SVCProcessor.Close()).To(BeNil())
	Expect(data.renderer.Close()).To(BeNil())
}

func removeService(data *data, service *svcmodel.Service) {
	updateEv := data.Datasync.DeleteEvent(svcmodel.Key(service.Name, service.Namespace))
	Expect(data.SVCProcessor.Update(updateEv)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
}

func createRuleChain(chainType linux_iptables.RuleChain_ChainType, serviceIP string, fromPort, toPort int32) *linux_iptables.RuleChain {
	rule := fmt.Sprintf("-d %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d",
		serviceIP+"/128", "tcp", "tcp", fromPort, toPort)
	return &linux_iptables.RuleChain{
		Name: fmt.Sprintf("port-forward--%s", chainType.String()),
		Namespace: &linux_namespace.NetNamespace{
			Type: linux_namespace.NetNamespace_FD,
		},
		Protocol:  linux_iptables.RuleChain_IPv6,
		Table:     linux_iptables.RuleChain_NAT,
		ChainType: chainType,
		Rules:     []string{rule},
	}
}

func addServiceEndpoints(pod1 podmodel.ID, pod1IP net.IP, pod2 podmodel.ID, pod2IP net.IP, port int32, data *data) {
	addServiceEndpointsInMultipleNodes(pod1, pod1IP, renderer_testing.MasterLabel, pod2, pod2IP, renderer_testing.MasterLabel, port, data)
}

func addServiceEndpointsInMultipleNodes(pod1 podmodel.ID, pod1IP net.IP, pod1Node string, pod2 podmodel.ID, pod2IP net.IP, pod2Node string, port int32, data *data) {
	eps1 := &epmodel.Endpoints{
		Name:      "service1",
		Namespace: renderer_testing.Namespace1,
		EndpointSubsets: []*epmodel.EndpointSubset{
			{
				Addresses: []*epmodel.EndpointSubset_EndpointAddress{
					{
						Ip:       pod1IP.String(),
						NodeName: pod1Node,
						TargetRef: &epmodel.ObjectReference{
							Kind:      "Pod",
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					{
						Ip:       pod2IP.String(),
						NodeName: pod2Node,
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
						Port:     port,
						Protocol: "TCP",
					},
				},
			},
		},
	}
	updateEv := data.Datasync.PutEvent(epmodel.Key(eps1.Name, eps1.Namespace), eps1)
	Expect(data.SVCProcessor.Update(updateEv)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
}

func addLocalPod(pod podmodel.ID, data *data, retriever *configRetriever.MockConfigRetriever) net.IP {
	// add pod
	updateEv := data.PodManager.AddPod(&podmanager.LocalPod{ID: pod})
	Expect(data.SVCProcessor.Update(updateEv)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())

	// allocate IPs for new pods
	podIP, err := data.IPAM.AllocatePodIP(pod, "", "")
	Expect(err).To(BeNil())

	// add mock loop interfaces to pods (SRv6 renderer updates their ip addresses)
	retriever.AddConfig(linux_interfaces.InterfaceKey(data.IPNet.GetPodLoopIfName(pod.Namespace, pod.Name)), &linux_interfaces.Interface{
		IpAddresses: []string{},
	})
	return podIP
}

func addServiceMetadata(data *data, port int32) *svcmodel.Service {
	service1 := &svcmodel.Service{
		Name:                  "service1",
		Namespace:             renderer_testing.Namespace1,
		ServiceType:           "ClusterIP",
		ExternalTrafficPolicy: "Cluster",
		ClusterIp:             "2096::eef9",
		ExternalIps:           []string{},
		Port: []*svcmodel.Service_ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     port,
				NodePort: 0,
			},
		},
	}
	updateEv1 := data.Datasync.PutEvent(svcmodel.Key(service1.Name, service1.Namespace), service1)
	Expect(data.SVCProcessor.Update(updateEv1)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
	return service1
}

func emptyResync(data *data) {
	resyncEv, _ := data.Datasync.ResyncEvent(keyPrefixes...)
	Expect(data.SVCProcessor.Resync(resyncEv.KubeState)).To(BeNil())
	Expect(data.Txn.Commit()).To(BeNil())
}

func initTest(testName string, config *config.Config, configRetriever controller.ConfigRetriever, snatOnly bool, withoutMasterIPs ...bool) *data {
	fixture := renderer_testing.NewFixture(testName, config, newMockIPNet(), nodeIPAddr, nodeIPNet, mgmtIP, withoutMasterIPs...)
	data := &data{Fixture: fixture}

	// transactions
	data.srv6Handler = handler.NewSRv6Mock(data.Logger)
	data.routeHandler = handler.NewRouteMock(data.Logger)
	data.interfaceHandler = handler.NewInterfaceMock(data.Logger)
	data.ruleChainHandler = handler.NewRuleChainMock(data.Logger)
	vppAgentMock := vppagent.NewMockVPPAgent(data.srv6Handler, data.routeHandler, data.interfaceHandler, data.ruleChainHandler)
	data.txnTracker = localclient.NewTxnTracker(vppAgentMock.ApplyTxn)

	// Prepare SRv6 Renderer.
	data.renderer = &srv6.Renderer{
		Deps: srv6.Deps{
			Log:              data.Logger,
			ContivConf:       data.ContivConf,
			NodeSync:         data.NodeSync,
			PodManager:       data.PodManager,
			IPAM:             data.IPAM,
			IPNet:            data.IPNet,
			ConfigRetriever:  configRetriever,
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
	ipNet.SetHostInterconnectIfName(hostInterIfName)
	ipNet.SetPodIfName(renderer_testing.Pod1, renderer_testing.Pod1If)
	ipNet.SetPodIfName(renderer_testing.Pod2, renderer_testing.Pod2If)
	ipNet.SetHostIPs([]net.IP{mgmtIP})
	return ipNet
}

func defaultConfig() *config.Config {
	return &config.Config{
		NatExternalTraffic: true,
		RoutingConfig: config.RoutingConfig{
			NodeToNodeTransport: contivconf.SRv6Transport,
			UseSRv6ForServices:  true,
			MainVRFID:           renderer_testing.MainVrfID,
			PodVRFID:            renderer_testing.PodVrfID,
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
		IPAMConfig: config.IPAMConfig{
			NodeInterconnectDHCP:          false,
			NodeInterconnectCIDR:          "fe10:f00d::/90",
			PodSubnetCIDR:                 "2001::/48",
			PodSubnetOneNodePrefixLen:     64,
			VPPHostSubnetCIDR:             "2002::/64",
			VPPHostSubnetOneNodePrefixLen: 112,
			VxlanCIDR:                     "2005::/112",
			ServiceCIDR:                   "2096::/110",
		},
	}
}
