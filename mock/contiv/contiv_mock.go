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

package contiv

import (
	"net"
	"sync"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging/logrus"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	sync.Mutex

	podIf              map[podmodel.ID]string
	podAppNs           map[podmodel.ID]uint32
	podNetwork         *net.IPNet
	tcpStackDisabled   bool
	stnMode            bool
	natExternalTraffic bool
	natLoopbackIP      net.IP
	nodeIP             string
	nodeIPsubs         []chan string
	podPreRemovalHooks []contiv.PodActionHook
	mainPhysIf         string
	otherPhysIfs       []string
	hostInterconnect   string
	vxlanBVIIfName     string
	gwIP               net.IP
	containerIndex     *containeridx.ConfigIndex
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	ci := containeridx.NewConfigIndex(logrus.DefaultLogger(), "test", "title", nil)
	return &MockContiv{
		podIf:          make(map[podmodel.ID]string),
		podAppNs:       make(map[podmodel.ID]uint32),
		containerIndex: ci,
	}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mc *MockContiv) SetPodIfName(pod podmodel.ID, ifName string) {
	mc.podIf[pod] = ifName
}

// SetPodAppNsIndex allows to create a fake association between a pod and a VPP
// application namespace index.
func (mc *MockContiv) SetPodAppNsIndex(pod podmodel.ID, nsIndex uint32) {
	mc.podAppNs[pod] = nsIndex
}

// SetPodNetwork allows to set what tests will assume as the pod subnet
// for the current host node.
func (mc *MockContiv) SetPodNetwork(podNetwork string) {
	_, mc.podNetwork, _ = net.ParseCIDR(podNetwork)
}

// SetContainerIndex allows to set index that contains configured containers
func (mc *MockContiv) SetContainerIndex(ci *containeridx.ConfigIndex) {
	mc.containerIndex = ci
}

// SetTCPStackDisabled allows to set flag denoting if the tcpStack is disabled or not.
func (mc *MockContiv) SetTCPStackDisabled(tcpStackDisabled bool) {
	mc.tcpStackDisabled = tcpStackDisabled
}

// SetSTNMode allows to set flag denoting if the STN is used or not.
func (mc *MockContiv) SetSTNMode(stnMode bool) {
	mc.stnMode = stnMode
}

// SetNodeIP allows to set what tests will assume the node IP is.
func (mc *MockContiv) SetNodeIP(nodeIP string) {
	mc.Lock()
	defer mc.Unlock()

	mc.nodeIP = nodeIP

	for _, sub := range mc.nodeIPsubs {
		select {
		case sub <- nodeIP:
		default:
			// skip subscribers who are not ready to receive notification
		}
	}
}

// SetMainPhysicalIfName allows to set what tests will assume the name of the main
// physical interface is.
func (mc *MockContiv) SetMainPhysicalIfName(ifName string) {
	mc.mainPhysIf = ifName
}

// SetOtherPhysicalIfNames allows to set what tests will assume the list of other physical
// interface names is.
func (mc *MockContiv) SetOtherPhysicalIfNames(ifs []string) {
	mc.otherPhysIfs = ifs
}

// SetHostInterconnectIfName allows to set what tests will assume the name of the host-interconnect
// interface is.
func (mc *MockContiv) SetHostInterconnectIfName(ifName string) {
	mc.hostInterconnect = ifName
}

// SetVxlanBVIIfName allows to set what tests will assume the name of the VXLAN BVI interface is.
func (mc *MockContiv) SetVxlanBVIIfName(ifName string) {
	mc.vxlanBVIIfName = ifName
}

// SetDefaultGatewayIP allows to set what tests will assume the default gateway IP is (can be nil).
func (mc *MockContiv) SetDefaultGatewayIP(gwIP net.IP) {
	mc.gwIP = gwIP
}

// SetNatExternalTraffic allows to set what tests will assume the state of SNAT is.
func (mc *MockContiv) SetNatExternalTraffic(natExternalTraffic bool) {
	mc.natExternalTraffic = natExternalTraffic
}

// SetNatLoopbackIP allows to set what tests will assume the NAT loopback IP is.
func (mc *MockContiv) SetNatLoopbackIP(natLoopIP string) {
	mc.natLoopbackIP = net.ParseIP(natLoopIP)
}

// DeletingPod allows to simulate event of deleting pod - all registered pre-removal hooks
// are called.
func (mc *MockContiv) DeletingPod(podID podmodel.ID) {
	for _, hook := range mc.podPreRemovalHooks {
		hook(podID.Namespace, podID.Name)
	}
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mc *MockContiv) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mc.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
}

// GetNsIndex returns pod's namespace index as set previously using SetPodNsIndex.
func (mc *MockContiv) GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool) {
	nsIndex, exists = mc.podAppNs[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return nsIndex, exists
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (mc *MockContiv) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	for podID, name := range mc.podIf {
		if name == ifname {
			return podID.Namespace, podID.Name, true
		}
	}
	return "", "", false
}

// GetPodByAppNsIndex looks up podName and podNamespace that is associated with the VPP application namespace.
func (mc *MockContiv) GetPodByAppNsIndex(nsIndex uint32) (podNamespace string, podName string, exists bool) {
	for podID, index := range mc.podAppNs {
		if index == nsIndex {
			return podID.Namespace, podID.Name, true
		}
	}
	return "", "", false
}

// GetContainerIndex returns the index of configured containers/pods
func (mc *MockContiv) GetContainerIndex() containeridx.Reader {
	return mc.containerIndex
}

// GetPodNetwork returns static subnet constant that should represent pod subnet for current host node
func (mc *MockContiv) GetPodNetwork() (podNetwork *net.IPNet) {
	return mc.podNetwork
}

// IsTCPstackDisabled returns true if the tcp stack is disabled and only veths are configured
func (mc *MockContiv) IsTCPstackDisabled() bool {
	return mc.tcpStackDisabled
}

// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
func (mc *MockContiv) InSTNMode() bool {
	return mc.stnMode
}

// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
// with node IP before being sent out from the node.
func (mc *MockContiv) NatExternalTraffic() bool {
	return mc.natExternalTraffic
}

// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (mc *MockContiv) GetNatLoopbackIP() net.IP {
	return mc.natLoopbackIP
}

// GetNodeIP returns the IP+network address of this node.
func (mc *MockContiv) GetNodeIP() (net.IP, *net.IPNet) {
	mc.Lock()
	defer mc.Unlock()

	nodeIP, nodeNet, _ := net.ParseCIDR(mc.nodeIP)
	return nodeIP, nodeNet
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (mc *MockContiv) WatchNodeIP(subscriber chan string) {
	mc.Lock()
	defer mc.Unlock()

	mc.nodeIPsubs = append(mc.nodeIPsubs, subscriber)
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (mc *MockContiv) GetMainPhysicalIfName() string {
	return mc.mainPhysIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (mc *MockContiv) GetOtherPhysicalIfNames() []string {
	return mc.otherPhysIfs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (mc *MockContiv) GetHostInterconnectIfName() string {
	return mc.hostInterconnect
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (mc *MockContiv) GetVxlanBVIIfName() string {
	return mc.vxlanBVIIfName
}

// GetDefaultGatewayIP returns the IP address of the default gateway for external traffic.
// If the default GW is not configured, the function returns nil.
func (mc *MockContiv) GetDefaultGatewayIP() net.IP {
	return mc.gwIP
}

// RegisterPodPreRemovalHook allows to register callback that will be run for each
// pod immediately before its removal.
func (mc *MockContiv) RegisterPodPreRemovalHook(hook contiv.PodActionHook) {
	mc.Lock()
	defer mc.Unlock()

	mc.podPreRemovalHooks = append(mc.podPreRemovalHooks, hook)
}
