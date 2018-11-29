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

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	sync.Mutex

	podIf                       map[podmodel.ID]string
	podSubnet                   *net.IPNet
	podSubnetThisNode           *net.IPNet
	hostIPs                     []net.IP
	mainVrfId                   uint32
	podVrfId                    uint32
	tcpStackDisabled            bool
	stnMode                     bool
	natExternalTraffic          bool
	cleanupIdleNATSessions      bool
	tcpNATSessionTimeout        uint32
	otherNATSessionTimeout      uint32
	disableNATVirtualReassembly bool
	serviceLocalEndpointWeight  uint8
	natLoopbackIP               net.IP
	nodeIP                      *net.IPNet
	mainPhysIf                  string
	otherPhysIfs                []string
	hostInterconnect            string
	vxlanBVIIfName              string
	defaultIfName               string
	defaultIfIP                 net.IP
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	return &MockContiv{
		podIf:                      make(map[podmodel.ID]string),
		serviceLocalEndpointWeight: 1,
	}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mc *MockContiv) SetPodIfName(pod podmodel.ID, ifName string) {
	mc.podIf[pod] = ifName
}

// SetPodNetwork allows to set what tests will assume the pod subnet is
// (same for this node as for the entire cluster for simplicity).
func (mc *MockContiv) SetPodSubnet(podSubnet string) {
	_, mc.podSubnet, _ = net.ParseCIDR(podSubnet)
	_, mc.podSubnetThisNode, _ = net.ParseCIDR(podSubnet)
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
func (mc *MockContiv) SetNodeIP(nodeIP *net.IPNet) {
	mc.Lock()
	defer mc.Unlock()

	mc.nodeIP = nodeIP
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

// SetDefaultInterface allows to set what tests will assume the default interface IP
// and name are (both can be zero values).
func (mc *MockContiv) SetDefaultInterface(ifName string, ifIP net.IP) {
	mc.defaultIfName = ifName
	mc.defaultIfIP = ifIP
}

// SetNatExternalTraffic allows to set what tests will assume the state of SNAT is.
func (mc *MockContiv) SetNatExternalTraffic(natExternalTraffic bool) {
	mc.natExternalTraffic = natExternalTraffic
}

// ServiceLocalEndpointWeight allows to set what tests will assume the weight for load-balancing
// of locally deployed service endpoints is.
func (mc *MockContiv) SetServiceLocalEndpointWeight(weight uint8) {
	mc.serviceLocalEndpointWeight = weight
}

// SetNATVirtualReassembly allows to set flag denoting if the NAT Virtual reassembly
// is disabled or not.
func (mc *MockContiv) SetNATVirtualReassembly(disable bool) {
	mc.disableNATVirtualReassembly = disable
}

// SetNatLoopbackIP allows to set what tests will assume the NAT loopback IP is.
func (mc *MockContiv) SetNatLoopbackIP(natLoopIP string) {
	mc.natLoopbackIP = net.ParseIP(natLoopIP)
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mc *MockContiv) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mc.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
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

// GetPodSubnetThisNode returns static subnet constant that should represent pod subnet for current host node
func (mc *MockContiv) GetPodSubnetThisNode() (podNetwork *net.IPNet) {
	return mc.podSubnetThisNode
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

// GetServiceLocalEndpointWeight returns the load-balancing weight assigned to locally deployed service endpoints.
func (mc *MockContiv) GetServiceLocalEndpointWeight() uint8 {
	return mc.serviceLocalEndpointWeight
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

	if mc.nodeIP == nil {
		return net.IP{}, nil
	}

	return mc.nodeIP.IP, &net.IPNet{
		IP:   mc.nodeIP.IP.Mask(mc.nodeIP.Mask),
		Mask: mc.nodeIP.Mask,
	}
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

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (mc *MockContiv) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	return mc.defaultIfName, mc.defaultIfIP
}

// CleanupIdleNATSessions returns true if cleanup of idle NAT sessions is enabled.
func (mc *MockContiv) CleanupIdleNATSessions() bool {
	return mc.cleanupIdleNATSessions
}

// GetTCPNATSessionTimeout returns NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (mc *MockContiv) GetTCPNATSessionTimeout() uint32 {
	return mc.tcpNATSessionTimeout
}

// GetOtherNATSessionTimeout returns NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (mc *MockContiv) GetOtherNATSessionTimeout() uint32 {
	return mc.otherNATSessionTimeout
}

// DisableNATVirtualReassembly returns true if fragmented packets should be dropped by NAT.
func (mc *MockContiv) DisableNATVirtualReassembly() bool {
	return mc.disableNATVirtualReassembly
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (mc *MockContiv) GetPodSubnet() *net.IPNet {
	return mc.podSubnet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (mc *MockContiv) GetHostIPs() []net.IP {
	return mc.hostIPs
}

// SetHostIPs sets IP addresses of this node present in the host network namespace (Linux).
func (mc *MockContiv) SetHostIPs(ips []net.IP) {
	mc.hostIPs = ips
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (mc *MockContiv) GetMainVrfID() uint32 {
	return mc.mainVrfId
}

// SetMainVrfID sets the ID of the main network connectivity VRF.
func (mc *MockContiv) SetMainVrfID(id uint32) {
	mc.mainVrfId = id
}

// GetPodVrfID returns the ID of the POD VRF.
func (mc *MockContiv) GetPodVrfID() uint32 {
	return mc.podVrfId
}

// SetPodVrfID sets the ID of the POD VRF.
func (mc *MockContiv) SetPodVrfID(id uint32) {
	mc.podVrfId = id
}
