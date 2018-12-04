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

package ipv4net

import (
	"net"
	"sync"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockIPv4Net is a mock for the ipv4net Plugin.
type MockIPv4Net struct {
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
	natLoopbackIP               net.IP
	nodeIP                      *net.IPNet
	mainPhysIf                  string
	otherPhysIfs                []string
	hostInterconnect            string
	vxlanBVIIfName              string
	defaultIfName               string
	defaultIfIP                 net.IP
}

// NewMockIPv4Net is a constructor for MockIPv4Net.
func NewMockIPv4Net() *MockIPv4Net {
	return &MockIPv4Net{podIf: make(map[podmodel.ID]string),
	}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mn *MockIPv4Net) SetPodIfName(pod podmodel.ID, ifName string) {
	mn.podIf[pod] = ifName
}

// SetPodNetwork allows to set what tests will assume the pod subnet is
// (same for this node as for the entire cluster for simplicity).
func (mn *MockIPv4Net) SetPodSubnet(podSubnet string) {
	_, mn.podSubnet, _ = net.ParseCIDR(podSubnet)
	_, mn.podSubnetThisNode, _ = net.ParseCIDR(podSubnet)
}

// SetTCPStackDisabled allows to set flag denoting if the tcpStack is disabled or not.
func (mn *MockIPv4Net) SetTCPStackDisabled(tcpStackDisabled bool) {
	mn.tcpStackDisabled = tcpStackDisabled
}

// SetSTNMode allows to set flag denoting if the STN is used or not.
func (mn *MockIPv4Net) SetSTNMode(stnMode bool) {
	mn.stnMode = stnMode
}

// SetNodeIP allows to set what tests will assume the node IP is.
func (mn *MockIPv4Net) SetNodeIP(nodeIP *net.IPNet) {
	mn.Lock()
	defer mn.Unlock()

	mn.nodeIP = nodeIP
}

// SetMainPhysicalIfName allows to set what tests will assume the name of the main
// physical interface is.
func (mn *MockIPv4Net) SetMainPhysicalIfName(ifName string) {
	mn.mainPhysIf = ifName
}

// SetOtherPhysicalIfNames allows to set what tests will assume the list of other physical
// interface names is.
func (mn *MockIPv4Net) SetOtherPhysicalIfNames(ifs []string) {
	mn.otherPhysIfs = ifs
}

// SetHostInterconnectIfName allows to set what tests will assume the name of the host-interconnect
// interface is.
func (mn *MockIPv4Net) SetHostInterconnectIfName(ifName string) {
	mn.hostInterconnect = ifName
}

// SetVxlanBVIIfName allows to set what tests will assume the name of the VXLAN BVI interface is.
func (mn *MockIPv4Net) SetVxlanBVIIfName(ifName string) {
	mn.vxlanBVIIfName = ifName
}

// SetDefaultInterface allows to set what tests will assume the default interface IP
// and name are (both can be zero values).
func (mn *MockIPv4Net) SetDefaultInterface(ifName string, ifIP net.IP) {
	mn.defaultIfName = ifName
	mn.defaultIfIP = ifIP
}

// SetNatExternalTraffic allows to set what tests will assume the state of SNAT is.
func (mn *MockIPv4Net) SetNatExternalTraffic(natExternalTraffic bool) {
	mn.natExternalTraffic = natExternalTraffic
}

// SetNatLoopbackIP allows to set what tests will assume the NAT loopback IP is.
func (mn *MockIPv4Net) SetNatLoopbackIP(natLoopIP string) {
	mn.natLoopbackIP = net.ParseIP(natLoopIP)
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mn *MockIPv4Net) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mn.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (mn *MockIPv4Net) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	for podID, name := range mn.podIf {
		if name == ifname {
			return podID.Namespace, podID.Name, true
		}
	}
	return "", "", false
}

// GetPodSubnetThisNode returns static subnet constant that should represent pod subnet for current host node
func (mn *MockIPv4Net) GetPodSubnetThisNode() (podNetwork *net.IPNet) {
	return mn.podSubnetThisNode
}

// IsTCPstackDisabled returns true if the tcp stack is disabled and only veths are configured
func (mn *MockIPv4Net) IsTCPstackDisabled() bool {
	return mn.tcpStackDisabled
}

// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
func (mn *MockIPv4Net) InSTNMode() bool {
	return mn.stnMode
}

// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
// with node IP before being sent out from the node.
func (mn *MockIPv4Net) NatExternalTraffic() bool {
	return mn.natExternalTraffic
}

// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (mn *MockIPv4Net) GetNatLoopbackIP() net.IP {
	return mn.natLoopbackIP
}

// GetNodeIP returns the IP+network address of this node.
func (mn *MockIPv4Net) GetNodeIP() (net.IP, *net.IPNet) {
	mn.Lock()
	defer mn.Unlock()

	if mn.nodeIP == nil {
		return net.IP{}, nil
	}

	return mn.nodeIP.IP, &net.IPNet{
		IP:   mn.nodeIP.IP.Mask(mn.nodeIP.Mask),
		Mask: mn.nodeIP.Mask,
	}
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (mn *MockIPv4Net) GetMainPhysicalIfName() string {
	return mn.mainPhysIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (mn *MockIPv4Net) GetOtherPhysicalIfNames() []string {
	return mn.otherPhysIfs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (mn *MockIPv4Net) GetHostInterconnectIfName() string {
	return mn.hostInterconnect
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (mn *MockIPv4Net) GetVxlanBVIIfName() string {
	return mn.vxlanBVIIfName
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (mn *MockIPv4Net) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	return mn.defaultIfName, mn.defaultIfIP
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (mn *MockIPv4Net) GetPodSubnet() *net.IPNet {
	return mn.podSubnet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPv4Net) GetHostIPs() []net.IP {
	return mn.hostIPs
}

// SetHostIPs sets IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPv4Net) SetHostIPs(ips []net.IP) {
	mn.hostIPs = ips
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (mn *MockIPv4Net) GetMainVrfID() uint32 {
	return mn.mainVrfId
}

// SetMainVrfID sets the ID of the main network connectivity VRF.
func (mn *MockIPv4Net) SetMainVrfID(id uint32) {
	mn.mainVrfId = id
}

// GetPodVrfID returns the ID of the POD VRF.
func (mn *MockIPv4Net) GetPodVrfID() uint32 {
	return mn.podVrfId
}

// SetPodVrfID sets the ID of the POD VRF.
func (mn *MockIPv4Net) SetPodVrfID(id uint32) {
	mn.podVrfId = id
}
