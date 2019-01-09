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

	podIf             map[podmodel.ID]string
	hostIPs           []net.IP
	nodeIP            *net.IPNet
	podSubnetThisNode *net.IPNet
	hostInterconnect  string
	vxlanBVIIfName    string
}

// NewMockIPv4Net is a constructor for MockIPv4Net.
func NewMockIPv4Net() *MockIPv4Net {
	return &MockIPv4Net{podIf: make(map[podmodel.ID]string)}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mn *MockIPv4Net) SetPodIfName(pod podmodel.ID, ifName string) {
	mn.podIf[pod] = ifName
}

// SetNodeIP allows to set what tests will assume the node IP is.
func (mn *MockIPv4Net) SetNodeIP(nodeIP *net.IPNet) {
	mn.Lock()
	defer mn.Unlock()

	mn.nodeIP = nodeIP
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

// SetHostIPs sets IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPv4Net) SetHostIPs(ips []net.IP) {
	mn.hostIPs = ips
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

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPv4Net) GetHostIPs() []net.IP {
	return mn.hostIPs
}

// GetPodSubnetThisNode returns POD network for the current node
// (given by nodeID allocated for this node).
func (mn *MockIPv4Net) GetPodSubnetThisNode() *net.IPNet {
	return mn.podSubnetThisNode
}
