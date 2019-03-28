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

package ipnet

import (
	"net"
	"sync"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockIPNet is a mock for the ipnet Plugin.
type MockIPNet struct {
	sync.Mutex

	podIf            map[podmodel.ID]string
	hostIPs          []net.IP
	nodeIP           *net.IPNet
	hostInterconnect string
	vxlanBVIIfName   string
}

// NewMockIPNet is a constructor for MockIPNet.
func NewMockIPNet() *MockIPNet {
	return &MockIPNet{podIf: make(map[podmodel.ID]string)}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mn *MockIPNet) SetPodIfName(pod podmodel.ID, ifName string) {
	mn.podIf[pod] = ifName
}

// SetNodeIP allows to set what tests will assume the node IP is.
func (mn *MockIPNet) SetNodeIP(nodeIP *net.IPNet) {
	mn.Lock()
	defer mn.Unlock()

	mn.nodeIP = nodeIP
}

// SetHostInterconnectIfName allows to set what tests will assume the name of the host-interconnect
// interface is.
func (mn *MockIPNet) SetHostInterconnectIfName(ifName string) {
	mn.hostInterconnect = ifName
}

// SetVxlanBVIIfName allows to set what tests will assume the name of the VXLAN BVI interface is.
func (mn *MockIPNet) SetVxlanBVIIfName(ifName string) {
	mn.vxlanBVIIfName = ifName
}

// SetHostIPs sets IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPNet) SetHostIPs(ips []net.IP) {
	mn.hostIPs = ips
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mn *MockIPNet) GetPodIfNames(podNamespace string, podName string) (vppIfName, linuxIfName, loopIfName string, exists bool) {
	vppIfName, exists = mn.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return vppIfName, "", "", exists
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (mn *MockIPNet) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	for podID, name := range mn.podIf {
		if name == ifname {
			return podID.Namespace, podID.Name, true
		}
	}
	return "", "", false
}

// GetNodeIP returns the IP+network address of this node.
func (mn *MockIPNet) GetNodeIP() (net.IP, *net.IPNet) {
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
func (mn *MockIPNet) GetHostInterconnectIfName() string {
	return mn.hostInterconnect
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (mn *MockIPNet) GetVxlanBVIIfName() string {
	return mn.vxlanBVIIfName
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (mn *MockIPNet) GetHostIPs() []net.IP {
	return mn.hostIPs
}
