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
	"fmt"
	"net"
	"sync"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	// prefix for logical name of the Linux loopback interface in a pod
	podLinuxLoopLogicalNamePrefix = "linux-loop"
)

// MockIPNet is a mock for the ipnet Plugin.
type MockIPNet struct {
	sync.Mutex

	podIf                      map[podmodel.ID]string
	networkToVRFID             map[string]uint32
	podInterfaceToNetwork      map[string]string
	externalInterfaceToNetwork map[string]string
	hostIPs                    []net.IP
	nodeIP                     *net.IPNet
	hostInterconnect           string
	vxlanBVIIfName             string
	vniID                      uint32
}

// NewMockIPNet is a constructor for MockIPNet.
func NewMockIPNet() *MockIPNet {
	return &MockIPNet{
		podIf:                      make(map[podmodel.ID]string),
		networkToVRFID:             make(map[string]uint32),
		podInterfaceToNetwork:      make(map[string]string),
		externalInterfaceToNetwork: make(map[string]string),
	}
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

// SetGetPodCustomIfNetworkName sets network name that pod custom interface belongs to.
func (mn *MockIPNet) SetGetPodCustomIfNetworkName(podID podmodel.ID, ifName string, networkName string) {
	mn.podInterfaceToNetwork[fmt.Sprintf("%s/%s", podID.String(), ifName)] = networkName
}

// SetGetExternalIfNetworkName sets network name that external interface belongs to.
func (mn *MockIPNet) SetGetExternalIfNetworkName(ifName string, networkName string) {
	mn.externalInterfaceToNetwork[ifName] = networkName
}

// SetNetworkVrfID sets VRF table ID to network name that it should belong to.
func (mn *MockIPNet) SetNetworkVrfID(networkName string, vrfID uint32) {
	mn.networkToVRFID[networkName] = vrfID
}

// GetPodIfNames returns pod's interface name as set previously using SetPodIfName.
func (mn *MockIPNet) GetPodIfNames(podNamespace string, podName string) (vppIfName, linuxIfName,
	loopIfName string, exists bool) {
	vppIfName, exists = mn.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return vppIfName, "", mn.GetPodLoopIfName(podNamespace, podName), exists
}

// GetPodCustomIfNames looks up logical interface name that corresponds to the custom interface
// with specified name and type associated with the given local pod name + namespace.
func (mn *MockIPNet) GetPodCustomIfNames(podNamespace, podName, customIfName string) (ifName string,
	linuxIfName string, exists bool) {
	//return "", linuxIfName, false
	return customIfName, customIfName, true
}

// GetExternalIfName returns logical name that corresponds to the specified external interface name and VLAN ID.
func (mn *MockIPNet) GetExternalIfName(extIfName string, vlan uint32) (ifName string) {
	if vlan == 0 {
		return extIfName
	}
	return fmt.Sprintf("%s.%d", extIfName, vlan)
}

// GetPodLoopIfName computes logical name of loop interface for given pod
func (mn *MockIPNet) GetPodLoopIfName(podNamespace string, podName string) string {
	return podLinuxLoopLogicalNamePrefix + "-" + podName + "-" + podNamespace
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

// GetOrAllocateVxlanVNI returns the allocated VXLAN VNI number for the given network.
// Allocates a new VNI if not already allocated.
func (mn *MockIPNet) GetOrAllocateVxlanVNI(networkName string) (vni uint32, err error) {
	return mn.vniID, err
}

// ReleaseVxlanVNI releases the allocated VXLAN VNI number for the given network.
func (mn *MockIPNet) ReleaseVxlanVNI(networkName string) (err error) {
	return nil
}

// GetOrAllocateVrfID returns the allocated VRF ID number for the given network.
// Allocates a new VRF ID if not already allocated.
func (mn *MockIPNet) GetOrAllocateVrfID(networkName string) (vrf uint32, err error) {
	return mn.networkToVRFID[networkName], err
}

// ReleaseVrfID releases the allocated VRF ID number for the given network.
func (mn *MockIPNet) ReleaseVrfID(networkName string) (err error) {
	return nil
}

// GetPodCustomIfNetworkName returns the name of custom network which should contain given
// pod custom interface or error otherwise. This supports both type of pods, remote and local
func (mn *MockIPNet) GetPodCustomIfNetworkName(podID podmodel.ID, ifName string) (string, error) {
	return mn.podInterfaceToNetwork[fmt.Sprintf("%s/%s", podID.String(), ifName)], nil
}

// GetExternalIfNetworkName returns the name of custom network which should contain given
// external interface or error otherwise.
func (mn *MockIPNet) GetExternalIfNetworkName(ifName string) (string, error) {
	return mn.externalInterfaceToNetwork[ifName], nil
}
