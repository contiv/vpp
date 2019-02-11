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

package ipam

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// API defines methods provided by IPAM for use by other plugins.
type API interface {
	// NodeIPAddress computes IP address of the node based on the provided node ID.
	NodeIPAddress(nodeID uint32) (net.IP, *net.IPNet, error)

	// VxlanIPAddress computes IP address of the VXLAN interface based on the provided
	// node ID.
	VxlanIPAddress(nodeID uint32) (net.IP, *net.IPNet, error)

	// HostInterconnectIPInVPP provides the IPv4 address for the VPP-end of the VPP-to-host
	// interconnect.
	HostInterconnectIPInVPP() net.IP

	// HostInterconnectIPInLinux provides the IPv4 address of the host(Linux)-end
	// of the VPP-to-host interconnect.
	HostInterconnectIPInLinux() net.IP

	// HostInterconnectSubnetThisNode returns vswitch network used to connect
	// VPP to its host Linux Stack on this node.
	HostInterconnectSubnetThisNode() *net.IPNet

	// HostInterconnectSubnetAllNodes returns vswitch base subnet used to connect
	// VPP to its host Linux Stack on all nodes.
	HostInterconnectSubnetAllNodes() *net.IPNet

	// HostInterconnectSubnetOtherNode returns VPP-host network of another node
	// identified by nodeID.
	HostInterconnectSubnetOtherNode(nodeID uint32) (*net.IPNet, error)

	// PodSubnetAllNodes returns POD subnet that is a base subnet for all PODs
	// of all nodes.
	PodSubnetAllNodes() *net.IPNet

	// PodSubnetThisNode returns POD network for the current node
	// (given by nodeID allocated for this node).
	PodSubnetThisNode() *net.IPNet

	// PodSubnetOtherNode returns the POD network of another node identified by nodeID.
	PodSubnetOtherNode(nodeID uint32) (*net.IPNet, error)

	// ServiceNetwork returns range allocated for services.
	ServiceNetwork() *net.IPNet

	// PodGatewayIP returns gateway IP address of the POD subnet of this node.
	PodGatewayIP() net.IP

	// NatLoopbackIP returns the IP address of a virtual loopback, used to route
	// traffic between clients and services via VPP even if the source and destination
	// are the same IP addresses and would otherwise be routed locally.
	NatLoopbackIP() net.IP

	// AllocatePodIP tries to allocate IP address for the given pod.
	AllocatePodIP(podID podmodel.ID, ipamType string, ipamData string) (net.IP, error)

	// GetPodIP returns the allocated pod IP, together with the mask.
	// Returns nil if the pod does not have allocated IP address.
	GetPodIP(podID podmodel.ID) *net.IPNet

	// ReleasePodIP releases the pod IP address making it available for new PODs.
	ReleasePodIP(podID podmodel.ID) error
}

// PodCIDRChange is triggered when CIDR for PODs on the current node changes.
type PodCIDRChange struct {
	LocalPodCIDR *net.IPNet
}

// GetName returns name of the PodCIDRChange event.
func (ev *PodCIDRChange) GetName() string {
	return "Pod CIDR Change"
}

// String describes PodCIDRChange event.
func (ev *PodCIDRChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* LocalPodCIDR: %v\n"+
		ev.GetName(), ev.LocalPodCIDR)
}

// Method is UpstreamResync.
func (ev *PodCIDRChange) Method() controller.EventMethodType {
	return controller.UpstreamResync
}

// IsBlocking returns false.
func (ev *PodCIDRChange) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *PodCIDRChange) Done(error) {
	return
}
