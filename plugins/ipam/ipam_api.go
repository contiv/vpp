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

	"github.com/contiv/vpp/plugins/contivconf/config"
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

	// NodeIDFromPodIP returns node ID from provided POD IP address.
	NodeIDFromPodIP(podIP net.IP) (uint32, error)

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

	// AllocatePodCustomIfIP tries to allocate custom IP address for the given interface of a given pod.
	AllocatePodCustomIfIP(podID podmodel.ID, ifName, network string, isServiceEndpoint bool) (net.IP, error)

	// GetPodCustomIfIP returns the allocated custom interface pod IP, together with the mask.
	// Returns nil if the pod does not have allocated custom interface IP address.
	GetPodCustomIfIP(podID podmodel.ID, ifName, network string) *net.IPNet

	// GetPodFromIP returns the pod information related to the allocated pod IP.
	// found is false if the provided IP address has not been allocated to any local pod.
	GetPodFromIP(podIP net.IP) (podID podmodel.ID, found bool)

	// ReleasePodIPs releases all pod IP addresses making them available for new PODs.
	ReleasePodIPs(podID podmodel.ID) error

	// AllocateVxlanVNI tries to allocate a free VNI for the VXLAN with given name.
	// If the given VXLAN already has a VNI allocated, returns the existing allocation.
	AllocateVxlanVNI(vxlanName string) (vni uint32, err error)

	// GetVxlanVNI returns an existing VNI allocation for the VXLAN with given name.
	// found is false if no allocation for the given VXLAN name exists.
	GetVxlanVNI(vxlanName string) (vni uint32, found bool)

	// ReleaseVxlanVNI releases VNI allocated for the VXLAN with given name.
	ReleaseVxlanVNI(vxlanName string) (err error)

	// BsidForServicePolicy creates a valid SRv6 binding SID for given k8s service IP addresses <serviceIPs>. This sid
	// should be used only for k8s service policy
	BsidForServicePolicy(serviceIPs []net.IP) net.IP

	// SidForServiceHostLocalsid creates a valid SRv6 SID for service locasid leading to host on the current node. Created SID
	// doesn't depend on anything and is the same for each node, because there is only one way how to get to host in each
	// node and localsid have local significance (their sid don't have to be globally unique)
	SidForServiceHostLocalsid() net.IP

	// SidForServicePodLocalsid creates a valid SRv6 SID for service locasid leading to pod backend. The SID creation is
	// based on backend IP <backendIP>.
	SidForServicePodLocalsid(backendIP net.IP) net.IP

	// SidForNodeToNodePodLocalsid creates a valid SRv6 SID for locasid that is part of node-to-node Srv6 tunnel and
	// outputs packets to pod VRF table.
	SidForNodeToNodePodLocalsid(nodeIP net.IP) net.IP

	// SidForNodeToNodeHostLocalsid creates a valid SRv6 SID for locasid that is part of node-to-node Srv6 tunnel and
	// outputs packets to main VRF table.
	SidForNodeToNodeHostLocalsid(nodeIP net.IP) net.IP

	// SidForServiceNodeLocalsid creates a valid SRv6 SID for service locasid serving as intermediate step in policy segment list.
	SidForServiceNodeLocalsid(nodeIP net.IP) net.IP

	// BsidForNodeToNodePodPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and routes traffic to pod VRF table
	BsidForNodeToNodePodPolicy(nodeIP net.IP) net.IP

	// BsidForNodeToNodeHostPolicy creates a valid SRv6 SID for policy that is part of node-to-node Srv6 tunnel and routes traffic to main VRF table
	BsidForNodeToNodeHostPolicy(nodeIP net.IP) net.IP

	// BsidForSFCPolicy creates a valid SRv6 SID for policy used for SFC
	BsidForSFCPolicy(sfcName string) net.IP

	// SidForSFCServiceFunctionLocalsid creates a valid SRv6 SID for locasid leading to pod of service function given by
	// <serviceFunctionPodIP> IP address.
	SidForSFCServiceFunctionLocalsid(sfcName string, serviceFunctionPodIP net.IP) net.IP

	// SidForSFCEndLocalsid creates a valid SRv6 SID for locasid of segment that is the last link of SFC chain
	SidForSFCEndLocalsid(serviceFunctionPodIP net.IP) net.IP

	// GetIPAMConfigForJSON returns IPAM configuration in format suitable
	// for marshalling to JSON (subnets not converted to net.IPNet + defined
	// JSON flag for every option). If contivCIDR is used it returns actual
	// dissected subnets.
	GetIPAMConfigForJSON() *config.IPAMConfig
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
