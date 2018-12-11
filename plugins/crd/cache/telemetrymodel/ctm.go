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

package telemetrymodel

import (
	"github.com/gogo/protobuf/jsonpb"

	"github.com/ligato/cn-infra/health/statuscheck/model/status"

	"github.com/ligato/vpp-agent/idxvpp2"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	linux_ifaceidx "github.com/ligato/vpp-agent/plugins/linuxv2/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"

	"github.com/contiv/vpp/plugins/ipv4net"
)

/*********************************** Reports **********************************/

// Reports is the per node array of report lines generated from validate()
type Reports map[string][]string

// DeepCopy returns a deep copy of Reports.
func (r Reports) DeepCopy() (out Reports) {
	out = make(Reports, len(r))
	for key, val := range r {
		var outVal []string
		if val == nil {
			out[key] = nil
		} else {
			in, out := &val, &outVal
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		out[key] = outVal
	}
	return out
}

/************************************ Node *************************************/

// NodeInfo is struct to hold some basic information of a kubernetes node.
type NodeInfo struct {
	ID        uint32
	IPAddr    string
	ManIPAddr string // correlated with Kubernetes node model in ContivTelemetryCache.corelateMgmtIP()
	Name      string
}

// Node is a struct to hold all relevant information of a kubernetes node.
// It is populated with various information such as the interfaces and L2Fibs
// as well as the name and IP Addresses.
type Node struct {
	*NodeInfo

	// node status
	NodeLiveness  *status.AgentStatus
	NodeTelemetry map[string]NodeTelemetry

	// node configuration
	NodeInterfaces    NodeInterfaceMap
	NodeBridgeDomains NodeBridgeDomains
	NodeL2Fibs        NodeL2FibTable
	NodeIPArp         NodeIPArpTable
	NodeStaticRoutes  NodeStaticRoutes
	NodeIPam          *ipv4net.IPAMData
	LinuxInterfaces   LinuxInterfaces

	// pods
	PodMap map[string]*Pod
}

/******************************** VPP interface ********************************/

type NodeInterfaceMap map[uint32]NodeInterface

// GetByName retrieves interface by the logical name.
func (m NodeInterfaceMap) GetByName(name string) (iface NodeInterface, exists bool) {
	for _, iface = range m {
		if iface.Value.Name == name {
			return iface, true
		}
	}
	return iface, false
}

// NodeInterfaces is a list of node (VPP) interfaces.
type NodeInterfaces []NodeInterface

// NodeInterface holds un-marshalled VPP Interface data.
type NodeInterface struct {
	Key      string
	Value    vppInterface
	Metadata ifaceidx.IfaceMetadata
}

// vppInterface extends VPP interface proto model with JSON un-marshaller from jsonpb.
type vppInterface struct {
	*interfaces.Interface
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *vppInterface) UnmarshalJSON(data []byte) error {
	v.Interface = &interfaces.Interface{}
	return jsonpb.UnmarshalString(string(data), v.Interface)
}

/******************************* Linux interface *******************************/

// LinuxInterfaces is a list of host (Linux) interfaces.
type LinuxInterfaces []LinuxInterface

// LinuxInterface holds un-marshalled Linux Interface data.
type LinuxInterface struct {
	Key      string
	Value    linuxInterface
	Metadata linux_ifaceidx.LinuxIfMetadata
}

// linuxInterface extends Linux interface proto model with JSON un-marshaller from jsonpb.
type linuxInterface struct {
	*linux_interfaces.Interface
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *linuxInterface) UnmarshalJSON(data []byte) error {
	v.Interface = &linux_interfaces.Interface{}
	return jsonpb.UnmarshalString(string(data), v.Interface)
}

/******************************** Bridge domain ********************************/

// NodeBridgeDomains is a list of VPP bridge domains.
type NodeBridgeDomains []NodeBridgeDomain

// NodeBridgeDomain holds un-marshalled VPP bridge domain data.
type NodeBridgeDomain struct {
	Key      string
	Value    vppBridgeDomain
	Metadata idxvpp2.OnlyIndex
}

// vppBridgeDomain extends VPP BD proto model with JSON un-marshaller from jsonpb.
type vppBridgeDomain struct {
	*l2.BridgeDomain
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *vppBridgeDomain) UnmarshalJSON(data []byte) error {
	v.BridgeDomain = &l2.BridgeDomain{}
	return jsonpb.UnmarshalString(string(data), v.BridgeDomain)
}

/*********************************** L2 FIB ***********************************/

// NodeL2FibTable is a list of VPP L2 FIB entries.
type NodeL2FibTable []NodeL2FibEntry

// NodeL2FibEntry holds un-marshalled VPP L2 FIB entry data.
type NodeL2FibEntry struct {
	Key   string
	Value vppL2FIB
}

// vppL2FIB extends VPP L2 FIB entry proto model with JSON un-marshaller from jsonpb.
type vppL2FIB struct {
	*l2.FIBEntry
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *vppL2FIB) UnmarshalJSON(data []byte) error {
	v.FIBEntry = &l2.FIBEntry{}
	return jsonpb.UnmarshalString(string(data), v.FIBEntry)
}

/*********************************** IP ARP ***********************************/

// NodeIPArpTable is a list of VPP ARP entries.
type NodeIPArpTable []NodeIPArpEntry

// NodeIPArpEntry holds un-marshalled VPP ARP entry data.
type NodeIPArpEntry struct {
	Key   string
	Value vppARP
}

// vppARP extends VPP ARP entry proto model with JSON un-marshaller from jsonpb.
type vppARP struct {
	*l3.ARPEntry
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *vppARP) UnmarshalJSON(data []byte) error {
	v.ARPEntry = &l3.ARPEntry{}
	return jsonpb.UnmarshalString(string(data), v.ARPEntry)
}

/********************************* L3 Routes **********************************/

// NodeStaticRoutes is a list of VPP L3 routes.
type NodeStaticRoutes []NodeIPRoute

// NodeIPRoute holds un-marshalled VPP L3 route data.
type NodeIPRoute struct {
	Key   string
	Value vppL3Route
}

// vppL3Route extends VPP L3 route proto model with JSON un-marshaller from jsonpb.
type vppL3Route struct {
	*l3.StaticRoute
}

// UnmarshalJSON uses un-marshaller from jsonpb.
func (v *vppL3Route) UnmarshalJSON(data []byte) error {
	v.StaticRoute = &l3.StaticRoute{}
	return jsonpb.UnmarshalString(string(data), v.StaticRoute)
}

/********************************** Telemetry **********************************/

// NodeTelemetries defines a map of NodeTelemetry
type NodeTelemetries map[string]NodeTelemetry

//NodeTelemetry holds the unmarshalled node telemetry JSON data
type NodeTelemetry struct {
	Command string   `json:"command"`
	Output  []Output `json:"output"`
}

//Output holds the unmarshalled node telemetry output
type Output struct {
	command string
	output  []OutputEntry
}

//OutputEntry holds the unmarshalled node output telemetry data
type OutputEntry struct {
	nodeName string
	count    int
	reason   string
}

/************************************* Pod ************************************/

// Pod contains pod parameter data
type Pod struct {
	// Name of the pod unique within the namespace.
	// Cannot be updated.
	Name string `json:"name,omitempty"`
	// Namespace the pod is inserted into.
	// An empty namespace is equivalent to the "default" namespace, but "default"
	// is the canonical representation.
	// Cannot be updated.
	Namespace string `json:"namespace,omitempty"`
	// A list of labels attached to this pod.
	// +optional
	Label []*PodLabel `json:"label,omitempty"`
	// IP address allocated to the pod. Routable at least within the cluster.
	// Empty if not yet allocated.
	// +optional
	IPAddress string `json:"ip_address,omitempty"`
	// IP address of the host to which the pod is assigned.
	// Empty if not yet scheduled.
	// +optional
	HostIPAddress string `json:"host_ip_address,omitempty"`
	// Name of the interface on VPP through which the pod is connected
	// to VPP. Will be empty for host-network pods.
	VppIfName string `json:"vpp_if_name,omitempty"`
	// Internal name of the interface on VPP through which the pod is connected
	// to VPP. Will be empty for host-network pods.
	VppIfInternalName string `json:"vpp_if_internal_name,omitempty"`
	// IP address of the interface on VPP through which the pod is
	// connected to VPP. Will be empty for host-network pods.
	VppIfIPAddr string `json:"vpp_if_ip_addr,omitempty"`
	// Software IfIndex of the interface on VPP through which the pod is
	// connected to VPP. Will be empty for host-network pods.
	VppSwIfIdx uint32 `json:"vpp_sw_if_idx,omitempty"`
}

// PodLabel contains key/value pair info
type PodLabel struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}
