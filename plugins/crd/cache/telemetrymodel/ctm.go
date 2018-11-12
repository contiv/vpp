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
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
)

// see doc.go for instructions on how to generate the deep copy routines when
// the structs in this file change.

//Reports is the per node array of report lines generated from validate()
type Reports map[string][]string

//Node is a struct to hold all relevant information of a kubernetes node.
//It is populated with various information such as the interfaces and L2Fibs
//as well as the name and IP Addresses.
type Node struct {
	ID                uint32
	IPAddr            string
	ManIPAddr         string
	Name              string
	NodeLiveness      *NodeLiveness
	NodeInterfaces    map[int]NodeInterface
	NodeBridgeDomains map[int]NodeBridgeDomain
	NodeL2Fibs        map[string]NodeL2FibEntry
	NodeTelemetry     map[string]NodeTelemetry
	NodeIPArp         []NodeIPArpEntry
	NodeStaticRoutes  []NodeIPRoute
	NodeIPam          *IPamEntry
	LinuxInterfaces   []LinuxInterface
	PodMap            map[string]*Pod
}

//NodeLiveness holds the unmarshalled node liveness JSON data
type NodeLiveness struct {
	BuildVersion string `json:"build_version"`
	BuildDate    string `json:"build_date"`
	State        uint32 `json:"state"`
	StartTime    uint32 `json:"start_time"`
	LastChange   uint32 `json:"last_change"`
	LastUpdate   uint32 `json:"last_update"`
	CommitHash   string `json:"commit_hash"`
}

// LinuxInterfaces defines an array of LinuxInterfaces
type LinuxInterfaces []LinuxInterface

// NodeInterfaces defines a map of NodeInterface
type NodeInterfaces map[int]NodeInterface

// NodeBridgeDomains defines a map of NodeBridgeDomain
type NodeBridgeDomains map[int]NodeBridgeDomain

// NodeL2FibTable defines a map of NodeL2FibEntry
type NodeL2FibTable map[string]NodeL2FibEntry

// NodeTelemetries defines a map of NodeTelemetry
type NodeTelemetries map[string]NodeTelemetry

// NodeIPArpTable defines an array of NodeIPArpEntries
type NodeIPArpTable []NodeIPArpEntry

// NodeStaticRoutes defines an array of NodeIPRoute object
type NodeStaticRoutes []NodeIPRoute

//NodeInterface holds unmarshalled Interface JSON data
type NodeInterface struct {
	If     Interface     `json:"interface"`
	IfMeta InterfaceMeta `json:"interface_meta"`
}

// LinuxInterface contains data for linux interfaces on a node
type LinuxInterface struct {
	If     LinuxIf     `json:"linux_interface"`
	IfMeta LinuxIfMeta `json:"linux_interface_meta"`
}

// LinuxIf defines the data structure for Linux interface data
type LinuxIf struct {
	Name        string   `json:"name"`
	IPAddresses []string `json:"ip_addresses"`
	HostIfName  string   `json:"host_if_name"`
}

// LinuxIfMeta defines the data structure for Linux interface metadata
type LinuxIfMeta struct {
	Index     uint32 `json:"index"`
	Name      string `json:"name"`
	Alias     string `json:"alias"`
	OperState string `json:"oper_state"`
	Flags     string `json:"flags"`
	MacAddr   string `json:"mac_addr"`
	Mtu       uint32 `json:"mtu"`
	Type      string `json:"type"`
}

// Interface contains interface parameter data
type Interface struct {
	Name        string                   `json:"name"`
	IfType      interfaces.InterfaceType `json:"type,omitempty"`
	Enabled     bool                     `json:"enabled,omitempty"`
	PhysAddress string                   `json:"phys_address,omitempty"`
	Mtu         uint32                   `json:"mtu,omitempty"`
	Vrf         uint32                   `json:"vrf,omitempty"`
	IPAddresses []string                 `json:"ip_addresses,omitempty"`
	Vxlan       Vxlan                    `json:"vxlan,omitempty"`
	Tap         Tap                      `json:"tap,omitempty"`
}

// InterfaceMeta defines the interface VPP internal metadata
type InterfaceMeta struct {
	SwIfIndex       uint32 `json:"sw_if_index"`
	Tag             string `json:"tag"`
	VppInternalName string `json:"internal_name"`
}

// Vxlan contains vxlan parameter data
type Vxlan struct {
	SrcAddress string `json:"src_address"`
	DstAddress string `json:"dst_address"`
	Vni        uint32 `json:"vni"`
}

// Tap contains tap parameter data
type Tap struct {
	Version    uint32 `json:"version"`
	HostIfName string `json:"host_if_name"`
}

// NodeBridgeDomain holds the unmarshalled bridge domain data.
type NodeBridgeDomain struct {
	Bd     BridgeDomain     `json:"bridge_domain"`
	BdMeta BridgeDomainMeta `json:"bridge_domain_meta"`
}

// BridgeDomain defines the Bridge Domain main data set
type BridgeDomain struct {
	Interfaces []BdInterface `json:"interfaces"`
	Name       string        `json:"name"`
	Forward    bool          `json:"forward"`
}

// BridgeDomainMeta defines the Bridge Domain VPP internal metadata
type BridgeDomainMeta struct {
	BdID      uint32           `json:"bridge_domain_id"`
	BdID2Name BdID2NameMapping `json:"bridge_domain_id_to_name"`
}

// BdInterface defines the BD Interface data
type BdInterface struct {
	Name            string `json:"name"`
	BVI             bool   `json:"bridged_virtual_interface,omitempty"`
	SplitHorizonGrp uint32 `json:"split_horizon_group"`
}

// BdID2NameMapping defines the mapping of BD ifIndices to interface Names
type BdID2NameMapping map[uint32]string

//NodeL2FibEntry holds unmarshalled L2Fib JSON data
type NodeL2FibEntry struct {
	Fe     L2FibEntry     `json:"fib"`
	FeMeta L2FibEntryMeta `json:"fib_meta"`
}

//IPamEntry holds unmarchalled ipam JSON data
type IPamEntry struct {
	NodeID            uint32 `json:"nodeId"`
	NodeName          string `json:"nodeName"`
	NodeIP            string `json:"nodeIP"`
	PodSubnetThisNode string `json:"podNetwork"`
	VppHostNetwork    string `json:"vppHostNetwork"`
	Config            config `json:"config"`
}

type config struct {
	PodVPPSubnetCIDR              string `json:"podVPPSubnetCIDR"`
	PodSubnetCIDR                 string `json:"podSubnetCIDR"`
	PodSubnetOneNodePrefixLen     uint32 `json:"podSubnetOneNodePrefixLen"`
	VppHostSubnetCIDR             string `json:"vppHostSubnetCIDR"`
	VppHostSubnetOneNodePrefixLen uint32 `json:"vppHostSubnetOneNodePrefixLen"`
	NodeInterconnectCIDR          string `json:"nodeInterconnectCIDR"`
	NodeInterconnectDHCP          bool   `json:"nodeInterconnectDHCP"`
	VxlanCIDR                     string `json:"vxlanCIDR"`
	ServiceCIDR                   string `json:"serviceCIDR"`
	ContivCIDR                    string `json:"contivCIDR"`
}

// L2FibEntry defines the L2 FIB entry data set
type L2FibEntry struct {
	BridgeDomainName        string `json:"bridge_domain"`
	OutgoingIfName          string `json:"outgoing_interface"`
	PhysAddress             string `json:"phys_address"`
	StaticConfig            bool   `json:"static_config,omitempty"`
	BridgedVirtualInterface bool   `json:"bridged_virtual_interface,omitempty"`
}

// L2FibEntryMeta defines the L2FIB entry VPP internal metadata
type L2FibEntryMeta struct {
	BridgeDomainID  uint32 `json:"bridge_domain_id"`
	OutgoingIfIndex uint32 `json:"outgoing_interface_sw_if_idx"`
}

//NodeIPArpEntry holds unmarshalled IP ARP data
type NodeIPArpEntry struct {
	Ae     IPArpEntry     `json:"Arp"`
	AeMeta IPArpEntryMeta `json:"Meta"`
}

// IPArpEntry defines the IP ARP Entry entry data set
type IPArpEntry struct {
	Interface   string `json:"interface"`
	IPAddress   string `json:"ip_address"`
	PhysAddress string `json:"phys_address"`
	Static      bool   `json:"static,omitempty"`
}

// IPArpEntryMeta defines the IP ARP Entry VPP internal metadata
type IPArpEntryMeta struct {
	IfIndex uint32 `json:"SwIfIndex"`
}

// NodeIPRoute holds the unmarshalled node static route JSON data.
type NodeIPRoute struct {
	Ipr     IPRoute     `json:"Route"`
	IprMeta IPRouteMeta `json:"Meta"`
}

// IPRoute defines the IP Route entry data set
type IPRoute struct {
	Type        uint32 `json:"type"`
	VrfID       uint32 `json:"vrf_id"`
	DstAddr     string `json:"dst_ip_addr"`
	NextHopAddr string `json:"next_hop_addr"`
	OutIface    string `json:"outgoing_interface"`
	Weight      uint32 `json:"weight"`
	ViaVRFID    uint32 `json:"via_vrf_id"`
}

// IPRouteMeta defines the IP Route VPP internal metadata
type IPRouteMeta struct {
	TableName         string `json:"TableName"`
	OutgoingIfIdx     uint32 `json:"OutgoingIfIdx"`
	Afi               uint32 `json:"Afi"`
	IsLocal           bool   `json:"IsLocal,omitempty"`
	IsUDPEncap        bool   `json:"IsUDPEncap,omitempty"`
	IsUnreach         bool   `json:"IsUnreach,omitempty"`
	IsProhibit        bool   `json:"IsProhibit,omitempty"`
	IsResolveHost     bool   `json:"IsResolveHost,omitempty"`
	IsResolveAttached bool   `json:"IsResolveAttached,omitempty"`
	IsDvr             bool   `json:"IsDvr,omitempty"`
	IsSourceLookup    bool   `json:"IsSourceLookup,omitempty"`
	NextHopID         uint32 `json:"NextHopID"`
	RpfID             uint32 `json:"RpfID"`
}

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

//Pod contains pod parameter data
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

//PodLabel contains key/value pair info
type PodLabel struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}
