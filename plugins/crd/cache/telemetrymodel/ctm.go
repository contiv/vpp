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

//Node is a struct to hold all relevant information of a kubernetes node.
//It is populated with various information such as the interfaces and L2Fibs
//as well as the name and IP Addresses.
type Node struct {
	ID                uint32
	IPAdr             string
	ManIPAdr          string
	Name              string
	NodeLiveness      *NodeLiveness
	NodeInterfaces    map[int]NodeInterface
	NodeBridgeDomains map[int]NodeBridgeDomain
	NodeL2Fibs        map[string]NodeL2FibEntry
	NodeTelemetry     map[string]NodeTelemetry
	NodeIPArp         []NodeIPArpEntry
	NodeStaticRoutes  []NodeIPRoute
	Report            []string
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

// NodeInterfaces defines a map of NodeInterface
type NodeInterfaces map[int]NodeInterface

// NodeBridgeDomains defines a map of NodeBridgeDomain
type NodeBridgeDomains map[int]NodeBridgeDomain

// NodeL2FibTable defines a map of NodeL2FibEntry
type NodeL2FibTable map[string]NodeL2FibEntry

// NodeTelemetries defines a map of NodeTelemetry
type NodeTelemetries map[string]NodeTelemetry

// NodeIPArpTable defines an array of NodeIPArpEntry
type NodeIPArpTable []NodeIPArpEntry

// NodeStaticRoutes defines an array of NodeIPRoute object
type NodeStaticRoutes []NodeIPRoute

//NodeInterface holds unmarshalled Interface JSON data
type NodeInterface struct {
	If     Interface     `json:"interface"`
	IfMeta InterfaceMeta `json:"interface_meta"`
}

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

// BridgeDomainMeta defines the Bridge Domain main data set
type BridgeDomain struct {
	Interfaces []BdInterface `json:"interfaces"`
	Name       string        `json:"name"`
	Forward    bool          `json:"forward"`
}

// BridgeDomainMeta defines the Bridge Domain VPP internal metadata
type BridgeDomainMeta struct {
	BdID      uint32           `json:"bridge_domain_id"`
	BdId2Name BdId2NameMapping `json:"bridge_domain_id_to_name"`
}

// BdInterface defines the BD Interface data
type BdInterface struct {
	Name            string `json:"name"`
	BVI             bool   `json:"bridged_virtual_interface,omitempty"`
	SplitHorizonGrp uint32 `json:"split_horizon_group"`
}

// BdId2NameMapping defines the mapping of BD ifIndices to interface Names
type BdId2NameMapping map[uint32]string

//NodeL2FibEntry holds unmarshalled L2Fib JSON data
type NodeL2FibEntry struct {
	Fe     L2FibEntry     `json:"fib"`
	FeMeta L2FibEntryMeta `json:"fib_meta"`
}

type L2FibEntry struct {
	BridgeDomainName        string `json:"bridge_domain"`
	OutgoingIfName          string `json:"outgoing_interface"`
	PhysAddress             string `json:"phys_address"`
	StaticConfig            bool   `json:"static_config,omitempty"`
	BridgedVirtualInterface bool   `json:"bridged_virtual_interface,omitempty"`
}

type L2FibEntryMeta struct {
	BridgeDomainId  uint32 `json:"bridge_domain_id"`
	OutgoingIfIndex uint32 `json:"outgoing_interface_sw_if_idx"`
}

//NodeIPArpEntry holds unmarshalled IP ARP data
type NodeIPArpEntry struct {
	Ae     IPArpEntry     `json:"Arp"`
	AeMeta IPArpEntryMeta `json:"Meta"`
}

type IPArpEntry struct {
	Interface   string `json:"interface"`
	IPAddress   string `json:"ip_address"`
	PhysAddress string `json:"phys_address"`
	Static      bool   `json:"static,omitempty"`
}

type IPArpEntryMeta struct {
	IfIndex uint32 `json:"SwIfIndex"`
}

// NodeIPRoute holds the unmarshalled node static route JSON data.
type NodeIPRoute struct {
	Ipr     IPRoute     `json:"Route"`
	IprMeta IPRouteMeta `json:"Meta"`
}

type IPRoute struct {
	VrfID       uint32  `json:"vrf_id"`
	DstAddr     string `json:"dst_ip_addr"`
	NextHopAddr string  `json:"next_hop_addr"`
	OutIface    string  `json:"outgoing_interface"`
	Weight      uint32  `json:"weight"`
}

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

type dstAddr struct {
	IP   string `json:"IP"`
	Mask string `json:"Mask"`
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
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// Namespace the pod is inserted into.
	// An empty namespace is equivalent to the "default" namespace, but "default"
	// is the canonical representation.
	// Cannot be updated.
	Namespace string `protobuf:"bytes,2,opt,name=namespace" json:"namespace,omitempty"`
	// A list of labels attached to this pod.
	// +optional
	Label []*PodLabel `protobuf:"bytes,3,rep,name=label" json:"label,omitempty"`
	// IP address allocated to the pod. Routable at least within the cluster.
	// Empty if not yet allocated.
	// +optional
	IPAddress string `protobuf:"bytes,4,opt,name=ip_address,json=ipAddress" json:"ip_address,omitempty"`
	// IP address of the host to which the pod is assigned.
	// Empty if not yet scheduled.
	// +optional
	HostIPAddress string `protobuf:"bytes,5,opt,name=host_ip_address,json=hostIpAddress" json:"host_ip_address,omitempty"`
	// Name of the interface on VPP through which the pod is connected
	// to VPP. Will be empty for host-network pods.
	VppIfName string
	// IP address of the interface on VPP through which the pod is
	// connected to VPP. Will be empty for host-network pods.
	VppIfIPAddr string
}

//PodLabel contains key/value pair info
type PodLabel struct {
	Key   string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}
