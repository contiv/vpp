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



type NodeInterfaces map[int]NodeInterface
type NodeBridgeDomains map[int]NodeBridgeDomain
type NodeL2FibTable map[string]NodeL2FibEntry
type NodeTelemetries map[string]NodeTelemetry
type NodeIPArpTable []NodeIPArpEntry

//NodeTelemetry holds the unmarshalled node telemetry JSON data
type NodeTelemetry struct {
	Command string   `json:"command"`
	Output  []Output `json:"output"`
}

type Output struct {
	command string
	output  []OutputEntry
}

type OutputEntry struct {
	nodeName string
	count    int
	reason   string
}

//NodeL2FibEntry holds unmarshalled L2Fib JSON data
type NodeL2FibEntry struct {
	BridgeDomainIdx          uint32 `json:"bridge_domain_idx"`
	OutgoingInterfaceSwIfIdx uint32 `json:"outgoing_interface_sw_if_idx"`
	PhysAddress              string `json:"phys_address"`
	StaticConfig             bool   `json:"static_config"`
	BridgedVirtualInterface  bool   `json:"bridged_virtual_interface"`
}

//NodeInterface holds unmarshalled Interface JSON data
type NodeInterface struct {
	VppInternalName string                   `json:"vpp_internal_name"`
	Name            string                   `json:"name"`
	IfType          interfaces.InterfaceType `json:"type,omitempty"`
	Enabled         bool                     `json:"enabled,omitempty"`
	PhysAddress     string                   `json:"phys_address,omitempty"`
	Mtu             uint32                   `json:"mtu,omitempty"`
	Vxlan           Vxlan                    `json:"vxlan,omitempty"`
	IPAddresses     []string                 `json:"ip_addresses,omitempty"`
	Tap             Tap                      `json:"tap,omitempty"`
}

type Vxlan struct {
	SrcAddress string `json:"src_address"`
	DstAddress string `json:"dst_address"`
	Vni        uint32 `json:"vni"`
}

//NodeIPArpEntry holds unmarshalled IP ARP data
type NodeIPArpEntry struct {
	Interface  uint32 `json:"interface"`
	IPAddress  string `json:"IPAddress"`
	MacAddress string `json:"MacAddress"`
	Static     bool   `json:"Static"`
}

type Tap struct {
	Version    uint32 `json:"version"`
	HostIfName string `json:"host_if_name"`
}

//NodeBridgeDomain holds the unmarshalled bridge domain data.
type NodeBridgeDomain struct {
	Interfaces []BDinterfaces `json:"interfaces"`
	Name       string         `json:"name"`
	Forward    bool           `json:"forward"`
}

type BDinterfaces struct {
	SwIfIndex uint32 `json:"sw_if_index"`
}


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
	Label []*Pod_Label `protobuf:"bytes,3,rep,name=label" json:"label,omitempty"`
	// IP address allocated to the pod. Routable at least within the cluster.
	// Empty if not yet allocated.
	// +optional
	IpAddress string `protobuf:"bytes,4,opt,name=ip_address,json=ipAddress" json:"ip_address,omitempty"`
	// IP address of the host to which the pod is assigned.
	// Empty if not yet scheduled.
	// +optional
	HostIpAddress string `protobuf:"bytes,5,opt,name=host_ip_address,json=hostIpAddress" json:"host_ip_address,omitempty"`
	// List of containers belonging to the pod.
	// Containers cannot currently be added or removed.
	// There must be at least one container in a Pod.
	// Cannot be updated.
}

type Pod_Label struct {
	Key   string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}