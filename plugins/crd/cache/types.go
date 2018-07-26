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

package cache

import "github.com/ligato/cn-infra/logging"

// here goes different cache types

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
	NodeBridgeDomains map[int]NodeBridgeDomains
	NodeL2Fibs        map[string]NodeL2Fib
	NodeTelemetry     map[string]NodeTelemetry
	NodeIPArp         []NodeIPArp
}

//Cache holds various maps which all take different keys but point to the same underlying value.
type Cache struct {
	nMap        map[string]*Node
	loopIPMap   map[string]*Node
	gigEIPMap   map[string]*Node
	loopMACMap  map[string]*Node
	errorReport map[string][]string
	logger      logging.Logger
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

//NodeLivenessDTO is used to associate NodeLiveness Data with a node name and send it over channel for processing
type NodeLivenessDTO struct {
	NodeName string
	NodeInfo *NodeLiveness
}

//NodeTelemetry holds the unmarshalled node telemetry JSON data
type NodeTelemetry struct {
	Command string   `json:"command"`
	Output  []output `json:"output"`
}

//NodeTelemetryDTO is used to associate NodeTelemetry data with a node name to be sent over a channel for processing
type NodeTelemetryDTO struct {
	NodeName string
	NodeInfo map[string]NodeTelemetry
}

type output struct {
	command string
	output  []outputEntry
}

type outputEntry struct {
	nodeName string
	count    int
	reason   string
}

//NodeL2Fib holds unmarshalled L2Fib JSON data
type NodeL2Fib struct {
	BridgeDomainIdx          uint32 `json:"bridge_domain_idx"`
	OutgoingInterfaceSwIfIdx uint32 `json:"outgoing_interface_sw_if_idx"`
	PhysAddress              string `json:"phys_address"`
	StaticConfig             bool   `json:"static_config"`
	BridgedVirtualInterface  bool   `json:"bridged_virtual_interface"`
}

//NodeL2FibsDTO associates a map of NodeL2Fib data with a node name to be sent over a channel for processing
type NodeL2FibsDTO struct {
	NodeName string
	NodeInfo map[string]NodeL2Fib
}

//NodeInterface holds unmarshalled Interface JSON data
type NodeInterface struct {
	VppInternalName string   `json:"vpp_internal_name"`
	Name            string   `json:"name"`
	IfType          uint32   `json:"type,omitempty"`
	Enabled         bool     `json:"enabled,omitempty"`
	PhysAddress     string   `json:"phys_address,omitempty"`
	Mtu             uint32   `json:"mtu,omitempty"`
	Vxlan           vxlan    `json:"vxlan,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	Tap             tap      `json:"tap,omitempty"`
}

//NodeInterfacesDTO associates a map of Node interfaces with a node name to be sent over a channel for processing
type NodeInterfacesDTO struct {
	NodeName string
	NodeInfo map[int]NodeInterface
}

type vxlan struct {
	SrcAddress string `json:"src_address"`
	DstAddress string `json:"dst_address"`
	Vni        uint32 `json:"vni"`
}

//NodeIPArp holds unmarshalled IP ARP data
type NodeIPArp struct {
	Interface  uint32 `json:"interface"`
	IPAddress  string `json:"IPAddress"`
	MacAddress string `json:"MacAddress"`
	Static     bool   `json:"Static"`
}

//NodeIPArpDTO associates an IP Arp table with a node name to be sent over a channel for processing.
type NodeIPArpDTO struct {
	NodeInfo []NodeIPArp
	NodeName string
}

type tap struct {
	Version    uint32 `json:"version"`
	HostIfName string `json:"host_if_name"`
}

//NodeBridgeDomains holds the unmarshalled bridge domain data.
type NodeBridgeDomains struct {
	Interfaces []bdinterfaces `json:"interfaces"`
	Name       string         `json:"name"`
	Forward    bool           `json:"forward"`
}

type bdinterfaces struct {
	SwIfIndex uint32 `json:"sw_if_index"`
}

//NodeBridgeDomainsDTO associates a map of bridge domains with a node name to be sent over a channel for processing.
type NodeBridgeDomainsDTO struct {
	NodeName string
	NodeInfo map[int]NodeBridgeDomains
}
