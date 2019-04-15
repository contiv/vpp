// Copyright (c) 2019 Cisco and/or its affiliates.
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

package config

import (
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
)

// Config represents configuration for the Contiv agent.
// The path to the configuration file can be specified in two ways:
//  - using the `-contiv-config=<path to config>` argument, or
//  - using the `CONTIV_CONFIG=<path to config>` environment variable
type Config struct {
	InterfaceConfig
	RoutingConfig
	IPNeighborScanConfig

	StealFirstNIC  bool   `json:"stealFirstNIC,omitempty"`
	StealInterface string `json:"stealInterface,omitempty"`
	STNSocketFile  string `json:"stnSocketFile,omitempty"`
	STNVersion     uint8  `json:"stnVersion,omitempty"`

	NatExternalTraffic           bool `json:"natExternalTraffic,omitempty"`
	EnablePacketTrace            bool `json:"enablePacketTrace,omitempty"`
	CRDNodeConfigurationDisabled bool `json:"crdNodeConfigurationDisabled,omitempty"`

	IPAMConfig IPAMConfig   `json:"ipamConfig"`
	NodeConfig []NodeConfig `json:"nodeConfig"`
}

// InterfaceConfig contains configuration related to interfaces.
type InterfaceConfig struct {
	MTUSize                    uint32 `json:"mtuSize,omitempty"`
	UseTAPInterfaces           bool   `json:"useTAPInterfaces,omitempty"`
	TAPInterfaceVersion        uint8  `json:"tapInterfaceVersion,omitempty"`
	TAPv2RxRingSize            uint16 `json:"tapv2RxRingSize,omitempty"`
	TAPv2TxRingSize            uint16 `json:"tapv2TxRingSize,omitempty"`
	Vmxnet3RxRingSize          uint16 `json:"vmxnet3RxRingSize,omitempty"`
	Vmxnet3TxRingSize          uint16 `json:"vmxnet3TxRingSize,omitempty"`
	InterfaceRxMode            string `json:"interfaceRxMode,omitempty"` // "" == "default" / "polling" / "interrupt" / "adaptive"
	TCPChecksumOffloadDisabled bool   `json:"tcpChecksumOffloadDisabled,omitempty"`
}

// RoutingConfig groups configuration options related to routing.
type RoutingConfig struct {
	// VRF IDs
	MainVRFID uint32 `json:"mainVRFID,omitempty"`
	PodVRFID  uint32 `json:"podVRFID,omitempty"`

	// enable when no overlay (VXLAN) is needed for node-to-node communication,
	// e.g. if the nodes are on the same L2 network
	UseNoOverlay bool `json:"useNoOverlay,omitempty"`

	// Enabled when routing should be performed by using SRv6 (segment routing based on IPv6).
	// Routing within routing segments is done as normal IPv6 routing. Routing between 2 nodes
	// is just moving withing segment, so it is also IPv6 routing (no VXLANs)
	UseSRv6Interconnect bool `json:"useSRv6Interconnect,omitempty"`

	// when enabled, cluster IP CIDR should be routed towards VPP from Linux
	RouteServiceCIDRToVPP bool `json:"routeServiceCIDRToVPP,omitempty"`
}

// IPNeighborScanConfig contains configuration related to IP neighbour scanning.
type IPNeighborScanConfig struct {
	// when enabled, IP neighbors should be periodically scanned and probed
	// to maintain the ARP table
	ScanIPNeighbors          bool  `json:"scanIPNeighbors,omitempty"`
	IPNeighborScanInterval   uint8 `json:"ipNeighborScanInterval,omitempty"`
	IPNeighborStaleThreshold uint8 `json:"ipNeighborStaleThreshold,omitempty"`
}

// IPAMConfig groups IPAM configuration options as basic data types and with
// JSON tags, ready to be un-marshalled from the configuration.
// The string fields are then parsed to *net.IPNet and returned as such in IPAMConfig
// structure.
type IPAMConfig struct {
	UseExternalIPAM                       bool   `json:"useExternalIPAM,omitempty"`
	ContivCIDR                            string `json:"contivCIDR,omitempty"`
	ServiceCIDR                           string `json:"serviceCIDR,omitempty"`
	NodeInterconnectDHCP                  bool   `json:"nodeInterconnectDHCP,omitempty"`
	PodSubnetCIDR                         string `json:"podSubnetCIDR,omitempty"`
	PodSubnetOneNodePrefixLen             uint8  `json:"podSubnetOneNodePrefixLen,omitempty"`
	VPPHostSubnetCIDR                     string `json:"vppHostSubnetCIDR,omitempty"`
	VPPHostSubnetOneNodePrefixLen         uint8  `json:"vppHostSubnetOneNodePrefixLen,omitempty"`
	NodeInterconnectCIDR                  string `json:"nodeInterconnectCIDR,omitempty"`
	VxlanCIDR                             string `json:"vxlanCIDR,omitempty"`
	DefaultGateway                        string `json:"defaultGateway,omitempty"`
	Srv6ServicePolicyBSIDSubnetCIDR       string `json:"srv6ServicePolicyBSIDSubnetCIDR,omitempty"`
	Srv6ServicePodLocalSIDSubnetCIDR      string `json:"srv6ServicePodLocalSIDSubnetCIDR,omitempty"`
	Srv6ServiceHostLocalSIDSubnetCIDR     string `json:"srv6ServiceHostLocalSIDSubnetCIDR,omitempty"`
	Srv6ServiceNodeLocalSIDSubnetCIDR     string `json:"srv6ServiceNodeLocalSIDSubnetCIDR,omitempty"`
	Srv6NodeToNodePodLocalSIDSubnetCIDR   string `json:"srv6NodeToNodePodLocalSIDSubnetCIDR,omitempty"`
	Srv6NodeToNodeHostLocalSIDSubnetCIDR  string `json:"srv6NodeToNodeHostLocalSIDSubnetCIDR,omitempty"`
	Srv6NodeToNodePodPolicySIDSubnetCIDR  string `json:"srv6NodeToNodePodPolicySIDSubnetCIDR,omitempty"`
	Srv6NodeToNodeHostPolicySIDSubnetCIDR string `json:"srv6NodeToNodeHostPolicySIDSubnetCIDR,omitempty"`
}

// NodeConfig represents configuration specific to a given node.
type NodeConfig struct {
	// name of the node, should match with the hostname
	NodeName string `json:"nodeName"`

	// node config specification can be defined either via the configuration file
	// or using CRD
	nodeconfigcrd.NodeConfigSpec
}
