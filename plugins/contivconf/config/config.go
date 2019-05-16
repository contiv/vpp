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

	// Transportation used for node-to-node communication:
	// 1. VXLAN overlay ("vxlan") encapsulates/decapsulates traffic between nodes using VXLAN.
	// 2. SRv6 overlay ("srv6") encapsulates/decapsulates traffic between nodes using SRv6 (segment routing based on IPv6).
	// SRv6's steering and policy will be on ingress node and SRv6's localsid on egress node. This transportation expects
	// ipv6 to be enabled (SRv6 packets=IPv6 packets using SR header extension).
	// 3. Using none of the previous mentioned overlays ("nooverlay") and route traffic using routing tables/etc., e.g. if the nodes are on the same L2 network.
	NodeToNodeTransport string `json:"nodeToNodeTransport,omitempty"`

	// Enabled when routing for K8s service should be performed by using SRv6 (segment routing based on IPv6).
	// The routing within the routing segments is done as normal IPv6 routing, therefore IPv6 must be enabled.
	// This setting handles how packet is transported from service client to service backend, but not how is transported
	// response packet(if any) from backend to service client. This is handled by non-service routing that uses on node-to-node
	// part of route the "NodeToNodeTransport" setting. To communicate between nodes only using SRv6, set it to "srv6" (+ UseSRv6ForServices=true).
	UseSRv6ForServices bool `json:"useSRv6ForServices,omitempty"`

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
	UseExternalIPAM               bool       `json:"useExternalIPAM,omitempty"`
	ContivCIDR                    string     `json:"contivCIDR,omitempty"`
	ServiceCIDR                   string     `json:"serviceCIDR,omitempty"`
	NodeInterconnectDHCP          bool       `json:"nodeInterconnectDHCP,omitempty"`
	PodSubnetCIDR                 string     `json:"podSubnetCIDR,omitempty"`
	PodSubnetOneNodePrefixLen     uint8      `json:"podSubnetOneNodePrefixLen,omitempty"`
	VPPHostSubnetCIDR             string     `json:"vppHostSubnetCIDR,omitempty"`
	VPPHostSubnetOneNodePrefixLen uint8      `json:"vppHostSubnetOneNodePrefixLen,omitempty"`
	NodeInterconnectCIDR          string     `json:"nodeInterconnectCIDR,omitempty"`
	VxlanCIDR                     string     `json:"vxlanCIDR,omitempty"`
	DefaultGateway                string     `json:"defaultGateway,omitempty"`
	SRv6                          SRv6Config `json:"srv6"`
}

// SRv6Config is part of IPAM configuration that configures SID prefixes of SRv6 components
type SRv6Config struct {
	ServicePolicyBSIDSubnetCIDR       string `json:"servicePolicyBSIDSubnetCIDR,omitempty"`
	ServicePodLocalSIDSubnetCIDR      string `json:"servicePodLocalSIDSubnetCIDR,omitempty"`
	ServiceHostLocalSIDSubnetCIDR     string `json:"serviceHostLocalSIDSubnetCIDR,omitempty"`
	ServiceNodeLocalSIDSubnetCIDR     string `json:"serviceNodeLocalSIDSubnetCIDR,omitempty"`
	NodeToNodePodLocalSIDSubnetCIDR   string `json:"nodeToNodePodLocalSIDSubnetCIDR,omitempty"`
	NodeToNodeHostLocalSIDSubnetCIDR  string `json:"nodeToNodeHostLocalSIDSubnetCIDR,omitempty"`
	NodeToNodePodPolicySIDSubnetCIDR  string `json:"nodeToNodePodPolicySIDSubnetCIDR,omitempty"`
	NodeToNodeHostPolicySIDSubnetCIDR string `json:"nodeToNodeHostPolicySIDSubnetCIDR,omitempty"`
}

// NodeConfig represents configuration specific to a given node.
type NodeConfig struct {
	// name of the node, should match with the hostname
	NodeName string `json:"nodeName"`

	// node config specification can be defined either via the configuration file
	// or using CRD
	nodeconfigcrd.NodeConfigSpec
}
