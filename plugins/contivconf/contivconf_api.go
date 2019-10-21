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

package contivconf

import (
	"fmt"
	"net"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
)

/********************************* Plugin API *********************************/

// API defines methods provided by ContivConf for use by other plugins.
type API interface {
	// InSTNMode returns true if the agent operates in the STN mode
	// (node has single interface stolen from the host stack for VPP).
	// STN configuration can be obtained via GetSTNConfig().
	InSTNMode() bool

	// UseDHCP returns true when the main VPP interface should be configured
	// with DHCP instead of static IP addresses.
	// With DHCP, GetMainInterfaceStaticIPs() and GetStaticDefaultGW() should
	// be ignored.
	UseDHCP() bool

	// EnablePacketTrace returns true if packets flowing through VPP should be
	// captured for later inspection.
	EnablePacketTrace() bool

	// GetMainInterfaceName returns the logical name of the VPP physical interface
	// to use for connecting the node with the cluster.
	// If empty, a loopback interface should be configured instead.
	GetMainInterfaceName() string

	// GetMainInterfaceConfiguredIPs returns the list of IP addresses configured
	// to be assigned to the main interface. Ignore if DHCP is enabled.
	// The function may return an empty list, then it is necessary to request
	// node IP from IPAM.
	GetMainInterfaceConfiguredIPs() IPsWithNetworks

	// GetOtherVPPInterfaces returns configuration to apply for non-main physical
	// VPP interfaces.
	GetOtherVPPInterfaces() OtherInterfaces

	// GetStaticDefaultGW returns the IP address of the default gateway.
	// Ignore if DHCP is enabled (in that case it is provided by the DHCP server)
	GetStaticDefaultGW() net.IP

	// NatExternalTraffic returns true when it is required to S-NAT traffic
	// leaving the node and heading out from the cluster.
	NatExternalTraffic() bool

	// GetIPAMConfig returns configuration to be used by the IPAM module.
	GetIPAMConfig() *IPAMConfig

	// GetIPAMConfigForJSON returns IPAM configuration in format suitable
	// for marshalling to JSON (subnets not converted to net.IPNet + defined
	// JSON flag for every option).
	GetIPAMConfigForJSON() *config.IPAMConfig

	// GetInterfaceConfig returns configuration related to VPP interfaces.
	GetInterfaceConfig() *config.InterfaceConfig

	// GetRoutingConfig returns configuration related to IP routing.
	GetRoutingConfig() *config.RoutingConfig

	// GetIPNeighborScanConfig returns configuration related to IP Neighbor
	// scanning.
	GetIPNeighborScanConfig() *config.IPNeighborScanConfig

	// GetSTNConfig returns configuration related to STN feature.
	// Use the method only in the STN mode - i.e. when InSTNMode() returns true.
	GetSTNConfig() *STNConfig

	// UseVmxnet3 returns true if vmxnet3 driver should be used for access to physical
	// interfaces instead of DPDK.
	// Vmxnet3 configuration can be obtained using GetVmxnet3Config()
	UseVmxnet3() bool

	// GetVmxnet3Config returns configuration related to vmxnet3 feature.
	// Use the method only if vmxnet3 is in use - i.e. when UseVmxnet3() returns true.
	GetVmxnet3Config() (*Vmxnet3Config, error)
}

/******************************** Configuration ********************************/

// IPAMConfig groups configuration options related to IP address allocation.
type IPAMConfig struct {
	// UseExternalIPAM is true if IPAM is provided by an external IPAM plugin instead of Contiv.
	UseExternalIPAM bool

	// UseIPv6 is true if IPv6 networking should be used instead of IPv4.
	UseIPv6 bool

	// CIDR to use for all IP address allocations.
	// If defined (non-nil), the manually selected subnets (CustomIPAMSubnets, see below)
	// should be ignored - i.e. this field takes precedence.
	// IPAM implementation should subdivide the network into smaller chunks to split
	// the address space between nodes and different kinds of endpoints (pods, vxlans, ...)
	// - see CustomIPAMSubnets for the list of subnets to consider.
	// The IPAM algorithm should consider the expected maximum usage of every subnet
	// and allocate the space accordingly to avoid collisions or inefficient
	// address space usage.
	ContivCIDR *net.IPNet // can be nil

	// Subnet used by services.
	ServiceCIDR *net.IPNet

	// if set to true, DHCP is used to acquire IP for the main VPP interface
	// (NodeInterconnectCIDR does not have to be allocated in that case)
	NodeInterconnectDHCP bool

	// DefaultGateway is global option to set default gateway for nodes. Alternatively,
	// nodeConfig can be used
	DefaultGateway net.IP

	// Manually selected subnets (if ContivCIDR is defined, this is overridden
	// by IPAM's own allocation algorithm).
	CustomIPAMSubnets

	// SRv6 settings defining computation of SID/BSID for SRv6 locasids/policies
	SRv6Settings
}

// SRv6Settings hold all SID/BSID managment settings (SID/BSID is basically IPv6 address)
type SRv6Settings struct {
	// ServicePolicyBSIDSubnetCIDR is subnet applied to lowest k8s service IP to get unique
	// (per service,per node) binding sid for SRv6 policy
	ServicePolicyBSIDSubnetCIDR *net.IPNet
	// ServicePodLocalSIDSubnetCIDR is subnet applied to k8s service local pod backend IP to get unique sid
	// for SRv6 Localsid referring to local pod beckend using DX6 end function
	ServicePodLocalSIDSubnetCIDR *net.IPNet
	// ServiceHostLocalSIDSubnetCIDR is subnet applied to k8s service host pod backend IP to get unique sid
	// for SRv6 Localsid referring to local host beckend using DX6 end function
	ServiceHostLocalSIDSubnetCIDR *net.IPNet
	// ServiceNodeLocalSIDSubnetCIDR is subnet applied to node IP to get unique sid for SRv6 Localsid that is
	// intermediate segment routing to other nodes in Srv6 segment list (used in k8s services)
	ServiceNodeLocalSIDSubnetCIDR *net.IPNet
	// NodeToNodePodLocalSIDSubnetCIDR is subnet applied to node IP to get unique sid for SRv6 Localsid that is
	// the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into
	// pod VRF table (DT6 end function of localsid)
	NodeToNodePodLocalSIDSubnetCIDR *net.IPNet
	// NodeToNodeHostLocalSIDSubnetCIDR is subnet applied to node IP to get unique sid for SRv6 Localsid that
	// is the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into
	// main VRF table (DT6 end function of localsid)
	NodeToNodeHostLocalSIDSubnetCIDR *net.IPNet
	// NodeToNodePodPolicySIDSubnetCIDR is subnet applied to node IP to get unique bsid for SRv6 policy that
	// defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodePodLocalSIDSubnetCIDR`
	NodeToNodePodPolicySIDSubnetCIDR *net.IPNet
	// NodeToNodeHostPolicySIDSubnetCIDR is subnet applied to node IP to get unique bsid for SRv6 policy that
	// defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodeHostLocalSIDSubnetCIDR`.
	NodeToNodeHostPolicySIDSubnetCIDR *net.IPNet
	// SFCPolicyBSIDSubnetCIDR is subnet applied to SFC ID(trimmed hash of SFC name) to get unique binding
	// sid for SRv6 policy used in SFC
	SFCPolicyBSIDSubnetCIDR *net.IPNet
	// SFCServiceFunctionSIDSubnetCIDR is subnet applied to combination of SFC ID(trimmed hash of SFC name) and
	// service function pod IP address to get unique sid for SRv6 Localsid referring to SFC service function
	SFCServiceFunctionSIDSubnetCIDR *net.IPNet
	// SFCEndLocalSIDSubnetCIDR is subnet applied to the IP address of last link of SFC to get unique sid
	// for last localsid in the segment routing path representing SFC chain
	SFCEndLocalSIDSubnetCIDR *net.IPNet
	// SFCIDLengthUsedInSidForServiceFunction is length(in bits) of SFC ID(trimmed hash of SFC name) that
	// should be used by computing SFC ServiceFunction localsid SID. A hash is computed from SFC name,
	// trimmed by length (this setting) and used in computation of SFC ServiceFunction localsid SID
	// (SID=prefix from sfcServiceFunctionSIDSubnetCIDR + trimmed hash of SFC name + service function pod
	// IP address).
	SFCIDLengthUsedInSidForServiceFunction uint8
}

// CustomIPAMSubnets allows users to manually select individual subnets.
// IPAM implementation should respect the selection, but only if ContivCIDR
// is undefined. Otherwise, the IPAM module is responsible for calculating the
// subnets by dissecting ContivCIDR by its own algorithm.
type CustomIPAMSubnets struct {
	// Subnet from which individual POD networks are allocated.
	// This is subnet for all PODs across all nodes.
	PodSubnetCIDR *net.IPNet

	// Prefix length of subnet used for all PODs within 1 node.
	PodSubnetOneNodePrefixLen uint8

	// Subnet used across all nodes for VPP to host Linux stack interconnect.
	VPPHostSubnetCIDR *net.IPNet

	// Prefix length of subnet used for VPP to host stack interconnect
	// within 1 node.
	VPPHostSubnetOneNodePrefixLen uint8

	// Subnet used for inter-node connections.
	NodeInterconnectCIDR *net.IPNet

	// Subnet used for inter-node VXLANs.
	VxlanCIDR *net.IPNet
}

// STNConfig groups config options related to STN (Steal-the-NIC).
type STNConfig struct {
	StealInterface string // can be empty if the interface is already stolen
	STNRoutes      []*stn_grpc.STNReply_Route
	STNSocketFile  string
	STNVersion     uint8
}

// Vmxnet3Config groups config options related to Vmxnet3 feature.
type Vmxnet3Config struct {
	MainInterfaceName       string // main interface name as seen by VPP
	MainInterfacePCIAddress string // PCI address of the main interface
}

// OtherInterfaceConfig represents configuration for a non-main VPP interface.
type OtherInterfaceConfig struct {
	InterfaceName string
	UseDHCP       bool
	IPs           IPsWithNetworks
}

// OtherInterfaces is a list of other interfaces.
type OtherInterfaces []*OtherInterfaceConfig

// String return string representation of configurations for other interfaces.
func (ifaces OtherInterfaces) String() string {
	str := "["
	first := true
	for _, iface := range ifaces {
		if !first {
			str += ", "
		}
		first = false
		str += fmt.Sprintf("{name:%s, useDHCP:%t, IPs: %s}",
			iface.InterfaceName, iface.UseDHCP, iface.IPs)
	}
	str += "]"
	return str
}

// IPWithNetwork encapsulates IP address with the network address.
type IPWithNetwork struct {
	Version IPVersion
	Address net.IP
	Network *net.IPNet
}

// IPVersion is either v4 or v6.
type IPVersion int

const (
	// IPv4 represents IP version 4.
	IPv4 IPVersion = iota
	// IPv6 represents IP version 6.
	IPv6
)

// IPsWithNetworks is a list of pairs (address, network).
type IPsWithNetworks []*IPWithNetwork

// String return string representation of IP addresses with networks.
func (ips IPsWithNetworks) String() string {
	str := "["
	first := true
	for _, ip := range ips {
		if !first {
			str += ", "
		}
		first = false
		str += fmt.Sprintf("(%s, %s)", ip.Address.String(), ip.Network.String())
	}
	str += "]"
	return str
}

/************************** Node Config Change Event **************************/

// NodeConfigChange is triggered when Node configuration provided via CRD changes.
// The event is handled by UpstreamResync - the plugins should re-read
// the configuration provided by ContivConf and re-calculate the state accordingly.
type NodeConfigChange struct {
	// not exported - plugins are expected to use ContivConf API to re-read
	// the configuration after the change
	nodeConfig *config.NodeConfig
}

// GetName returns name of the NodeConfigChange event.
func (ev *NodeConfigChange) GetName() string {
	return "Node-specific Configuration Change"
}

// String describes NodeIPv4Change event.
func (ev *NodeConfigChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* STN interface: %s\n"+
		"* Main interface: (name=%s, IP=%s, useDHCP=%t)\n"+
		"* GW: %s\n"+
		"* NAT external traffic: %t\n"+
		"* Other interfaces: %+v",
		ev.GetName(), ev.nodeConfig.StealInterface,
		ev.nodeConfig.MainVPPInterface.InterfaceName, ev.nodeConfig.MainVPPInterface.IP,
		ev.nodeConfig.MainVPPInterface.UseDHCP, ev.nodeConfig.Gateway,
		ev.nodeConfig.NatExternalTraffic, ev.nodeConfig.OtherVPPInterfaces)
}

// Method is UpstreamResync.
func (ev *NodeConfigChange) Method() controller.EventMethodType {
	return controller.UpstreamResync
}

// IsBlocking returns false.
func (ev *NodeConfigChange) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *NodeConfigChange) Done(error) {
	return
}
