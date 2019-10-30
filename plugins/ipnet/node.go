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

package ipnet

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	customnetmodel "github.com/contiv/vpp/plugins/crd/handler/customnetwork/model"
	extifmodel "github.com/contiv/vpp/plugins/crd/handler/externalinterface/model"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/srv6"
	"github.com/ligato/vpp-agent/pkg/models"
	"github.com/pkg/errors"
)

/* Main VPP interface */
const (
	loopbackNICLogicalName = "loopbackNIC" // logical name of the loopback interface configured instead of physical NICs
)

/* VXLANs */
const (
	// VXLAN Network Identifier (or VXLAN Segment ID) for the default pod network
	defaultPodVxlanVNI = 10

	// name of the VXLAN for the default pod network
	defaultPodVxlanName = "default"

	// as VXLAN tunnels are added to a BD, they must be configured with the same
	// and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may
	// loop among servers with the same VXLAN segment because VXLAN tunnels are fully
	// meshed among servers.
	vxlanSplitHorizonGroup = 1

	// vxlanBVIInterfacePrefix is the name prefix of the VXLAN BVI interface.
	vxlanBVIInterfacePrefix = "vxlanBVI"

	// DefaultVxlanBVIInterfaceName name of the VXLAN interface for the default pod network.
	DefaultVxlanBVIInterfaceName = vxlanBVIInterfacePrefix

	// name prefix of the VXLAN bridge domain
	vxlanBDNamePrefix = "vxlanBD"

	// podGwLoopbackInterfaceName is the name of the POD gateway loopback interface.
	podGwLoopbackInterfaceName = "podGwLoop"

	// VxlanVniPoolName is name for the ID pool of VXLAN VNIs
	VxlanVniPoolName  = "vni"
	vxlanVNIPoolStart = 5000    // to leave enough space for custom config of the vswitch
	vxlanVNIPoolEnd   = 1 << 24 // given by VXLAN header

	// vrfPoolName is name for the ID pool of VRFs
	vrfPoolName  = "vrf"
	vrfPoolStart = 10         // to leave enough space for custom config of the vswitch
	vrfPoolEnd   = ^uint32(0) // VRF is uint32
)

// customNetworkInfo holds information about a custom network
type customNetworkInfo struct {
	config *customnetmodel.CustomNetwork
	// list of local pods in custom network
	localPods map[string]*podmanager.LocalPod
	// list of local interfaces (pod + external) in custom network
	localInterfaces []string
	// list of all pods in custom network
	pods map[string]*podmanager.Pod
	// list of all external interfaces in custom network
	extInterfaces map[string]*extifmodel.ExternalInterface
	// list of all interfaces (pod + external) in custom network
	// (map[pod ID/external interface name]=list of interfaces for that pod/external interface)
	interfaces map[string][]string
}

// prefix for the hardware address of VXLAN interfaces
var vxlanBVIHwAddrPrefix = []byte{0x12, 0x2b}

/********************** Other Node Connectivity Configuration ***********************/

// otherNodeConnectivityConfig return configuration used to connect this node with the given other node.
func (n *IPNet) otherNodeConnectivityConfig(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	// VXLAN for the default pod network
	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport && len(n.nodeIP) > 0 {
		vxlanCfg := n.vxlanToOtherNodeConfig(node, DefaultPodNetworkName, defaultPodVxlanVNI)
		mergeConfiguration(config, vxlanCfg)
	}

	// VXLANs for custom networks
	for _, nw := range n.customNetworks {
		// get the VNI of the VXLAN
		vni, err := n.GetOrAllocateVxlanVNI(nw.config.Name)
		if err != nil {
			return config, err
		}
		if nw.config != nil && nw.config.Type == customnetmodel.CustomNetwork_L2 {
			vxlanCfg := n.vxlanToOtherNodeConfig(node, nw.config.Name, vni)
			mergeConfiguration(config, vxlanCfg)
		}
		if nw.config != nil && nw.config.Type == customnetmodel.CustomNetwork_L3 &&
			n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
			vxlanCfg := n.vxlanToOtherNodeConfig(node, nw.config.Name, vni)
			mergeConfiguration(config, vxlanCfg)
		}
	}

	nextHop, err := n.otherNodeNextHopIP(node)
	if err != nil {
		n.Log.Error(err)
		return config, err
	}

	// route to pods of the other node
	if !n.ContivConf.GetIPAMConfig().UseExternalIPAM { // skip in case that external IPAM is in use
		podsCfg, err := n.connectivityToOtherNodePods(DefaultPodNetworkName, node.ID, nextHop)
		if err != nil {
			n.Log.Error(err)
			return config, err
		}
		mergeConfiguration(config, podsCfg)
	}

	// routes to pods in L3 custom networks
	for _, nw := range n.customNetworks {
		if nw.config != nil && nw.config.Type == customnetmodel.CustomNetwork_L3 {
			podsCfg, err := n.connectivityToOtherNodePods(nw.config.Name, node.ID, nextHop)
			if err != nil {
				n.Log.Error(err)
				return config, err
			}
			mergeConfiguration(config, podsCfg)
		}
	}

	// route to the host stack of the other node
	hostStackCfg, err := n.connectivityToOtherNodeHostStack(node.ID, nextHop)
	if err != nil {
		n.Log.Error(err)
		return config, err
	}
	mergeConfiguration(config, hostStackCfg)

	// route to management IPs of the other node
	mgmIPConf, err := n.connectivityToOtherNodeManagementIPAddresses(node, nextHop)
	if err != nil {
		n.Log.Error(err)
		return config, err
	}
	mergeConfiguration(config, mgmIPConf)

	return config, nil
}

// vxlanToOtherNodeConfig returns configuration of the vxlan tunnel towards a remote node.
// If staticFib is true, also creates static ARP and FIB entries pointing to the remote node's BVI IP address.
func (n *IPNet) vxlanToOtherNodeConfig(node *nodesync.Node, network string, vni uint32) (
	config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)

	// get IP address of the node
	nodeIP, err := n.otherNodeIP(node)
	if err != nil {
		return config
	}

	// VXLAN interface
	key, vxlanIf := n.vxlanIfToOtherNode(network, vni, node.ID, nodeIP)
	config[key] = vxlanIf

	// ARP entry for the IP address on the opposite side
	vxlanIP, _, err := n.IPAM.VxlanIPAddress(node.ID)
	if err != nil {
		n.Log.Error(err)
		return config
	}
	key, vxlanArp := n.vxlanArpEntry(network, node.ID, vxlanIP)
	config[key] = vxlanArp

	// L2 FIB for the hardware address on the opposite side
	key, vxlanFib := n.vxlanFibEntry(network, node.ID)
	config[key] = vxlanFib
	return config
}

// otherNodeNextHopIP returns next hop address for routes towards the other node.
func (n *IPNet) otherNodeNextHopIP(node *nodesync.Node) (nextHop net.IP, err error) {

	switch n.ContivConf.GetRoutingConfig().NodeToNodeTransport {
	case contivconf.SRv6Transport:
		fallthrough // use NoOverlayTransport for other variables
	case contivconf.NoOverlayTransport:
		// route traffic destined to the other node directly
		if len(node.VppIPAddresses) > 0 {
			nextHop = node.VppIPAddresses[0].Address
		} else {
			nextHop, err = n.otherNodeIPFromID(node.ID)
			if err != nil {
				n.Log.Error(err)
				return nextHop, err
			}
		}
	case contivconf.VXLANTransport:
		// route traffic destined to the other node via VXLANs
		vxlanNextHop, _, err := n.IPAM.VxlanIPAddress(node.ID)
		if err != nil {
			n.Log.Error(err)
			return nextHop, err
		}
		nextHop = vxlanNextHop
	}
	return nextHop, err
}

/*********************************** DHCP *************************************/

var (
	// variable used only in the context of go routines running handleDHCPNotification
	lastDHCPLease *vpp_interfaces.DHCPLease
)

// handleDHCPNotifications handles DHCP state change notifications
func (n *IPNet) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	n.Log.Info("DHCP notification received")

	// check for validity of the DHCP event
	if notif.Del {
		lastDHCPLease = nil
		n.Log.Info("Ignoring event of removed DHCP lease")
		return
	}
	if !n.useDHCP {
		n.Log.Info("Ignoring DHCP event, dynamic IP address assignment is disabled")
		return
	}
	if notif.Value == nil {
		n.Log.Warn("DHCP notification metadata is empty")
		return
	}
	dhcpLease, isDHCPLease := notif.Value.(*vpp_interfaces.DHCPLease)
	if !isDHCPLease {
		n.Log.Warn("Received invalid DHCP notification")
		return
	}
	if dhcpLease.InterfaceName != n.ContivConf.GetMainInterfaceName() {
		n.Log.Debugf("DHCP notification for a non-main interface (%s)",
			dhcpLease.InterfaceName)
		return
	}
	if proto.Equal(dhcpLease, lastDHCPLease) {
		// nothing has really changed, ignore
		n.Log.Info("Ignoring DHCP event - this lease was already processed")
		return
	}
	lastDHCPLease = dhcpLease

	// parse DHCP lease fields
	hostAddr, hostNet, defaultGw, err := n.parseDHCPLease(dhcpLease)
	if err != nil {
		return
	}

	// push event into the event loop
	n.EventLoop.PushEvent(&NodeIPv4Change{
		NodeIP:    hostAddr,
		NodeIPNet: hostNet,
		DefaultGw: defaultGw,
	})
	n.Log.Infof("Sent NodeIPv4Change event to the event loop for DHCP lease: %+v", *dhcpLease)
}

// parseDHCPLease parses fields of a DHCP lease.
func (n *IPNet) parseDHCPLease(lease *vpp_interfaces.DHCPLease) (hostAddr net.IP, hostNet *net.IPNet, defaultGw net.IP, err error) {
	// parse IP address of the default gateway
	if lease.RouterIpAddress != "" {
		defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
		if err != nil {
			n.Log.Errorf("Failed to parse DHCP route IP address: %v", err)
			return
		}
	}

	// parse host IP address and network
	if lease.HostIpAddress != "" {
		hostAddr, hostNet, err = net.ParseCIDR(lease.HostIpAddress)
		if err != nil {
			n.Log.Errorf("Failed to parse DHCP host IP address: %v", err)
			return
		}
	}
	return
}

/*********************** Global vswitch configuration *************************/

// enabledIPNeighborScan returns configuration for enabled IP neighbor scanning
// (used to clean up old ARP entries).
func (n *IPNet) enabledIPNeighborScan() (key string, config *vpp_l3.IPScanNeighbor) {
	ipScanConfig := n.ContivConf.GetIPNeighborScanConfig()
	config = &vpp_l3.IPScanNeighbor{
		Mode:           vpp_l3.IPScanNeighbor_IPv4,
		ScanInterval:   uint32(ipScanConfig.IPNeighborScanInterval),
		StaleThreshold: uint32(ipScanConfig.IPNeighborStaleThreshold),
	}
	key = vpp_l3.IPScanNeighborKey()
	return key, config
}

/************************************ NICs ************************************/

// externalInterfaceConfig returns configuration of an external interface of the vswitch VPP.
func (n *IPNet) externalInterfaceConfig(extIf *extifmodel.ExternalInterface, eventType configEventType) (
	config controller.KeyValuePairs, updateConfig controller.KeyValuePairs, err error) {

	config = make(controller.KeyValuePairs)
	updateConfig = make(controller.KeyValuePairs)
	myNodeName := n.ServiceLabel.GetAgentLabel()

	for _, nodeIf := range extIf.Nodes {
		if nodeIf.Node == myNodeName {
			// parse IP address
			var ip contivconf.IPsWithNetworks
			if nodeIf.Ip != "" {
				ipAddr, ipNet, err := net.ParseCIDR(nodeIf.Ip)
				if err != nil {
					n.Log.Warnf("Unable to parse interface %s IP: %v", nodeIf.VppInterfaceName, err)
				} else {
					ip = contivconf.IPsWithNetworks{&contivconf.IPWithNetwork{Address: ipAddr, Network: ipNet}}
				}
			}
			vppIfName := nodeIf.VppInterfaceName
			vrf := n.ContivConf.GetRoutingConfig().MainVRFID
			if n.isDefaultPodNetwork(extIf.Network) || n.isL3Network(extIf.Network) {
				vrf, _ = n.GetOrAllocateVrfID(extIf.Network)
			}
			if nodeIf.Vlan == 0 {
				// standard interface config
				key, iface := n.physicalInterface(nodeIf.VppInterfaceName, vrf, ip)
				config[key] = iface
			} else {
				// VLAN subinterface config (main interface with no IP + subinterface)
				key, iface := n.physicalInterface(nodeIf.VppInterfaceName, vrf, nil)
				config[key] = iface
				key, iface = n.subInterface(nodeIf.VppInterfaceName, vrf, nodeIf.Vlan, ip)
				config[key] = iface
				vppIfName = iface.Name
			}
			if !n.isDefaultPodNetwork(extIf.Network) && !n.isStubNetwork(extIf.Network) {
				// post-configure interface in custom network
				n.cacheCustomNetworkInterface(extIf.Network, nil, nil, extIf, vppIfName,
					true, eventType != configDelete)
				if n.isL2Network(extIf.Network) {
					bdKey, bd := n.l2CustomNwBridgeDomain(n.customNetworks[extIf.Network])
					updateConfig[bdKey] = bd
				}
			}
		}
	}
	return
}

// physicalInterface returns configuration for physical interface - either the main interface
// connecting node with the rest of the cluster or an extra physical interface requested
// in the config file.
func (n *IPNet) physicalInterface(name string, vrf uint32, ips contivconf.IPsWithNetworks) (key string, config *vpp_interfaces.Interface) {
	ifConfig := n.ContivConf.GetInterfaceConfig()
	iface := &vpp_interfaces.Interface{
		Name:    name,
		Type:    vpp_interfaces.Interface_DPDK,
		Enabled: true,
		Vrf:     vrf,
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	if n.ContivConf.UseVmxnet3() {
		iface.Type = vpp_interfaces.Interface_VMXNET3_INTERFACE
		iface.Link = &vpp_interfaces.Interface_VmxNet3{
			VmxNet3: &vpp_interfaces.VmxNet3Link{
				RxqSize: uint32(ifConfig.Vmxnet3RxRingSize),
				TxqSize: uint32(ifConfig.Vmxnet3TxRingSize),
			},
		}
	}
	if interfaceRxModeType(ifConfig.InterfaceRxMode) != vpp_interfaces.Interface_RxMode_DEFAULT {
		iface.RxModes = []*vpp_interfaces.Interface_RxMode{
			{
				DefaultMode: true,
				Mode:        interfaceRxModeType(ifConfig.InterfaceRxMode),
			},
		}
	}
	key = vpp_interfaces.InterfaceKey(name)
	return key, iface
}

// subInterface returns configuration for a VLAN subinterface of an interface.
func (n *IPNet) subInterface(parentIfName string, vrf uint32, vlan uint32, ips contivconf.IPsWithNetworks) (
	key string, config *vpp_interfaces.Interface) {
	iface := &vpp_interfaces.Interface{
		Name:    n.getSubInterfaceName(parentIfName, vlan),
		Type:    vpp_interfaces.Interface_SUB_INTERFACE,
		Enabled: true,
		Vrf:     vrf,
		Link: &vpp_interfaces.Interface_Sub{
			Sub: &vpp_interfaces.SubInterface{
				ParentName: parentIfName,
				SubId:      vlan,
			},
		},
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = vpp_interfaces.InterfaceKey(iface.Name)
	return key, iface
}

// getSubInterfaceName returns logical name for a VLAN subinterface of an interface.
func (n *IPNet) getSubInterfaceName(parentIfName string, vlan uint32) string {
	return fmt.Sprintf("%s.%d", parentIfName, vlan)
}

// loopbackInterface returns configuration for loopback created when no physical interfaces
// are configured.
func (n *IPNet) loopbackInterface(ips contivconf.IPsWithNetworks) (key string, config *vpp_interfaces.Interface) {
	iface := &vpp_interfaces.Interface{
		Name:    loopbackNICLogicalName,
		Type:    vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	for _, ip := range ips {
		iface.IpAddresses = append(iface.IpAddresses, ipNetToString(combineAddrWithNet(ip.Address, ip.Network)))
	}
	key = vpp_interfaces.InterfaceKey(loopbackNICLogicalName)
	return key, iface
}

// defaultRoute return configuration for default route connecting the node with the outside world.
func (n *IPNet) defaultRoute(gwIP net.IP, outIfName string) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		DstNetwork:        anyNetAddrForAF(gwIP),
		NextHopAddr:       gwIP.String(),
		OutgoingInterface: outIfName,
		VrfId:             n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = models.Key(route)
	return key, route
}

/************************************ VRFs ************************************/

// vrfMainTables returns main VRF tables (each for each sub-address family (SAFI), e.g. IPv4, IPv6)
func (n *IPNet) vrfMainTables() map[string]*vpp_l3.VrfTable {
	tables := make(map[string]*vpp_l3.VrfTable)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// Note: we are explicitly creating vrf tables even with zero vrf id (zero vrf tables are created automatically)
	// to get uniform vrf table labeling in all cases
	k, v := n.vrfTable(routingCfg.MainVRFID, vpp_l3.VrfTable_IPV4, "mainVRF")
	tables[k] = v
	if n.ContivConf.GetIPAMConfig().UseIPv6 ||
		n.ContivConf.GetRoutingConfig().UseSRv6ForServices ||
		n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.SRv6Transport {
		k, v := n.vrfTable(routingCfg.MainVRFID, vpp_l3.VrfTable_IPV6, "mainVRF")
		tables[k] = v
	}

	return tables
}

// vrfTablesForPods returns VRF tables for networking between pods.
func (n *IPNet) vrfTablesForPods() map[string]*vpp_l3.VrfTable {
	tables := make(map[string]*vpp_l3.VrfTable)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if !n.ContivConf.GetIPAMConfig().UseIPv6 {
		k, v := n.vrfTable(routingCfg.PodVRFID, vpp_l3.VrfTable_IPV4, "podVRF")
		tables[k] = v
	}
	if n.ContivConf.GetIPAMConfig().UseIPv6 ||
		n.ContivConf.GetRoutingConfig().UseSRv6ForServices {
		k, v := n.vrfTable(routingCfg.PodVRFID, vpp_l3.VrfTable_IPV6, "podVRF")
		tables[k] = v
	}

	return tables
}

// vrfTable creates configuration for VRF table and adds it to the tables <tables>
func (n *IPNet) vrfTable(vrfID uint32, protocol vpp_l3.VrfTable_Protocol, label string) (string, *vpp_l3.VrfTable) {
	n.Log.Infof("Creating VRF table configuration: vrfID=%v, protocol=%v, label(without protocol)=%v", vrfID, protocol, label)

	// creating vrf config
	protocolStr := "IPv4"
	if protocol == vpp_l3.VrfTable_IPV6 {
		protocolStr = "IPv6"
	}
	vrf := &vpp_l3.VrfTable{
		Id:       vrfID,
		Protocol: protocol,
		Label:    label + "-" + protocolStr,
	}

	// adding it to tables
	key := vpp_l3.VrfTableKey(vrf.Id, vrf.Protocol)
	return key, vrf
}

// routesPodToMainVRF returns non-drop routes from default Pod VRF to Main VRF.
func (n *IPNet) routesPodToMainVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	// by default to go from Pod VRF via Main VRF
	r1 := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  anyNetAddrForAF(n.IPAM.PodGatewayIP(DefaultPodNetworkName)),
		VrfId:       routingCfg.PodVRFID,
		ViaVrfId:    routingCfg.MainVRFID,
		NextHopAddr: anyAddrForAF(n.IPAM.PodGatewayIP(DefaultPodNetworkName)),
	}
	r1Key := models.Key(r1)
	routes[r1Key] = r1

	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
		// host network (this node) routed from Pod VRF via Main VRF
		// (only needed for overly mode (VXLAN), to have better prefix match so that the drop route is not in effect)
		r2 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.HostInterconnectSubnetThisNode().String(),
			VrfId:       routingCfg.PodVRFID,
			ViaVrfId:    routingCfg.MainVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.HostInterconnectSubnetThisNode().IP),
		}
		r2Key := models.Key(r2)
		routes[r2Key] = r2
	}

	return routes
}

// routesMainToPodVRF returns non-drop routes from Main VRF to default Pod VRF.
func (n *IPNet) routesMainToPodVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
		// pod subnet (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.PodSubnetAllNodes(DefaultPodNetworkName).String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.PodSubnetAllNodes(DefaultPodNetworkName).IP),
		}
		r1Key := models.Key(r1)
		routes[r1Key] = r1

		// host network (all nodes) routed from Main VRF via Pod VRF (to go via VXLANs)
		r2 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.HostInterconnectSubnetAllNodes().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.HostInterconnectSubnetAllNodes().IP),
		}
		r2Key := models.Key(r2)
		routes[r2Key] = r2
	} else {
		// pod subnet (this node only) routed from Main VRF to Pod VRF
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.PodSubnetThisNode(DefaultPodNetworkName).String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.PodSubnetThisNode(DefaultPodNetworkName).IP),
		}
		r1Key := models.Key(r1)
		routes[r1Key] = r1
	}

	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		// service subnet routed from Main VRF to Pod VRF
		r1 := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  n.IPAM.ServiceNetwork().String(),
			VrfId:       routingCfg.MainVRFID,
			ViaVrfId:    routingCfg.PodVRFID,
			NextHopAddr: anyAddrForAF(n.IPAM.ServiceNetwork().IP),
		}
		r1Key := models.Key(r1)
		routes[r1Key] = r1
	}

	return routes
}

// dropRoutesIntoPodVRF returns drop routes for default Pod VRF.
func (n *IPNet) dropRoutesIntoPodVRF() map[string]*vpp_l3.Route {
	routes := make(map[string]*vpp_l3.Route)
	routingCfg := n.ContivConf.GetRoutingConfig()

	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		// drop packets destined to service subnet with no more specific routes
		r1 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.ServiceNetwork())
		r1Key := models.Key(r1)
		routes[r1Key] = r1
	}

	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
		// drop packets destined to pods no longer deployed
		r1 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.PodSubnetAllNodes(DefaultPodNetworkName))
		r1Key := models.Key(r1)
		routes[r1Key] = r1

		// drop packets destined to nodes no longer deployed
		r2 := n.dropRoute(routingCfg.PodVRFID, n.IPAM.HostInterconnectSubnetAllNodes())
		r2Key := models.Key(r2)
		routes[r2Key] = r2
	}

	return routes
}

// dropRoute is a helper method to construct drop route.
func (n *IPNet) dropRoute(vrfID uint32, dstAddr *net.IPNet) *vpp_l3.Route {
	return &vpp_l3.Route{
		Type:        vpp_l3.Route_DROP,
		DstNetwork:  dstAddr.String(),
		VrfId:       vrfID,
		NextHopAddr: anyAddrForAF(dstAddr.IP),
	}
}

// podGwLoopback returns configuration of the loopback interface used in the POD VRF
// to respond on POD gateway IP address.
func (n *IPNet) podGwLoopback(network string, vrf uint32) (key string, config *vpp_interfaces.Interface) {
	lo := &vpp_interfaces.Interface{
		Name:    n.podGwLoopbackInterfaceName(network),
		Type:    vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(
			n.IPAM.PodGatewayIP(network), n.IPAM.PodSubnetThisNode(network)))},
		Vrf: vrf,
	}
	key = vpp_interfaces.InterfaceKey(lo.Name)
	return key, lo
}

// podGwLoopbackInterfaceName returns the name of the loopback interface for pod default gateway.
func (n *IPNet) podGwLoopbackInterfaceName(network string) string {
	if network == "" || network == DefaultPodNetworkName {
		return podGwLoopbackInterfaceName
	}
	return podGwLoopbackInterfaceName + "-" + network
}

/************************** Custom Networks **************************/

// customNetworkConfig returns configuration of a custom netwok on the vswitch VPP.
func (n *IPNet) customNetworkConfig(nwConfig *customnetmodel.CustomNetwork, eventType configEventType) (
	config controller.KeyValuePairs, err error) {

	config = make(controller.KeyValuePairs)

	nw := n.customNetworks[nwConfig.Name]
	if nw == nil {
		nw = &customNetworkInfo{
			config:        nwConfig,
			localPods:     map[string]*podmanager.LocalPod{},
			pods:          map[string]*podmanager.Pod{},
			extInterfaces: map[string]*extifmodel.ExternalInterface{},
			interfaces:    map[string][]string{},
		}
		n.customNetworks[nwConfig.Name] = nw
	} else {
		nw.config = nwConfig
	}

	// get / allocate a VNI for the VXLAN
	vni, err := n.GetOrAllocateVxlanVNI(nwConfig.Name)
	if err != nil {
		return config, err
	}

	if nwConfig.Type == customnetmodel.CustomNetwork_L2 {
		// VXLANs to the other nodes
		for _, node := range n.getRemoteNodesWithIP() {
			vxlanCfg := n.vxlanToOtherNodeConfig(node, nw.config.Name, vni)
			mergeConfiguration(config, vxlanCfg)
		}
		// bridge domain for local & VXLAN interfaces
		bdKey, bd := n.l2CustomNwBridgeDomain(nw)
		config[bdKey] = bd

		// in case of delete event, release the VXLAN VNI
		if eventType == configDelete {
			n.ReleaseVxlanVNI(nwConfig.Name)
		}
	}
	if nwConfig.Type == customnetmodel.CustomNetwork_L3 {
		// get / allocate a VRF ID
		vrfID, err := n.GetOrAllocateVrfID(nwConfig.Name)
		if err != nil {
			return config, err
		}

		// VRF for custom interfaces
		proto := vpp_l3.VrfTable_IPV4
		if isIPv6Str(nwConfig.SubnetCIDR) {
			proto = vpp_l3.VrfTable_IPV6
		}
		vrfKey, vrf := n.vrfTable(vrfID, proto, nwConfig.Name)
		config[vrfKey] = vrf

		// loopback with the gateway IP address for PODs
		// - used as the unnumbered IP for the POD facing interfaces
		key, loop := n.podGwLoopback(nwConfig.Name, vrfID)
		config[key] = loop

		// VXLAN BD + BVI
		key, bd := n.vxlanBridgeDomain(nwConfig.Name)
		config[key] = bd
		key, bvi, _ := n.vxlanBVILoopback(nwConfig.Name, vrfID)
		config[key] = bvi

		// connectivity to the other nodes
		for _, node := range n.getRemoteNodesWithIP() {
			// VXLANs to the other nodes
			if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
				vxlanCfg := n.vxlanToOtherNodeConfig(node, nw.config.Name, vni)
				mergeConfiguration(config, vxlanCfg)
			}

			// routes to pods in L3 custom networks
			nextHop, err := n.otherNodeNextHopIP(node)
			if err != nil {
				n.Log.Error(err)
				return config, err
			}
			routesCfg, err := n.connectivityToOtherNodePods(nw.config.Name, node.ID, nextHop)
			if err != nil {
				n.Log.Error(err)
				return config, err
			}
			mergeConfiguration(config, routesCfg)
		}

		// configure local pods with interfaces that belong to this network
		for _, pod := range nw.localPods {
			podCfg, _ := n.podCustomIfsConfig(pod, eventType)
			mergeConfiguration(config, podCfg)
		}
		// configure external interfaces that belong to this network
		for _, extIf := range nw.extInterfaces {
			ifCfg, _, _ := n.externalInterfaceConfig(extIf, eventType)
			mergeConfiguration(config, ifCfg)
		}

		// in case of delete event, release the VRF & VNI
		if eventType == configDelete {
			n.ReleaseVxlanVNI(nwConfig.Name)
			n.ReleaseVrfID(nwConfig.Name)
		}
	}

	if eventType == configDelete {
		n.customNetworks[nwConfig.Name].config = nil
	}

	return config, nil
}

// l2CustomNwBridgeDomain returns configuration for the bridge domain of a L2 custom network.
func (n *IPNet) l2CustomNwBridgeDomain(nw *customNetworkInfo) (key string, config *vpp_l2.BridgeDomain) {
	if nw == nil {
		return "", nil
	}
	bd := &vpp_l2.BridgeDomain{
		Name:                nw.config.Name,
		Learn:               true,
		Forward:             true,
		Flood:               true,
		UnknownUnicastFlood: true,
	}
	// local interfaces
	// SplitHorizonGroup must be zero for these!
	for _, iface := range nw.localInterfaces {
		bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
			Name: iface,
		})
	}
	// VXLANs to the other nodes
	for _, node := range n.getRemoteNodesWithIP() {
		bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
			Name:              n.nameForVxlanToOtherNode(nw.config.Name, node.ID),
			SplitHorizonGroup: vxlanSplitHorizonGroup,
		})
	}
	key = vpp_l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// cacheCustomNetworkInterface caches interface-related information for later use in custom networks.
// The local pod, pod or extIf arguments can be null.
func (n *IPNet) cacheCustomNetworkInterface(customNwName string, localPod *podmanager.LocalPod,
	pod *podmanager.Pod, extIf *extifmodel.ExternalInterface, ifName string, cacheForLocal bool, isAdd bool) {

	// custom network is not known yet create one
	nw := n.customNetworks[customNwName]
	if nw == nil {
		nw = &customNetworkInfo{
			localPods:     map[string]*podmanager.LocalPod{},
			pods:          map[string]*podmanager.Pod{},
			extInterfaces: map[string]*extifmodel.ExternalInterface{},
			interfaces:    map[string][]string{},
		}
		n.customNetworks[customNwName] = nw
	}

	// cache pods / interfaces belonging to this network
	if isAdd {
		if cacheForLocal {
			nw.localInterfaces = sliceAppendIfNotExists(nw.localInterfaces, ifName)

			if localPod != nil {
				nw.localPods[localPod.ID.String()] = localPod
			}
		} else {
			var key string
			if pod != nil {
				key = pod.ID.String()
			} else {
				key = extIf.Name
			}
			nw.interfaces[key] = sliceAppendIfNotExists(nw.interfaces[key], ifName)

			if pod != nil {
				nw.pods[pod.ID.String()] = pod
			}
			if extIf != nil {
				nw.extInterfaces[extIf.Name] = extIf
			}
		}
		if extIf != nil {
			nw.extInterfaces[extIf.Name] = extIf
		}
	} else {
		if cacheForLocal {
			nw.localInterfaces = sliceRemove(nw.localInterfaces, ifName)
			if localPod != nil {
				delete(nw.localPods, localPod.ID.String())
			}
		} else {
			var key string
			if pod != nil {
				key = pod.ID.String()
			} else {
				key = extIf.Name
			}
			nw.interfaces[key] = sliceRemove(nw.interfaces[key], ifName)
			if pod != nil {
				delete(nw.pods, pod.ID.String())
			}
			if extIf != nil {
				delete(nw.extInterfaces, extIf.Name)
			}
		}
		if extIf != nil {
			delete(nw.extInterfaces, extIf.Name)
		}
	}
}

// isDefaultPodNetwork returns true if provided network name is the default pod network.
func (n *IPNet) isDefaultPodNetwork(nwName string) bool {
	return nwName == DefaultPodNetworkName || nwName == ""
}

// isStubNetwork returns true if provided network name is the "stub" network (not connected anywhere).
func (n *IPNet) isStubNetwork(nwName string) bool {
	return nwName == stubNetworkName
}

// isL2Network returns true if provided network name is a layer 2 (switched) network.
func (n *IPNet) isL2Network(nwName string) bool {
	nw := n.customNetworks[nwName]
	if nw == nil || nw.config == nil {
		return false
	}
	return nw.config.Type == customnetmodel.CustomNetwork_L2
}

// isL3Network returns true if provided network name is a layer 3 (routed) network.
func (n *IPNet) isL3Network(nwName string) bool {
	nw := n.customNetworks[nwName]
	if nw == nil || nw.config == nil {
		return false
	}
	return nw.config.Type == customnetmodel.CustomNetwork_L3
}

/************************** Bridge Domain with VXLANs **************************/

// vxlanBVILoopback returns configuration of the loopback interfaces acting as BVI
// for the bridge domain with VXLAN interfaces.
func (n *IPNet) vxlanBVILoopback(network string, vrf uint32) (key string, config *vpp_interfaces.Interface, err error) {
	vxlanIP, vxlanIPNet, err := n.IPAM.VxlanIPAddress(n.NodeSync.GetNodeID())
	if err != nil {
		return "", nil, err
	}
	vxlan := &vpp_interfaces.Interface{
		Name:        n.vxlanBVIInterfaceName(network),
		Type:        vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{ipNetToString(combineAddrWithNet(vxlanIP, vxlanIPNet))},
		PhysAddress: hwAddrForNodeInterface(n.NodeSync.GetNodeID(), vxlanBVIHwAddrPrefix),
		Vrf:         vrf,
	}
	key = vpp_interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan, nil
}

// vxlanBridgeDomain returns configuration for the bridge domain with VXLAN interfaces.
func (n *IPNet) vxlanBridgeDomain(network string) (key string, config *vpp_l2.BridgeDomain) {
	bd := &vpp_l2.BridgeDomain{
		Name:                n.vxlanBDName(network),
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*vpp_l2.BridgeDomain_Interface{
			{
				Name:                    n.vxlanBVIInterfaceName(network),
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
	for _, node := range n.getRemoteNodesWithIP() {
		bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
			Name:              n.nameForVxlanToOtherNode(network, node.ID),
			SplitHorizonGroup: vxlanSplitHorizonGroup,
		})
	}
	key = vpp_l2.BridgeDomainKey(bd.Name)
	return key, bd
}

// vxlanBDName returns name of the VXLAN bridge domain.
func (n *IPNet) vxlanBDName(network string) string {
	if network == "" || network == DefaultPodNetworkName {
		return vxlanBDNamePrefix
	}
	return vxlanBDNamePrefix + "-" + network
}

// vxlanBVIInterfaceName returns the name of the VXLAN BVI interface.
func (n *IPNet) vxlanBVIInterfaceName(network string) string {
	if network == "" || network == DefaultPodNetworkName {
		return vxlanBVIInterfacePrefix
	}
	return vxlanBVIInterfacePrefix + "-" + network
}

// nameForVxlanToOtherNode returns logical name to use for VXLAN interface
// connecting this node with the given other node.
func (n *IPNet) nameForVxlanToOtherNode(vxlanName string, otherNodeID uint32) string {
	return fmt.Sprintf("vxlan-%s-%d", vxlanName, otherNodeID)
}

// vxlanIfToOtherNode returns configuration for VXLAN interface connecting this node
// with the given other node.
func (n *IPNet) vxlanIfToOtherNode(vxlanName string, vni uint32, otherNodeID uint32, otherNodeIP net.IP) (
	key string, config *vpp_interfaces.Interface) {

	vxlan := &vpp_interfaces.Interface{
		Name: n.nameForVxlanToOtherNode(vxlanName, otherNodeID),
		Type: vpp_interfaces.Interface_VXLAN_TUNNEL,
		Link: &vpp_interfaces.Interface_Vxlan{
			Vxlan: &vpp_interfaces.VxlanLink{
				SrcAddress: n.nodeIP.String(),
				DstAddress: otherNodeIP.String(),
				Vni:        vni,
			},
		},
		Enabled: true,
		Vrf:     n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = vpp_interfaces.InterfaceKey(vxlan.Name)
	return key, vxlan
}

// vxlanArpEntry returns configuration for ARP entry resolving hardware address
// of the VXLAN BVI interface of another node.
func (n *IPNet) vxlanArpEntry(network string, otherNodeID uint32, vxlanIP net.IP) (key string, config *vpp_l3.ARPEntry) {
	arp := &vpp_l3.ARPEntry{
		Interface:   n.vxlanBVIInterfaceName(network),
		IpAddress:   vxlanIP.String(),
		PhysAddress: hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		Static:      true,
	}
	key = vpp_l3.ArpEntryKey(arp.Interface, arp.IpAddress)
	return key, arp
}

// vxlanFibEntry returns configuration for L2 FIB used inside the bridge domain with VXLANs
// to route traffic destinated to the given other node through the right VXLAN interface.
func (n *IPNet) vxlanFibEntry(network string, otherNodeID uint32) (key string, config *vpp_l2.FIBEntry) {
	fib := &vpp_l2.FIBEntry{
		BridgeDomain:            n.vxlanBDName(network),
		PhysAddress:             hwAddrForNodeInterface(otherNodeID, vxlanBVIHwAddrPrefix),
		OutgoingInterface:       n.nameForVxlanToOtherNode(defaultPodVxlanName, otherNodeID),
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  vpp_l2.FIBEntry_FORWARD,
	}
	key = vpp_l2.FIBKey(fib.BridgeDomain, fib.PhysAddress)
	return key, fib
}

// otherNodeIP returns IP address of the given other node
func (n *IPNet) otherNodeIP(node *nodesync.Node) (net.IP, error) {
	if len(node.VppIPAddresses) > 0 {
		return node.VppIPAddresses[0].Address, nil
	}
	nodeIP, err := n.otherNodeIPFromID(node.ID)
	if err != nil {
		n.Log.Error(err)
		return nil, err
	}
	return nodeIP, nil
}

// otherNodeIPFromID calculates the (statically selected) IP address of the given other node
func (n *IPNet) otherNodeIPFromID(otherNodeID uint32) (net.IP, error) {
	nodeIP, _, err := n.IPAM.NodeIPAddress(otherNodeID)
	if err != nil {
		err := fmt.Errorf("Failed to get Node IP address for node ID %v, error: %v ",
			otherNodeID, err)
		n.Log.Error(err)
		return nodeIP, err
	}
	return nodeIP, nil
}

/************************** SRv6 **************************/

// srv6NodeToNodeSegmentIngress creates configuration that routes SRv6 packet based on IPv6 routing to correct node.
// In compare to srv6NodeToNodeTunnelIngress, no encapsulation/decapsulation of SRv6 is done in node-to-node communication. This
// configuration is used when node-to-node communication using SRv6 is part of longer SRv6 path (i.e k8s services that extend
// the path to the service backend pods)
func (n *IPNet) srv6NodeToNodeSegmentIngress(otherNodeID uint32, nextHopIP net.IP) (config controller.KeyValuePairs, err error) {
	// getting info / preparing values
	config = make(controller.KeyValuePairs, 0)
	otherNodeIP, _, err := n.IPAM.NodeIPAddress(otherNodeID)
	if err != nil {
		return config, fmt.Errorf("unable to generate node IP address due to: %v", err)
	}
	sid := n.IPAM.SidForServiceNodeLocalsid(otherNodeIP)

	// create route for srv6-encapsulated packet to correct node
	_, ipNet, err := net.ParseCIDR(sid.To16().String() + "/128")
	if err != nil {
		return config, fmt.Errorf("unable to convert SID into IPv6 destination network: %v", err)
	}
	key, route := n.routeToOtherNodeNetworks(defaultPodVxlanName, ipNet, nextHopIP)
	if err != nil {
		n.Log.Error(err)
		return config, fmt.Errorf("unable create IPv6 route for SRv6 sid for k8s node: %v", err)
	}
	config[key] = route

	return config, nil

}

// srv6NodeToNodeDX6PodTunnelIngress creates configuration for ingress part of SRv6 node-to-node tunnel leading
// directly to remote pod (DX6 end function). It is expected that given pod has assigned IP address.
func (n *IPNet) srv6NodeToNodeDX6PodTunnelIngress(pod *podmodel.Pod) (config controller.KeyValuePairs, err error) {
	// retrieve all data
	podIP := net.ParseIP(pod.IpAddress)
	if podIP == nil { // can't create sids for SRv6 localsid/policy segment list
		return config, errors.Errorf("ignoring srv6 pod-to-pod tunnel creation due to not assigned IP(or unable to parse it from string %v) "+
			"to destination pod (pod id %+v)", pod.IpAddress, podmodel.GetID(pod))
	}
	podSteeringNetwork, err := addFullPrefixToIP(podIP)
	if err != nil {
		return config, errors.Wrapf(err, "srv6 node-to-node tunnel (using DX6 connecting to pod with ID %v) can't be created "+
			"due to error from computing steering network for pod IP address %v", podmodel.GetID(pod), podIP)
	}
	if !n.IPAM.PodSubnetAllNodes(DefaultPodNetworkName).Contains(podIP) {
		n.Log.Warnf("excluding pod %v from creating srv6 DX6 node-to-node tunnel for it because its IP address(%v) seems not to be from Pod "+
			"subnet. It is probably system pod with other IP address range ", podmodel.GetID(pod), podIP)
		return make(controller.KeyValuePairs, 0), nil
	}
	nodeID, err := n.IPAM.NodeIDFromPodIP(podIP)
	if err != nil {
		return config, errors.Wrapf(err, "srv6 node-to-node tunnel (using DX6 connecting to pod with ID %v) can't be created "+
			"due to error from computing node id from pod IP address %v", podmodel.GetID(pod), podIP)
	}
	nodeIP, _, err := n.IPAM.NodeIPAddress(nodeID)
	if err != nil {
		return config, errors.Wrapf(err, "srv6 node-to-node tunnel (using DX6 connecting to pod with ID %v) can't be created "+
			"due to error from computing node IP address from node ID %+v", podmodel.GetID(pod), nodeID)
	}
	bsid := n.IPAM.BsidForNodeToNodePodPolicy(podIP) // this can be the same value one many nodes for the same target other node because it is not part of path
	sid := n.IPAM.SidForNodeToNodePodLocalsid(podIP)

	// create tunnel
	return n.srv6NodeToNodeTunnelIngress(nodeIP, podSteeringNetwork, bsid, sid, "podCrossconnection")
}

// srv6NodeToNodePodTunnelIngress creates start node configuration for srv6 tunnel between nodes leading to pod VRF table
// lookup on the other side(SRv6 path steers and encapsulates traffic on start node side and decapsulates on end node side)
func (n *IPNet) srv6NodeToNodePodTunnelIngress(otherNodeID uint32, otherNodeIP net.IP, nextHopIP net.IP, podNetwork *net.IPNet) (config controller.KeyValuePairs, err error) {
	bsid := n.IPAM.BsidForNodeToNodePodPolicy(otherNodeIP) // this can be the same value one many nodes for the same target other node because it is not part of path
	sid := n.IPAM.SidForNodeToNodePodLocalsid(otherNodeIP)
	return n.srv6NodeToNodeTunnelIngress(nextHopIP, podNetwork, bsid, sid, "lookupInPodVRF")
}

// srv6NodeToNodePodTunnelIngress creates start node configuration for srv6 tunnel between nodes leading to main VRF table
// lookup(for host destination) on the other side(SRv6 path steers and encapsulates traffic on start node side and
// decapsulates on end node side)
func (n *IPNet) srv6NodeToNodeHostTunnelIngress(otherNodeID uint32, otherNodeIP net.IP, nextHopIP net.IP) (config controller.KeyValuePairs, err error) {
	hostNetwork, err := n.IPAM.HostInterconnectSubnetOtherNode(otherNodeID)
	if err != nil {
		return config, fmt.Errorf("Failed to compute host network for node ID %v, error: %v ", otherNodeID, err)
	}
	bsid := n.IPAM.BsidForNodeToNodeHostPolicy(otherNodeIP) // this can be the same value one many nodes for the same target other node because it is not part of path
	sid := n.IPAM.SidForNodeToNodeHostLocalsid(otherNodeIP)
	return n.srv6NodeToNodeTunnelIngress(nextHopIP, hostNetwork, bsid, sid, "lookupInMainVRF")
}

func (n *IPNet) srv6NodeToNodeTunnelIngress(nextHopIP net.IP, networkToSteer *net.IPNet, bsid net.IP, sid net.IP, nameSuffix string) (config controller.KeyValuePairs, err error) {
	// getting info / preparing values
	config = make(controller.KeyValuePairs, 0)

	// creating steering to steer all packets for pods of the other node
	steering := n.srv6NodeToNodeSteeringConfig(networkToSteer, bsid, nameSuffix)
	config[models.Key(steering)] = steering

	// create Srv6 policy to get to other node
	policy := &vpp_srv6.Policy{
		Bsid:             bsid.String(),
		SprayBehaviour:   false,
		SrhEncapsulation: true,
		SegmentLists: []*vpp_srv6.Policy_SegmentList{
			{
				Weight:   1,
				Segments: []string{sid.String()},
			},
		},
	}
	config[models.Key(policy)] = policy

	// create route for srv6-encapsulated packet to correct node
	_, ipNet, err := net.ParseCIDR(sid.To16().String() + "/128")
	if err != nil {
		return config, fmt.Errorf("unable to convert SID into IPv6 destination network: %v", err)
	}
	key, route := n.routeToOtherNodeNetworks(DefaultPodNetworkName, ipNet, nextHopIP)
	if err != nil {
		n.Log.Error(err)
		return config, fmt.Errorf("unable create IPv6 route for SRv6 sid for k8s node: %v", err)
	}
	config[key] = route

	return config, nil
}

// srv6NodeToNodeSteeringConfig returns configuration of SRv6 steering used to steer traffic into SRv6 node-to-node tunnel
func (n *IPNet) srv6NodeToNodeSteeringConfig(networkToSteer *net.IPNet, bsid net.IP, nameSuffix string) *vpp_srv6.Steering {
	steering := &vpp_srv6.Steering{
		Name: fmt.Sprintf("forNodeToNodeTunneling-usingPolicyWithBSID-%v-and-%v", bsid.String(), nameSuffix),
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				PrefixAddress:     networkToSteer.String(),
				InstallationVrfId: n.ContivConf.GetRoutingConfig().MainVRFID,
			},
		},
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
	}
	return steering
}

// srv6DX6PodTunnelEgress creates configuration for egress part of SRv6 node-to-node tunnel leading
// directly to remote pod (DX6 end function)
func (n *IPNet) srv6DX6PodTunnelEgress(sid net.IP, outgoingInterface string, nextHop net.IP) (key string, config *vpp_srv6.LocalSID, err error) {
	if !n.ContivConf.GetIPAMConfig().UseIPv6 {
		return "", nil, errors.New("supporting only full IPv6 environment from node-to-node SRv6 tunnel ending with DX6 connecting to pod")
	}
	localSID := &vpp_srv6.LocalSID{
		Sid:               sid.String(),
		InstallationVrfId: n.ContivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
			OutgoingInterface: outgoingInterface,
			NextHop:           nextHop.String(),
		}},
	}
	return models.Key(localSID), localSID, nil
}

// srv6PodTunnelEgress creates LocalSID for receiving node-to-node communication encapsulated in SRv6. This node is
// the receiving end that used this localSID to decapsulate the SRv6 traffic and forward it by pod VRF ipv6/ipv4 table lookup.
func (n *IPNet) srv6PodTunnelEgress(sid net.IP) (key string, config *vpp_srv6.LocalSID) {
	return n.srv6TunnelEgress(sid, n.ContivConf.GetRoutingConfig().PodVRFID)
}

// srv6PodTunnelEgress creates LocalSID for receiving node-to-node communication encapsulated in SRv6. This node is
// the receiving end that used this localSID to decapsulate the SRv6 traffic and forward it by main VRF ipv6/ipv4 table lookup (host destination).
func (n *IPNet) srv6HostTunnelEgress(sid net.IP) (key string, config *vpp_srv6.LocalSID) {
	return n.srv6TunnelEgress(sid, n.ContivConf.GetRoutingConfig().MainVRFID)
}

func (n *IPNet) srv6TunnelEgress(sid net.IP, lookupVrfID uint32) (key string, config *vpp_srv6.LocalSID) {
	localSID := &vpp_srv6.LocalSID{
		Sid:               sid.String(),
		InstallationVrfId: n.ContivConf.GetRoutingConfig().MainVRFID,
	}
	if n.ContivConf.GetIPAMConfig().UseIPv6 {
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT6{EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
			VrfId: lookupVrfID,
		}}
	} else {
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DT4{EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
			VrfId: lookupVrfID,
		}}
	}
	return models.Key(localSID), localSID
}

// srv6NodeToNodeSegmentEgress creates LocalSID for receiving node-to-node communication encapsulated in SRv6. This node is
// the receiving end that used this localSID just to end current segment of srv6 routing and continue with routing using
// next srv6 segment.
func (n *IPNet) srv6NodeToNodeSegmentEgress(sid net.IP) (key string, config *vpp_srv6.LocalSID) {
	localSID := &vpp_srv6.LocalSID{
		Sid:               sid.String(),
		InstallationVrfId: n.ContivConf.GetRoutingConfig().MainVRFID,
		EndFunction:       &vpp_srv6.LocalSID_BaseEndFunction{BaseEndFunction: &vpp_srv6.LocalSID_End{}},
	}
	return models.Key(localSID), localSID
}

/************************** Connectivity / routes to other nodes **************************/

// connectivityToOtherNodePods returns configuration that will route traffic to pods of another node.
func (n *IPNet) connectivityToOtherNodePods(network string, otherNodeID uint32, nextHopIP net.IP) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs, 0)
	podNetwork, err := n.IPAM.PodSubnetOtherNode(network, otherNodeID)
	if err != nil {
		return config, fmt.Errorf("Failed to compute pod network for node ID %v, error: %v ", otherNodeID, err)
	}

	switch n.ContivConf.GetRoutingConfig().NodeToNodeTransport {
	case contivconf.SRv6Transport:
		// get other node IP
		otherNodeIP, computeErr := n.otherNodeIPFromID(otherNodeID)
		if computeErr != nil {
			n.Log.Error(computeErr)
			return config, computeErr
		}

		// get pod tunnel config
		if !n.ContivConf.GetRoutingConfig().UseDX6ForSrv6NodetoNodeTransport { // pod tunnel uses DT6 -> can be created just on node create/update event, because further packet routing to pod is handled by routing table on other node
			podTunnelConfig, err := n.srv6NodeToNodePodTunnelIngress(otherNodeID, otherNodeIP, nextHopIP, podNetwork)
			if err != nil {
				return config, fmt.Errorf("can't create configuration for node-to-node SRv6 tunnel for Pod traffic due to: %v", err)
			}
			mergeConfiguration(config, podTunnelConfig)
		}

		// get config of tunnel ending with intermediate(not the last one in segment list) segment
		segmentConfig, err := n.srv6NodeToNodeSegmentIngress(otherNodeID, nextHopIP)
		if err != nil {
			return config, fmt.Errorf("can't create configuration for node passing SRv6 path due to: %v", err)
		}
		mergeConfiguration(config, segmentConfig)
	case contivconf.NoOverlayTransport:
		fallthrough // the same as for VXLANTransport
	case contivconf.VXLANTransport:
		key, route := n.routeToOtherNodeNetworks(network, podNetwork, nextHopIP)
		config[key] = route
	}

	return config, nil
}

// connectivityToOtherNodeHostStack returns configuration that will route traffic to the host stack of another node.
func (n *IPNet) connectivityToOtherNodeHostStack(otherNodeID uint32, nextHopIP net.IP) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs, 0)
	switch n.ContivConf.GetRoutingConfig().NodeToNodeTransport {
	case contivconf.SRv6Transport:
		// get other node IP
		otherNodeIP, computeErr := n.otherNodeIPFromID(otherNodeID)
		if computeErr != nil {
			n.Log.Error(computeErr)
			return config, computeErr
		}

		// get host tunnel config
		hostTunnelConfig, err := n.srv6NodeToNodeHostTunnelIngress(otherNodeID, otherNodeIP, nextHopIP)
		if err != nil {
			return config, fmt.Errorf("can't create configuration for node-to-node SRv6 tunnel for Host traffic due to: %v", err)
		}
		mergeConfiguration(config, hostTunnelConfig)
	case contivconf.NoOverlayTransport:
		fallthrough // the same as for VXLANTransport
	case contivconf.VXLANTransport:
		hostNetwork, err := n.IPAM.HostInterconnectSubnetOtherNode(otherNodeID)
		if err != nil {
			return nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", otherNodeID, err)
		}
		key, route := n.routeToOtherNodeNetworks(DefaultPodNetworkName, hostNetwork, nextHopIP)
		config[key] = route
	}
	return config, nil
}

// routeToOtherNodeNetworks is a helper function to build route for traffic destined to another node.
func (n *IPNet) routeToOtherNodeNetworks(network string, destNetwork *net.IPNet, nextHopIP net.IP) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP.String(),
	}
	switch n.ContivConf.GetRoutingConfig().NodeToNodeTransport {
	case contivconf.NoOverlayTransport:
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	case contivconf.SRv6Transport:
		route.VrfId = n.ContivConf.GetRoutingConfig().MainVRFID
	case contivconf.VXLANTransport:
		route.OutgoingInterface = n.vxlanBVIInterfaceName(network)
		if n.isDefaultPodNetwork(network) {
			route.VrfId = n.ContivConf.GetRoutingConfig().PodVRFID
		} else {
			route.VrfId, _ = n.GetOrAllocateVrfID(network)
		}
	}
	key = models.Key(route)
	return key, route
}

// connectivityToOtherNodeManagementIPAddresses returns configuration that will route traffic to the management ip addresses of another node.
func (n *IPNet) connectivityToOtherNodeManagementIPAddresses(node *nodesync.Node, nextHop net.IP) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs, 0)
	for _, mgmtIP := range node.MgmtIPAddresses {
		switch n.ContivConf.GetRoutingConfig().NodeToNodeTransport {
		case contivconf.SRv6Transport:
			// get other node IP
			otherNodeIP, computeErr := n.otherNodeIPFromID(node.ID)
			if computeErr != nil {
				n.Log.Error(computeErr)
				return config, computeErr
			}

			// get tunnel config for management traffic
			_, ipNet, err := net.ParseCIDR(mgmtIP.String() + fullPrefixForAF(mgmtIP))
			if err != nil {
				return config, fmt.Errorf("unable to convert management IP %v into IPv6 destination network: %v", mgmtIP, err)
			}
			bsid := n.IPAM.BsidForNodeToNodeHostPolicy(otherNodeIP) // reusing srv6 node-to-node tunnel meant for communication with other node's host stack (it ends with DT6/DT4 looking into main vrf)
			steering := n.srv6NodeToNodeSteeringConfig(ipNet, bsid, "managementIP-"+mgmtIP.String())
			config[models.Key(steering)] = steering
		case contivconf.NoOverlayTransport:
			// route management IP address towards the destination node
			key, mgmtRoute1 := n.routeToOtherNodeManagementIP(mgmtIP, nextHop, n.ContivConf.GetRoutingConfig().MainVRFID, "")
			if mgmtRoute1 != nil {
				config[key] = mgmtRoute1
			}
		case contivconf.VXLANTransport:
			// route management IP address towards the destination node
			key, mgmtRoute1 := n.routeToOtherNodeManagementIP(mgmtIP, nextHop, n.ContivConf.GetRoutingConfig().PodVRFID, n.vxlanBVIInterfaceName(DefaultPodNetworkName))
			if mgmtRoute1 != nil {
				config[key] = mgmtRoute1
			}

			// inter-VRF route for the management IP address
			if !n.ContivConf.InSTNMode() {
				key, mgmtRoute2 := n.routeToOtherNodeManagementIPViaPodVRF(mgmtIP)
				config[key] = mgmtRoute2
			}
		}
	}
	return config, nil
}

// routeToOtherNodeManagementIP returns configuration for route applied to traffic destined
// to a management IP of another node.
func (n *IPNet) routeToOtherNodeManagementIP(managementIP, nextHopIP net.IP, vrfID uint32, outgoingInterface string) (
	key string, config *vpp_l3.Route) {

	if managementIP.Equal(nextHopIP) {
		return "", nil
	}
	route := &vpp_l3.Route{
		DstNetwork:        managementIP.String() + hostPrefixForAF(managementIP),
		NextHopAddr:       nextHopIP.String(),
		VrfId:             vrfID,
		OutgoingInterface: outgoingInterface,
	}
	key = models.Key(route)
	return key, route
}

// routeToOtherNodeManagementIPViaPodVRF returns configuration for route used
// in Main VRF to direct traffic destined to management IP of another node
// to go via Pod VRF (and then further via VXLANs).
func (n *IPNet) routeToOtherNodeManagementIPViaPodVRF(managementIP net.IP) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  managementIP.String() + hostPrefixForAF(managementIP),
		VrfId:       n.ContivConf.GetRoutingConfig().MainVRFID,
		ViaVrfId:    n.ContivConf.GetRoutingConfig().PodVRFID,
		NextHopAddr: anyAddrForAF(managementIP),
	}
	key = models.Key(route)
	return key, route
}

// getRemoteNodesWithIP returns list of remote nodes with IP connectivity.
func (n *IPNet) getRemoteNodesWithIP() (nodes []*nodesync.Node) {
	if len(n.nodeIP) == 0 {
		return
	}
	for _, node := range n.NodeSync.GetAllNodes() {
		if node.Name == n.ServiceLabel.GetAgentLabel() {
			// skip current node
			continue
		}
		if !nodeHasIPAddress(node) {
			// skip node without IP addresses
			continue
		}
		nodes = append(nodes, node)
	}
	return
}

// nodeHasIPAddress returns true if the given node has at least one VPP and one management IP address assigned.
func nodeHasIPAddress(node *nodesync.Node) bool {
	return node != nil && (len(node.VppIPAddresses) > 0 && len(node.MgmtIPAddresses) > 0)
}

// clone creates a deep copy of customNetworkInfo.
func (cn *customNetworkInfo) clone() (i *customNetworkInfo) {
	res := &customNetworkInfo{
		config:        proto.Clone(cn.config).(*customnetmodel.CustomNetwork),
		localPods:     map[string]*podmanager.LocalPod{},
		pods:          map[string]*podmanager.Pod{},
		extInterfaces: map[string]*extifmodel.ExternalInterface{},
		interfaces:    map[string][]string{},
	}
	for k, v := range cn.localPods {
		res.localPods[k] = v
	}
	for _, v := range cn.localInterfaces {
		cn.localInterfaces = append(cn.localInterfaces, v)
	}
	for k, v := range cn.pods {
		res.pods[k] = v
	}
	for k, v := range cn.extInterfaces {
		res.extInterfaces[k] = v
	}
	for k, v := range cn.interfaces {
		newV := make([]string, len(v))
		copy(newV, v)
		res.interfaces[k] = newV
	}
	return res
}

// getNodeID get ID of specified node
func (n *IPNet) getNodeID(nodeName string) (uint32, bool) {
	if node, exists := n.NodeSync.GetAllNodes()[nodeName]; exists {
		return node.ID, true
	}
	return 0, false
}
