// Copyright (c) 2017 Cisco and/or its affiliates.
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

package ipv4net

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"
	intf_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	"github.com/contiv/vpp/plugins/ipv4net/ipam"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

const (
	// defaultSTNSocketFile is the default socket file path where contiv-stn GRPC server
	// listens for incoming requests.
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// interface host name length limit in Linux
	linuxIfNameMaxLen = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen = 63

	// any IPv4 address
	ipv4NetAny = "0.0.0.0/0"
)

// IPv4Net plugin builds configuration to be applied by ligato/VPP-agent for VPP-based
// IPv4 network connectivity between Kubernetes pods and nodes.
type IPv4Net struct {
	Deps

	*externalState
	*internalState
}

// externalState groups attributes/callbacks used to access the state of the system
// outside of the plugin.
// The attributes are set in the plugin Init phase. In the unit tests it is possible
// to override the original Init method and inject mocks instead.
type externalState struct {
	// set to true when running unit tests
	test bool

	// global configuration
	config *Config

	// IPAM module used by the plugin
	ipam *ipam.IPAM

	// GoVPP channel for direct binary API calls (not needed for UTs)
	govppCh api.Channel

	// VPP DHCP index map
	dhcpIndex idxmap.NamedMapping

	// dumping of physical interfaces
	physicalIfsDump PhysicalIfacesDumpClb

	// callback to receive information about a stolen interface
	getSTNInfo StolenInterfaceInfoClb

	// dumping of host IPs
	hostLinkIPsDump HostLinkIPsDumpClb
}

// internalState groups attributes representing the internal state of the plugin.
// The attributes are refreshed by Resync and updated during Update events.
type internalState struct {
	// node-specific configuration (can be updated)
	thisNodeConfig *NodeConfig

	// DHCP watching
	watchingDHCP bool // true if dhcpIndex is being watched
	useDHCP      bool // whether DHCP is disabled by the latest config (can be changed via CRD)

	// this node's main IP address and the default gateway
	nodeIP    net.IP
	nodeIPNet *net.IPNet
	defaultGw net.IP

	// IP addresses of this node present in the host network namespace (Linux)
	hostIPs []net.IP

	// pod ID from interface name
	vppIfaceToPodMutex sync.RWMutex
	vppIfaceToPod      map[string]podmodel.ID

	// name of the main physical interface
	mainPhysicalIf string

	// name of extra physical interfaces configured by the agent
	otherPhysicalIfs []string

	// routes going via stolen interface
	stnRoutes []*stn_grpc.STNReply_Route
}

// Deps groups the dependencies of the plugin.
type Deps struct {
	infra.PluginDeps
	EventLoop    controller.EventLoop
	ServiceLabel servicelabel.ReaderAPI
	NodeSync     nodesync.API
	PodManager   podmanager.API
	VPPIfPlugin  vpp_ifplugin.API
	GoVPP        govppmux.API
	HTTPHandlers rest.HTTPHandlers
}

// PhysicalIfacesDumpClb is callback for dumping physical interfaces on VPP.
type PhysicalIfacesDumpClb func() (ifaces map[uint32]string, err error) // interface index -> interface name

// StolenInterfaceInfoClb is callback for receiving information about a stolen interface.
type StolenInterfaceInfoClb func(ifName string) (reply *stn_grpc.STNReply, err error)

// HostLinkIPsDumpClb is callback for dumping all IP addresses assigned to interfaces
// in the host stack.
type HostLinkIPsDumpClb func() ([]net.IP, error)

/********************************** Plugin ************************************/

// Init initializes attributes/callbacks used to access the plugin-external state.
// Internal state is initialized later by the first resync.
func (n *IPv4Net) Init() error {
	n.internalState = &internalState{}
	n.externalState = &externalState{}

	// load config file
	if n.config == nil {
		if err := n.loadExternalConfig(); err != nil {
			return err
		}
	}

	// create GoVPP channel
	var err error
	n.govppCh, err = n.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	// get reference to map with DHCP leases
	n.dhcpIndex = n.VPPIfPlugin.GetDHCPIndex()

	// setup callbacks used to access external state
	n.physicalIfsDump = n.dumpPhysicalInterfaces
	n.getSTNInfo = n.getStolenInterfaceInfo
	n.hostLinkIPsDump = n.getHostLinkIPs

	// initialize IPAM
	n.ipam, err = ipam.New(n.Log, n.NodeSync, &n.config.IPAMConfig,
		n.excludedIPsFromNodeCIDR())
	if err != nil {
		return err
	}

	// register REST handlers
	n.registerRESTHandlers()

	return nil
}

// StateToString returns human-readable string representation of the ipv4net
// plugin internal state.
// The method cannot be called String(), otherwise it overloads the Stringer
// from PluginDeps.
func (s *internalState) StateToString() string {
	// pod ID by VPP interface name
	vppIfaceToPod := "{"
	first := true
	for vppIfName, podID := range s.vppIfaceToPod {
		if !first {
			vppIfaceToPod += ", "
		}
		first = false
		vppIfaceToPod += fmt.Sprintf("%s: %s", vppIfName, podID.String())
	}
	vppIfaceToPod += "}"

	return fmt.Sprintf("<thisNodeConfig: %+v, useDHCP: %t, watchingDHCP: %t, "+
		"mainPhysicalIf: %s, otherPhysicalIfs: %v, "+
		"nodeIP: %s, nodeIPNet: %s, defaultGw: %s, hostIPs: %v, "+
		"vppIfaceToPod: %s, stnRoutes: %v",
		s.thisNodeConfig, s.useDHCP, s.watchingDHCP,
		s.mainPhysicalIf, s.otherPhysicalIfs,
		s.nodeIP.String(), ipNetToString(s.nodeIPNet), s.defaultGw.String(), s.hostIPs,
		vppIfaceToPod, s.stnRoutes)
}

// Close is called by the plugin infra upon agent cleanup.
// It cleans up the resources allocated by the plugin.
func (n *IPv4Net) Close() error {
	_, err := safeclose.CloseAll(n.govppCh)
	return err
}

/********************************** Events ************************************/

// HandlesEvent selects:
//   - any Resync event (extra action for NodeIPv4Change)
//   - KubeStateChange for CRD node-specific config of this node
//   - AddPod and DeletePod
//   - NodeUpdate for other nodes
//   - Shutdown event
func (n *IPv4Net) HandlesEvent(event controller.Event) bool {
	myNodeName := n.ServiceLabel.GetAgentLabel()
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case nodeconfig.Keyword:
			// interested only in the node config for this node
			if ksChange.Key == nodeconfig.Key(myNodeName) {
				return true
			}

		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	if _, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return true
	}
	if _, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return true
	}
	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return nodeUpdate.NodeName != n.ServiceLabel.GetAgentLabel()
	}
	if _, isShutdown := event.(*controller.Shutdown); isShutdown {
		return true
	}

	// unhandled event
	return false
}

/**************************** IPv4Net plugin API ******************************/

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (n *IPv4Net) GetPodByIf(ifName string) (podNamespace string, podName string, exists bool) {
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()

	podID, found := n.vppIfaceToPod[ifName]
	if !found {
		return "", "", false
	}
	return podID.Namespace, podID.Name, true
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (n *IPv4Net) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	// check that the pod is locally deployed
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	pod, exists := n.PodManager.GetLocalPods()[podID]
	if !exists {
		return "", false
	}

	// check that the pod is attached to VPP network stack
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()
	vppIfName, _ := n.podInterfaceName(pod)
	_, configured := n.vppIfaceToPod[vppIfName]
	if !configured {
		return "", false
	}

	return vppIfName, true
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (n *IPv4Net) GetPodSubnet() *net.IPNet {
	return n.ipam.PodSubnetAllNodes()
}

// GetPodSubnetThisNode provides subnet used for allocating pod IP addresses on this node.
func (n *IPv4Net) GetPodSubnetThisNode() *net.IPNet {
	return n.ipam.PodSubnetThisNode()
}

// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
func (n *IPv4Net) InSTNMode() bool {
	return n.config.StealFirstNIC || n.config.StealInterface != "" ||
		(n.thisNodeConfig != nil && n.thisNodeConfig.StealInterface != "")
}

// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
// with node IP before being sent out from the node.
func (n *IPv4Net) NatExternalTraffic() bool {
	if n.config.NatExternalTraffic ||
		(n.thisNodeConfig != nil && n.thisNodeConfig.NatExternalTraffic) {
		return true
	}
	return false
}

// CleanupIdleNATSessions returns true if cleanup of idle NAT sessions is enabled.
func (n *IPv4Net) CleanupIdleNATSessions() bool {
	return n.config.CleanupIdleNATSessions
}

// GetTCPNATSessionTimeout returns NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (n *IPv4Net) GetTCPNATSessionTimeout() uint32 {
	return n.config.TCPNATSessionTimeout
}

// GetOtherNATSessionTimeout returns NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (n *IPv4Net) GetOtherNATSessionTimeout() uint32 {
	return n.config.OtherNATSessionTimeout
}

// GetServiceLocalEndpointWeight returns the load-balancing weight assigned to locally deployed service endpoints.
func (n *IPv4Net) GetServiceLocalEndpointWeight() uint8 {
	return n.config.ServiceLocalEndpointWeight
}

// DisableNATVirtualReassembly returns true if fragmented packets should be dropped by NAT.
func (n *IPv4Net) DisableNATVirtualReassembly() bool {
	return n.config.DisableNATVirtualReassembly
}

// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (n *IPv4Net) GetNatLoopbackIP() net.IP {
	// Last unicast IP from the pod subnet is used as NAT-loopback.
	podNet := n.ipam.PodSubnetThisNode()
	_, broadcastIP := cidr.AddressRange(podNet)
	return cidr.Dec(broadcastIP)
}

// GetNodeIP returns the IP address of this node.
func (n *IPv4Net) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return n.nodeIP, n.nodeIPNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (n *IPv4Net) GetHostIPs() []net.IP {
	return n.hostIPs
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (n *IPv4Net) GetMainPhysicalIfName() string {
	return n.mainPhysicalIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (n *IPv4Net) GetOtherPhysicalIfNames() []string {
	return n.otherPhysicalIfs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (n *IPv4Net) GetHostInterconnectIfName() string {
	return n.hostInterconnectVPPIfName()
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (n *IPv4Net) GetVxlanBVIIfName() string {
	if n.config.UseL2Interconnect {
		return ""
	}

	return vxlanBVIInterfaceName
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (n *IPv4Net) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	if n.defaultGw != nil {
		if n.mainPhysicalIf != "" {
			if n.nodeIPNet != nil && n.nodeIPNet.Contains(n.defaultGw) {
				return n.mainPhysicalIf, n.nodeIP
			}
		}
		for _, physicalIf := range n.thisNodeConfig.OtherVPPInterfaces {
			intIP, intNet, _ := net.ParseCIDR(physicalIf.IP)
			if intNet != nil && intNet.Contains(n.defaultGw) {
				return physicalIf.InterfaceName, intIP
			}
		}
	}

	return "", nil
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (n *IPv4Net) GetMainVrfID() uint32 {
	if n.config.MainVRFID != 0 && n.config.PodVRFID != 0 {
		return n.config.MainVRFID
	}
	return defaultMainVrfID
}

// GetPodVrfID returns the ID of the POD VRF.
func (n *IPv4Net) GetPodVrfID() uint32 {
	if n.config.MainVRFID != 0 && n.config.PodVRFID != 0 {
		return n.config.PodVRFID
	}
	return defaultPodVrfID
}

/******************************* Helper methods *******************************/

// loadExternalConfig attempts to load external configuration from a YAML file.
func (n *IPv4Net) loadExternalConfig() error {
	externalCfg := &Config{}
	found, err := n.Cfg.LoadValue(externalCfg) // It tries to lookup `PluginName + "-config"` in the executable arguments.
	if err != nil {
		return fmt.Errorf("external Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("external Contiv plugin configuration was not found")
	}

	n.config = externalCfg
	n.Log.Infof("Contiv config: %+v", externalCfg)
	err = n.config.ApplyIPAMConfig()
	if err != nil {
		return err
	}
	n.config.ApplyDefaults()

	return nil
}

// loadNodeConfig loads config specific for this node (given by its agent label).
func (n *IPv4Net) loadNodeConfig(kubeStateData controller.KubeStateData) *NodeConfig {
	myNodeName := n.ServiceLabel.GetAgentLabel()
	// first try to get node config from CRD
	crdNodeConfigs := kubeStateData[nodeconfig.Keyword]
	for crdNodeCfgKey, crdNodeConfig := range crdNodeConfigs {
		if crdNodeCfgKey == nodeconfig.Key(myNodeName) {
			return nodeConfigFromProto(crdNodeConfig.(*nodeconfig.NodeConfig))
		}
	}
	// try to find the node-specific configuration inside the config file
	return n.config.GetNodeConfig(myNodeName)
}

// getStolenInterfaceConfig returns IP addresses and routes associated with the main
// interface before it was stolen from the host stack.
func (n *IPv4Net) getStolenInterfaceConfig(ifName string) (ipNets []*nodesync.IPWithNetwork, gw net.IP, routes []*stn_grpc.STNReply_Route, err error) {
	if ifName == "" {
		n.Log.Debug("Getting STN info for the first stolen interface")
	} else {
		n.Log.Debugf("Getting STN info for interface %s", ifName)
	}

	// request info about the stolen interface
	reply, err := n.getSTNInfo(ifName)
	if err != nil {
		n.Log.Errorf("Error by executing STN GRPC: %v", err)
		return
	}
	n.Log.Debugf("STN GRPC reply: %v", reply)

	// parse STN IP addresses
	for _, address := range reply.IpAddresses {
		ipNet := &nodesync.IPWithNetwork{}
		ipNet.Address, ipNet.Network, err = net.ParseCIDR(address)
		if err != nil {
			n.Log.Errorf("Failed to parse IP address returned by STN GRPC: %v", err)
			return
		}
		ipNets = append(ipNets, ipNet)
	}

	// try to find the default gateway in the list of routes
	for _, r := range reply.Routes {
		if r.DestinationSubnet == "" || strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			gw = net.ParseIP(r.NextHopIp)
			if err != nil {
				err = fmt.Errorf("failed to parse GW address returned by STN GRPC (%s)", r.NextHopIp)
				return
			}
			break
		}
	}
	if len(gw) == 0 && len(ipNets) > 0 {
		// no default gateway in routes, calculate fake gateway address for route pointing to VPP
		firstIP, lastIP := cidr.AddressRange(ipNets[0].Network)
		if !cidr.Inc(firstIP).Equal(ipNets[0].Address) {
			gw = cidr.Inc(firstIP)
		} else {
			gw = cidr.Dec(lastIP)
		}
	}

	// return routes without any processing
	routes = reply.Routes
	return
}

func (n *IPv4Net) getStolenInterfaceInfo(ifName string) (reply *stn_grpc.STNReply, err error) {
	// connect to STN GRPC server
	if n.config.STNSocketFile == "" {
		n.config.STNSocketFile = defaultSTNSocketFile
	}
	conn, err := grpc.Dial(
		n.config.STNSocketFile,
		grpc.WithInsecure(),
		grpc.WithDialer(
			func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
	)
	if err != nil {
		n.Log.Errorf("Unable to connect to STN GRPC: %v", err)
		return
	}
	defer conn.Close()
	c := stn_grpc.NewSTNClient(conn)

	// request info about the stolen interface
	return c.StolenInterfaceInfo(context.Background(), &stn_grpc.STNRequest{
		InterfaceName: ifName,
	})
}

func (n *IPv4Net) excludedIPsFromNodeCIDR() []net.IP {
	if n.config == nil {
		return nil
	}
	var excludedIPs []string
	for _, oneNodeConfig := range n.config.NodeConfig {
		if oneNodeConfig.Gateway == "" {
			continue
		}
		excludedIPs = appendIfMissing(excludedIPs, oneNodeConfig.Gateway)
	}
	var res []net.IP
	for _, ip := range excludedIPs {
		res = append(res, net.ParseIP(ip))
	}
	return res
}

// dumpPhysicalInterfaces dumps physical interfaces present on VPP.
func (n *IPv4Net) dumpPhysicalInterfaces() (ifaces map[uint32]string, err error) {
	ifaces = make(map[uint32]string)
	ifHandler := intf_vppcalls.NewIfVppHandler(n.govppCh, n.Log)

	// TODO: when supported dump also VMXNET3 interfaces (?)

	dump, err := ifHandler.DumpInterfacesByType(interfaces.Interface_DPDK)
	if err != nil {
		return ifaces, err
	}

	for ifIdx, iface := range dump {
		ifaces[ifIdx] = iface.Interface.Name
	}
	return ifaces, err
}

// getHostLinkIPs returns all IP addresses assigned to physical interfaces in the host
// network stack.
func (n *IPv4Net) getHostLinkIPs() (hostIPs []net.IP, err error) {
	links, err := netlink.LinkList()
	if err != nil {
		n.Log.Error("Unable to list host links:", err)
		return hostIPs, err
	}

	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") && !strings.HasPrefix(l.Attrs().Name, "docker") &&
			!strings.HasPrefix(l.Attrs().Name, "virbr") && !strings.HasPrefix(l.Attrs().Name, "vpp") {
			// not a virtual interface, list its IP addresses
			addrList, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				n.Log.Error("Unable to list link IPs:", err)
				return hostIPs, err
			}
			// return all IPs
			for _, addr := range addrList {
				hostIPs = append(hostIPs, addr.IP)
			}
		}
	}
	return hostIPs, nil
}
