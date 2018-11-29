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

package contiv

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"

	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/gogo/protobuf/proto"
)

/* Global constants */
const (
	// defaultSTNSocketFile is the default socket file path where CNI GRPC server listens for incoming CNI requests.
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// interface host name length limit in Linux
	linuxIfNameMaxLen = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen = 63

	// any IPv4 address
	ipv4NetAny = "0.0.0.0/0"
)

/* Pod connectivity */
const (
	// interface host name as required by Kubernetes for every pod
	podInterfaceHostName = "eth0" // required by Kubernetes

	// prefix for logical name of AF-Packet interface (VPP) connecting a pod
	podAFPacketLogicalNamePrefix = "afpacket"

	// prefix for logical name of VETH1 interface (pod namespace) connecting a pod
	podVETH1LogicalNamePrefix = "veth1-"

	// prefix for logical name of VETH2 interface (vswitch namespace) connecting a pod
	podVETH2LogicalNamePrefix = "veth2-"

	// prefix for logical name of the VPP-TAP interface connecting a pod
	podVPPSideTAPLogicalNamePrefix = "vpp-tap-"

	// prefix for logical name of the Linux-TAP interface connecting a pod
	podLinuxSideTAPLogicalNamePrefix = "linux-tap-"
)

/* Main VPP interface */
const (
	// loopbackNICLogicalName is the logical name of the loopback interface configured instead of physical NICs.
	loopbackNICLogicalName = "loopbackNIC"
)

/* VRFs */
const (
	defaultMainVrfID = 0
	defaultPodVrfID  = 1
)

/* VPP - Host interconnect */
const (
	/* AF-PACKET + VETH */

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the host stack side of the pipe
	hostInterconnectVETH1LogicalName = "veth-vpp1"
	hostInterconnectVETH1HostName    = "vpp1"

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the VPP side of the pipe
	hostInterconnectVETH2LogicalName = "veth-vpp2"
	hostInterconnectVETH2HostName    = "vpp2"

	// logical name of the AF-packet interface attached to VETH2.
	hostInterconnectAFPacketLogicalName = "afpacket-vpp2"

	/* TAP */

	// HostInterconnectTAPinVPPLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - VPP side
	HostInterconnectTAPinVPPLogicalName = "tap-vpp2"

	// HostInterconnectTAPinLinuxLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - Linux side
	HostInterconnectTAPinLinuxLogicalName = "tap-vpp1"

	// HostInterconnectTAPinLinuxHostName is the physical name of the TAP interface
	// connecting host stack with VPP
	//  - the Linux side
	HostInterconnectTAPinLinuxHostName = "vpp1"
)

// prefix for the hardware address of host interconnects
var hostInterconnectHwAddrPrefix = []byte{0x34, 0x3c}

/* VXLANs */
const (
	// VXLAN Network Identifier (or VXLAN Segment ID)
	vxlanVNI = 10

	// as VXLAN tunnels are added to a BD, they must be configured with the same
	// and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may
	// loop among servers with the same VXLAN segment because VXLAN tunnels are fully
	// meshed among servers.
	vxlanSplitHorizonGroup = 1

	// name of the VXLAN BVI interface.
	vxlanBVIInterfaceName = "vxlanBVI" // name of the VXLAN BVI interface.

	// name of the VXLAN bridge domain
	vxlanBDName = "vxlanBD"
)

// prefix for the hardware address of VXLAN interfaces
var vxlanBVIHwAddrPrefix = []byte{0x12, 0x2b}

// remoteCNIserver represents the remote CNI server instance.
// It accepts the requests from the contiv-CNI (acting as a GRPC-client) and configures
// the networking between VPP and Kubernetes Pods.
type remoteCNIserver struct {
	// input arguments
	*remoteCNIserverArgs

	// DHCP watching
	watchingDHCP bool // true if dhcpIndex is being watched
	useDHCP      bool // whether DHCP is disabled by the latest config (can be changed via CRD)

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// set to true when running unit tests
	test bool

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

// remoteCNIserverArgs groups input arguments of the Remote CNI Server.
type remoteCNIserverArgs struct {
	logging.Logger
	eventLoop controller.EventLoop

	// node synchronization
	nodeSync nodesync.API

	// pod management
	podManager podmanager.API

	// dumping of physical interfaces
	physicalIfsDump PhysicalIfacesDumpClb

	// callback to receive information about a stolen interface
	getStolenInterfaceInfo StolenInterfaceInfoClb

	// dumping of host IPs
	hostLinkIPsDump HostLinkIPsDumpClb

	// GoVPP channel for direct binary API calls (not needed for UTs)
	govppChan api.Channel

	// VPP DHCP index map
	dhcpIndex idxmap.NamedMapping

	// agent microservice label
	agentLabel string

	// node specific configuration
	nodeConfig *NodeConfig

	// global config
	config *Config

	// a set of IP addresses from node CIDR to not use for allocation
	nodeInterconnectExcludedIPs []net.IP

	// REST interface (not needed for UTs)
	http rest.HTTPHandlers
}

// PhysicalIfacesDumpClb is callback for dumping physical interfaces on VPP.
type PhysicalIfacesDumpClb func() (ifaces map[uint32]string, err error) // interface index -> interface name

// StolenInterfaceInfoClb is callback for receiving information about a stolen interface.
type StolenInterfaceInfoClb func(ifName string) (reply *stn_grpc.STNReply, err error)

// HostLinkIPsDumpClb is callback for dumping all IP addresses assigned to interfaces
// in the host stack.
type HostLinkIPsDumpClb func() ([]net.IP, error)

/********************************* Constructor *********************************/

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(args *remoteCNIserverArgs) (*remoteCNIserver, error) {
	ipam, err := ipam.New(args.Logger, args.nodeSync.GetNodeID(), &args.config.IPAMConfig, args.nodeInterconnectExcludedIPs)
	if err != nil {
		return nil, err
	}
	server := &remoteCNIserver{remoteCNIserverArgs: args, ipam: ipam}
	server.registerHandlers()
	return server, nil
}

/********************************** Stringer **********************************/

// String returns human-readable string representation of RemoteCNIServer state (not args).
func (s *remoteCNIserver) String() string {
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

	return fmt.Sprintf("<useDHCP: %t, watchingDHCP: %t, "+
		"mainPhysicalIf: %s, otherPhysicalIfs: %v, "+
		"nodeIP: %s, nodeIPNet: %s, defaultGw: %s, hostIPs: %v, "+
		"vppIfNameToPodID: %s, stnRoutes: %v",
		s.useDHCP, s.watchingDHCP,
		s.mainPhysicalIf, s.otherPhysicalIfs,
		s.nodeIP.String(), ipNetToString(s.nodeIPNet), s.defaultGw.String(), s.hostIPs,
		vppIfaceToPod, s.stnRoutes)
}

/********************************* Events **************************************/

// Resync re-synchronizes configuration based on Kubernetes state data.
func (s *remoteCNIserver) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {

	var wasErr error

	// ipam
	if resyncCount == 1 {
		// No need to run resync for IPAM in run-time - IP address will not be allocated
		// to a local pod without the agent knowing about it. Also there is a risk
		// of a race condition - resync triggered shortly after Add/DelPod may work
		// with K8s state data that do not yet reflect the freshly added/removed pod.
		err := s.ipam.Resync(kubeStateData)
		if err != nil {
			wasErr = err
			s.Logger.Error(err)
		}
	}

	// node <-> host, host -> pods
	err := s.configureVswitchConnectivity(event, txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// node <-> node
	err = s.otherNodesResync(txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// pods <-> vswitch
	if resyncCount == 1 {
		// refresh the map VPP interface logical name -> pod ID
		s.vppIfaceToPodMutex.Lock()
		s.vppIfaceToPod = make(map[string]podmodel.ID)
		for _, pod := range s.podManager.GetLocalPods() {
			if s.ipam.GetPodIP(pod.ID) == nil {
				continue
			}
			vppIfName, _ := s.podInterfaceName(pod)
			s.vppIfaceToPod[vppIfName] = pod.ID
		}
		s.vppIfaceToPodMutex.Unlock()
	}
	for _, pod := range s.podManager.GetLocalPods() {
		if s.ipam.GetPodIP(pod.ID) == nil {
			continue
		}
		config := s.podConnectivityConfig(pod)
		controller.PutAll(txn, config)
	}

	s.Logger.Infof("Remote CNI Server state after RESYNC: %s", s.String())
	return wasErr
}

// Update is called for:
//   - AddPod and DeletePod
//   - NodeUpdate for other nodes
//   - Shutdown event
func (s *remoteCNIserver) Update(event controller.Event, txn controller.UpdateOperations) (change string, err error) {
	if addPod, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return s.addPod(addPod, txn)
	}

	if delPod, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return s.deletePod(delPod, txn)
	}

	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return s.processNodeUpdateEvent(nodeUpdate, txn)
	}

	if _, isShutdown := event.(*controller.Shutdown); isShutdown {
		return s.cleanupVswitchConnectivity(txn)
	}

	return "", nil
}

// Revert is called for AddPod.
func (s *remoteCNIserver) Revert(event *podmanager.AddPod) error {
	pod := s.podManager.GetLocalPods()[event.Pod]
	s.ipam.ReleasePodIP(pod.ID)

	vppIface, _ := s.podInterfaceName(pod)
	s.vppIfaceToPodMutex.Lock()
	delete(s.vppIfaceToPod, vppIface)
	s.vppIfaceToPodMutex.Unlock()
	return nil
}

// addPod connects a Pod container to the network.
func (s *remoteCNIserver) addPod(event *podmanager.AddPod, txn controller.UpdateOperations) (change string, err error) {
	pod := s.podManager.GetLocalPods()[event.Pod]

	// 1. try to allocate an IP address for this pod

	_, err = s.ipam.AllocatePodIP(pod.ID)
	if err != nil {
		err = fmt.Errorf("failed to allocate new IP address for pod %v: %v", pod.ID, err)
		s.Logger.Error(err)
		return "", err
	}

	// 2. enable IPv6

	// This is necessary for the latest docker where ipv6 is disabled by default.
	// OS assigns automatically ipv6 addr to a newly created TAP. We
	// try to reassign all IPs once interfaces is moved to a namespace.
	// Without explicitly enabled ipv6 we receive an error while moving
	// interface to a namespace.
	if !s.test {
		err = s.enableIPv6(pod)
		if err != nil {
			err = fmt.Errorf("failed to enable ipv6 in the namespace for pod %v: %v", pod.ID, err)
			s.Logger.Error(err)
			return "", err
		}
	}

	// 3. prepare configuration for VPP <-> Pod connectivity

	config := s.podConnectivityConfig(pod)
	controller.PutAll(txn, config)

	// 4. update interface->pod map

	vppIface, _ := s.podInterfaceName(pod)
	s.vppIfaceToPodMutex.Lock()
	s.vppIfaceToPod[vppIface] = pod.ID
	s.vppIfaceToPodMutex.Unlock()

	return "configure IPv4 connectivity", nil
}

// deletePod disconnects a Pod container from the network.
func (s *remoteCNIserver) deletePod(event *podmanager.DeletePod, txn controller.UpdateOperations) (change string, err error) {
	pod, podExists := s.podManager.GetLocalPods()[event.Pod]
	if !podExists {
		return "", nil
	}

	// 1. prepare delete operations for transaction

	config := s.podConnectivityConfig(pod)
	controller.DeleteAll(txn, config)

	// 2. update interface->pod map

	vppIface, _ := s.podInterfaceName(pod)
	s.vppIfaceToPodMutex.Lock()
	delete(s.vppIfaceToPod, vppIface)
	s.vppIfaceToPodMutex.Unlock()

	// 3. release IP address of the POD

	err = s.ipam.ReleasePodIP(pod.ID)
	if err != nil {
		return "", err
	}
	return "un-configure IPv4 connectivity", nil
}

/********************************* Resync *************************************/

// configureVswitchConnectivity configures base vSwitch VPP connectivity.
// Namely, it configures:
//  - physical NIC interfaces
//  - connectivity to the host stack (Linux)
//  - one route in VPP for every host interface
//  - one route in the host stack to direct traffic destined to pods via VPP
//  - one route in the host stack to direct traffic destined to services via VPP
//  - inter-VRF routing
//  - IP neighbor scanning
func (s *remoteCNIserver) configureVswitchConnectivity(event controller.Event, txn controller.ResyncOperations) error {
	// configure physical NIC
	err := s.configureVswitchNICs(event, txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	err = s.configureVswitchHostConnectivity(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if s.UseSTN() {
		// configure STN connectivity
		s.configureSTNConnectivity(txn)
	}

	// configure inter-VRF routing
	s.configureVswitchVrfRoutes(txn)

	// enable IP neighbor scanning (to clean up old ARP entries)
	key, ipneigh := s.enabledIPNeighborScan()
	txn.Put(key, ipneigh)

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	if !s.test {
		s.subscribeVnetFibCounters()
	}

	// enable packet trace if requested (should be used for debugging only)
	if !s.test && s.config.EnablePacketTrace {
		s.executeDebugCLI("trace add dpdk-input 100000")
		s.executeDebugCLI("trace add virtio-input 100000")
	}

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (s *remoteCNIserver) configureVswitchNICs(event controller.Event, txn controller.ResyncOperations) error {
	// dump physical interfaces present on VPP
	nics, err := s.physicalIfsDump()
	if err != nil {
		s.Logger.Errorf("Failed to dump physical interfaces: %v", err)
		return err
	}
	s.Logger.Infof("Existing interfaces: %v", nics)

	// configure the main VPP NIC interface
	err = s.configureMainVPPInterface(event, nics, txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if s.nodeConfig != nil && len(s.nodeConfig.OtherVPPInterfaces) > 0 {
		s.Logger.Debug("Configuring VPP for additional interfaces")
		err = s.configureOtherVPPInterfaces(nics, txn)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(event controller.Event, physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
	var err error

	// 1. Determine the name of the main VPP NIC interface

	nicName := ""
	if s.nodeConfig != nil {
		// use name as as specified in node config YAML
		nicName = s.nodeConfig.MainVPPInterface.InterfaceName
		s.Logger.Debugf("Physical NIC name taken from nodeConfig: %v ", nicName)
	}

	if nicName == "" {
		// name not specified in config, use heuristic - select first non-virtual interface
	nextNIC:
		for _, physicalIface := range physicalIfaces {
			// exclude "other" (non-main) NICs
			if s.nodeConfig != nil {
				for _, otherNIC := range s.nodeConfig.OtherVPPInterfaces {
					if otherNIC.InterfaceName == physicalIface {
						continue nextNIC
					}
				}
			}

			// we have the main NIC
			nicName = physicalIface
			s.Logger.Debugf("Physical NIC not taken from nodeConfig, but heuristic was used: %v ", nicName)
			break
		}
	}

	if nicName != "" {
		s.Logger.Info("Configuring physical NIC ", nicName)
	}

	// 2. Determine the node IP address, default gateway IP and whether to use DHCP

	// 2.1 Read the configuration
	var nicStaticIPs []*nodesync.IPWithNetwork
	s.useDHCP = false
	if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.IP != "" {
		nicIP, nicIPNet, err := net.ParseCIDR(s.nodeConfig.MainVPPInterface.IP)
		if err != nil {
			s.Logger.Errorf("Failed to parse main interface IP address from the config: %v", err)
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nicIP, Network: nicIPNet})
	} else if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.UseDHCP {
		s.useDHCP = true
	} else if s.ipam.NodeInterconnectDHCPEnabled() {
		// inherit DHCP from global setting
		s.useDHCP = true
	}

	// 2.2 STN case, IP address taken from the stolen interface
	if s.UseSTN() {
		// determine name of the stolen interface
		var stolenIface string
		if s.nodeConfig != nil && s.nodeConfig.StealInterface != "" {
			stolenIface = s.nodeConfig.StealInterface
		} else if s.config.StealInterface != "" {
			stolenIface = s.config.StealInterface
		} // else go with the first stolen interface

		// obtain STN interface configuration
		nicStaticIPs, s.defaultGw, s.stnRoutes, err = s.getStolenInterfaceConfig(stolenIface)
		if err != nil {
			s.Logger.Errorf("Unable to get STN interface info: %v, disabling the interface.", err)
			return err
		}
	}

	// 2.3 Set node IP address
	if s.useDHCP {
		// ip address is assigned by DHCP server
		s.Logger.Infof("Configuring %v to use DHCP", nicName)
		if nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change); isNodeIPv4Change {
			// this resync event has been triggered to process DHCP event
			s.nodeIP = nodeIPv4Change.NodeIP
			s.nodeIPNet = nodeIPv4Change.NodeIPNet
			s.defaultGw = nodeIPv4Change.DefaultGw
		}
	} else if len(nicStaticIPs) > 0 {
		s.nodeIP = nicStaticIPs[0].Address
		s.nodeIPNet = nicStaticIPs[0].Network
		s.Logger.Infof("Configuring %v to use %v", nicName, s.nodeIP)
	} else {
		nodeIP, nodeIPNet, err := s.ipam.NodeIPAddress(s.nodeSync.GetNodeID())
		if err != nil {
			s.Logger.Error("Unable to generate node IP address.")
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nodeIP, Network: nodeIPNet})
		s.nodeIP = nodeIP
		s.nodeIPNet = nodeIPNet
		s.Logger.Infof("Configuring %v to use %v", nicName, nodeIP.String())
	}
	// publish the node IP address to other nodes
	var nodeIPs []*nodesync.IPWithNetwork
	if len(s.nodeIP) > 0 {
		nodeIPs = append(nodeIPs, &nodesync.IPWithNetwork{Address: s.nodeIP, Network: s.nodeIPNet})
	}
	s.nodeSync.PublishNodeIPs(nodeIPs, nodesync.IPv4)

	// 3. Configure the main interface

	if nicName != "" {
		// configure the physical NIC
		nicKey, nic := s.physicalInterface(nicName, nicStaticIPs)
		if s.useDHCP {
			// clear IP addresses
			nic.IpAddresses = []string{}
			nic.SetDhcpClient = true
			if !s.watchingDHCP {
				// start watching of DHCP notifications
				s.dhcpIndex.Watch("cniserver", s.handleDHCPNotification)
				s.watchingDHCP = true
			}
		}
		txn.Put(nicKey, nic)
		s.mainPhysicalIf = nicName
	} else {
		// configure loopback instead of the physical NIC
		s.Logger.Debug("Physical NIC not found, configuring loopback instead.")
		key, loopback := s.loopbackInterface(nicStaticIPs)
		txn.Put(key, loopback)
		s.mainPhysicalIf = ""
	}

	// 4. For 2NICs non-DHCP case, configure the default route from the configuration

	if !s.UseSTN() && !s.useDHCP {
		if s.mainPhysicalIf != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
			// configure default gateway from the config file
			s.defaultGw = net.ParseIP(s.nodeConfig.Gateway)
			if s.defaultGw == nil {
				err = fmt.Errorf("failed to parse gateway IP address from the config (%s)",
					s.nodeConfig.Gateway)
				return err
			}
			key, defaultRoute := s.defaultRoute(s.defaultGw, nicName)
			txn.Put(key, defaultRoute)
		}
	}

	return nil
}

// configureOtherVPPInterfaces configure all physical interfaces defined in the config but the main one.
func (s *remoteCNIserver) configureOtherVPPInterfaces(physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
	s.otherPhysicalIfs = []string{}

	// match existing interfaces and build configuration
	interfaces := make(map[string]*interfaces.Interface)
	for _, physicalIface := range physicalIfaces {
		for _, ifaceCfg := range s.nodeConfig.OtherVPPInterfaces {
			if ifaceCfg.InterfaceName == physicalIface {
				ipAddr, ipNet, err := net.ParseCIDR(ifaceCfg.IP)
				if err != nil {
					err := fmt.Errorf("failed to parse IP address configured for interface %s: %v",
						ifaceCfg.InterfaceName, err)
					return err
				}
				key, iface := s.physicalInterface(physicalIface, []*nodesync.IPWithNetwork{
					{Address: ipAddr, Network: ipNet},
				})
				interfaces[key] = iface
			}
		}
	}

	// configure the interfaces on VPP
	if len(interfaces) > 0 {
		for key, iface := range interfaces {
			txn.Put(key, iface)
			s.otherPhysicalIfs = append(s.otherPhysicalIfs, iface.Name)
		}
	}

	return nil
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(txn controller.ResyncOperations) (err error) {
	var key string

	// list all IPs assigned to host interfaces
	s.hostIPs, err = s.hostLinkIPsDump()
	if err != nil {
		return err
	}

	// configure interfaces between VPP and the host network stack
	if s.config.UseTAPInterfaces {
		// TAP interface
		key, vppTAP := s.interconnectTapVPP()
		txn.Put(key, vppTAP)
		key, hostVPP := s.interconnectTapHost()
		txn.Put(key, hostVPP)
	} else {
		// veth + AF_PACKET
		key, afpacket := s.interconnectAfpacket()
		txn.Put(key, afpacket)
		key, vethHost := s.interconnectVethHost()
		txn.Put(key, vethHost)
		key, vethVPP := s.interconnectVethVpp()
		txn.Put(key, vethVPP)
	}

	// configure routes from VPP to the host
	var routesToHost map[string]*l3.StaticRoute
	if !s.UseSTN() {
		routesToHost = s.routesToHost(s.ipam.HostInterconnectIPInLinux())
	} else {
		routesToHost = s.routesToHost(s.nodeIP)
	}
	for key, route := range routesToHost {
		txn.Put(key, route)
	}

	// configure the route from the host to PODs
	var routeToPods *linux_l3.StaticRoute
	if !s.UseSTN() {
		key, routeToPods = s.routePODsFromHost(s.ipam.HostInterconnectIPInVPP())
	} else {
		key, routeToPods = s.routePODsFromHost(s.defaultGw)
	}
	txn.Put(key, routeToPods)

	// route from the host to k8s service range from the host
	var routeToServices *linux_l3.StaticRoute
	if !s.UseSTN() {
		key, routeToServices = s.routeServicesFromHost(s.ipam.HostInterconnectIPInVPP())
	} else {
		key, routeToServices = s.routeServicesFromHost(s.defaultGw)
	}
	txn.Put(key, routeToServices)

	return nil
}

// configureSTNConnectivity configures vswitch VPP to operate in the STN mode.
func (s *remoteCNIserver) configureSTNConnectivity(txn controller.ResyncOperations) {
	if len(s.nodeIP) > 0 {
		// STN rule
		key, stnrule := s.stnRule()
		txn.Put(key, stnrule)

		// proxy ARP for ARP requests from the host
		key, proxyarp := s.proxyArpForSTNGateway()
		txn.Put(key, proxyarp)
	}

	// STN routes
	stnRoutesVPP := s.stnRoutesForVPP()
	for key, route := range stnRoutesVPP {
		txn.Put(key, route)
	}
	stnRoutesHost := s.stnRoutesForHost()
	for key, route := range stnRoutesHost {
		txn.Put(key, route)
	}
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (s *remoteCNIserver) configureVswitchVrfRoutes(txn controller.ResyncOperations) {
	// routes from main towards POD VRF: PodSubnet + VPPHostSubnet
	routes := s.routesMainToPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// routes from POD towards main VRF: default route + VPPHostNetwork
	routes = s.routesPodToMainVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// add DROP routes into POD VRF to avoid loops: the same routes that point
	// from main VRF to POD VRF are installed into POD VRF as DROP, to not go back
	// into the main VRF via default route in case that PODs are not reachable
	routes = s.dropRoutesIntoPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}
}

/********************************** Cleanup ***********************************/

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity
// configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity(txn controller.UpdateOperations) (change string, err error) {
	if s.config.UseTAPInterfaces {
		// everything configured in the host will disappear automatically
		return
	}

	// un-configure VETHs
	key, _ := s.interconnectVethHost()
	txn.Delete(key)
	key, _ = s.interconnectVethVpp()
	txn.Delete(key)
	return "removing VPP<->Host VETHs", nil
}

/************************** Main Interface IP Address **************************/

// getStolenInterfaceConfig returns IP addresses and routes associated with the main
// interface before it was stolen from the host stack.
func (s *remoteCNIserver) getStolenInterfaceConfig(ifName string) (ipNets []*nodesync.IPWithNetwork, gw net.IP, routes []*stn_grpc.STNReply_Route, err error) {
	if ifName == "" {
		s.Logger.Debug("Getting STN info for the first stolen interface")
	} else {
		s.Logger.Debugf("Getting STN info for interface %s", ifName)
	}

	// request info about the stolen interface
	reply, err := s.getStolenInterfaceInfo(ifName)
	if err != nil {
		s.Logger.Errorf("Error by executing STN GRPC: %v", err)
		return
	}
	s.Logger.Debugf("STN GRPC reply: %v", reply)

	// parse STN IP addresses
	for _, address := range reply.IpAddresses {
		ipNet := &nodesync.IPWithNetwork{}
		ipNet.Address, ipNet.Network, err = net.ParseCIDR(address)
		if err != nil {
			s.Logger.Errorf("Failed to parse IP address returned by STN GRPC: %v", err)
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

var (
	// variable used only in the context of go routines running handleDHCPNotification
	lastDHCPLease *interfaces.DHCPLease
)

// handleDHCPNotifications handles DHCP state change notifications
func (s *remoteCNIserver) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	s.Logger.Info("DHCP notification received")

	// check for validity of the DHCP event
	if notif.Del {
		s.Logger.Info("Ignoring event of removed DHCP lease")
		return
	}
	if !s.useDHCP {
		s.Logger.Info("Ignoring DHCP event, dynamic IP address assignment is disabled")
		return
	}
	if notif.Value == nil {
		s.Logger.Warn("DHCP notification metadata is empty")
		return
	}
	dhcpLease, isDHCPLease := notif.Value.(*interfaces.DHCPLease)
	if !isDHCPLease {
		s.Logger.Warn("Received invalid DHCP notification")
		return
	}
	if dhcpLease.InterfaceName != s.mainPhysicalIf {
		s.Logger.Warn("DHCP notification for a non-main interface")
		return
	}
	if proto.Equal(dhcpLease, lastDHCPLease) {
		// nothing has really changed, ignore
		s.Logger.Info("Ignoring DHCP event - this lease was already processed")
		return
	}
	lastDHCPLease = dhcpLease

	// parse DHCP lease fields
	hostAddr, hostNet, defaultGw, err := s.parseDHCPLease(dhcpLease)
	if err != nil {
		return
	}

	// push event into the event loop
	s.eventLoop.PushEvent(&NodeIPv4Change{
		NodeIP:    hostAddr,
		NodeIPNet: hostNet,
		DefaultGw: defaultGw,
	})
	s.Logger.Infof("Sent NodeIPv4Change event to the event loop for DHCP lease: %+v", *dhcpLease)
}

// parseDHCPLease parses fields of a DHCP lease.
func (s *remoteCNIserver) parseDHCPLease(lease *interfaces.DHCPLease) (hostAddr net.IP, hostNet *net.IPNet, defaultGw net.IP, err error) {
	// parse IP address of the default gateway
	if lease.RouterIpAddress != "" {
		defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
		if err != nil {
			s.Logger.Errorf("Failed to parse DHCP route IP address: %v", err)
			return
		}
	}

	// parse host IP address and network
	if lease.HostIpAddress != "" {
		hostAddr, hostNet, err = net.ParseCIDR(lease.HostIpAddress)
		if err != nil {
			s.Logger.Errorf("Failed to parse DHCP host IP address: %v", err)
			return
		}
	}
	return
}

/**************************** Remote CNI Server API ****************************/

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (s *remoteCNIserver) GetMainPhysicalIfName() string {
	return s.mainPhysicalIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (s *remoteCNIserver) GetOtherPhysicalIfNames() []string {
	return s.otherPhysicalIfs
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (s *remoteCNIserver) GetVxlanBVIIfName() string {
	if s.config.UseL2Interconnect {
		return ""
	}

	return vxlanBVIInterfaceName
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (s *remoteCNIserver) GetHostInterconnectIfName() string {
	return s.hostInterconnectVPPIfName()
}

// GetNodeIP returns the IP address of this node.
func (s *remoteCNIserver) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return s.nodeIP, s.nodeIPNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (s *remoteCNIserver) GetHostIPs() []net.IP {
	return s.hostIPs
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (s *remoteCNIserver) GetPodByIf(ifName string) (podNamespace string, podName string, exists bool) {
	s.vppIfaceToPodMutex.RLock()
	defer s.vppIfaceToPodMutex.RUnlock()

	podID, found := s.vppIfaceToPod[ifName]
	if !found {
		return "", "", false
	}
	return podID.Namespace, podID.Name, true
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (s *remoteCNIserver) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	pod, exists := s.podManager.GetLocalPods()[podID]
	if !exists {
		return "", false
	}

	vppIfName, _ := s.podInterfaceName(pod)
	_, configured := s.vppIfaceToPod[vppIfName]
	if !configured {
		return "", false
	}

	return vppIfName, true
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (s *remoteCNIserver) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	if s.defaultGw != nil {
		if s.mainPhysicalIf != "" {
			if s.nodeIPNet != nil && s.nodeIPNet.Contains(s.defaultGw) {
				return s.mainPhysicalIf, s.nodeIP
			}
		}
		for _, physicalIf := range s.nodeConfig.OtherVPPInterfaces {
			intIP, intNet, _ := net.ParseCIDR(physicalIf.IP)
			if intNet != nil && intNet.Contains(s.defaultGw) {
				return physicalIf.InterfaceName, intIP
			}
		}
	}

	return "", nil
}

// UseSTN returns true if the cluster was configured to be deployed in the STN mode.
func (s *remoteCNIserver) UseSTN() bool {
	return s.config.StealFirstNIC || s.config.StealInterface != "" ||
		(s.nodeConfig != nil && s.nodeConfig.StealInterface != "")
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (s *remoteCNIserver) GetMainVrfID() uint32 {
	if s.config.MainVRFID != 0 && s.config.PodVRFID != 0 {
		return s.config.MainVRFID
	}
	return defaultMainVrfID
}

// GetPodVrfID returns the ID of the POD VRF.
func (s *remoteCNIserver) GetPodVrfID() uint32 {
	if s.config.MainVRFID != 0 && s.config.PodVRFID != 0 {
		return s.config.PodVRFID
	}
	return defaultPodVrfID
}
