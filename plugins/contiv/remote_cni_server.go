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
	"time"

	"git.fd.io/govpp.git/api"
	"golang.org/x/net/context"
	"github.com/apparentlymart/go-cidr/cidr"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"

	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

const (
	resultOk               uint32 = 0
	resultErr              uint32 = 1
	linuxIfNameMaxLen             = 15
	logicalIfNameMaxLen           = 63
	afPacketNamePrefix            = "afpacket"
	vppTAPNamePrefix              = "vpp-tap-"
	linuxTAPNamePrefix            = "linux-tap-"
	podNameExtraArg               = "K8S_POD_NAME"
	podNamespaceExtraArg          = "K8S_POD_NAMESPACE"
	vethHostEndLogicalName        = "veth-vpp1"
	vethHostEndName               = "vpp1"
	vethVPPEndLogicalName         = "veth-vpp2"
	vethVPPEndName                = "vpp2"
	defaultMainVrfID              = 0
	defaultPodVrfID               = 1

	// defaultSTNSocketFile is the default socket file path where CNI GRPC server listens for incoming CNI requests.
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// TapHostEndLogicalName is the logical name of the VPP-host interconnect TAP interface (host end)
	TapHostEndLogicalName = "tap-vpp1"
	// TapHostEndName is the physical name of the VPP-host interconnect TAP interface (host end)
	TapHostEndName = "vpp1"
	// TapVPPEndLogicalName is the logical name of the VPP-host interconnect TAP interface (VPP end)
	TapVPPEndLogicalName = "tap-vpp2"
	// TapVPPEndName is the physical name of the VPP-host interconnect TAP interface (VPP end)
	TapVPPEndName = "vpp2"
	// HostInterconnectMAC is MAC address of tap that interconnects VPP with host stack
	HostInterconnectMAC = "01:23:45:67:89:42"
)

// remoteCNIserver represents the remote CNI server instance. It accepts the requests from the contiv-CNI
// (acting as a GRPC-client) and configures the networking between VPP and the PODs.
type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	// VPP local client transaction factory
	vppTxnFactory       func() linuxclient.DataChangeDSL
	vppResyncTxnFactory func() linuxclient.DataResyncDSL

	// GoVPP channel for direct binary API calls (if needed)
	govppChan api.Channel

	// VPP interface index map
	swIfIndex ifaceidx.IfaceMetadataIndex

	// VPP dhcp index map
	dhcpIndex idxmap.NamedMapping

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// set to true when running unit tests
	test bool

	// agent microservice label
	agentLabel string

	// unique identifier of the node
	nodeID uint32
	otherNodeIDs map[string]struct{}

	// this node's main IP address
	nodeIP string

	// IP addresses of this node present in the host network namespace (Linux)
	hostIPs []net.IP

	// nodeIPsubscribers is a slice of channels that are notified when nodeIP is changed
	nodeIPsubscribers []chan string

	// global config
	config *Config

	// podPreRemovalHooks is a slice of callbacks called before a pod removal
	podPreRemovalHooks []PodActionHook

	// podPostAddHooks is a slice of callbacks called once pod is added
	podPostAddHook []PodActionHook

	// node specific configuration
	nodeConfig *NodeConfig

	podContainer map[pod.ID]PodContainer
	podContainerByIfName map[string]PodContainer

	// the variables ensures that add/del requests are processed only after the server
	// was first resynced
	inSync     bool
	inSyncCond *sync.Cond

	// name of the main physical interface
	mainPhysicalIf string

	// name of extra physical interfaces configured by the agent
	otherPhysicalIfs []string

	stnIP string
	stnGw string

	// default gateway IP address
	defaultGw net.IP // TODO be careful about this

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	http rest.HTTPHandlers
}

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linuxclient.DataChangeDSL, vppResyncTxnFactory func() linuxclient.DataResyncDSL,
	govppChan api.Channel, index ifaceidx.IfaceMetadataIndex, dhcpIndex idxmap.NamedMapping, agentLabel string,
	config *Config, nodeConfig *NodeConfig, nodeID uint32, nodeExcludeIPs []net.IP, broker keyval.ProtoBroker, http rest.HTTPHandlers) (*remoteCNIserver, error) {

	ipam, err := ipam.New(logger, nodeID, agentLabel, &config.IPAMConfig, nodeExcludeIPs, broker)
	if err != nil {
		return nil, err
	}

	server := &remoteCNIserver{
		Logger:              logger,
		vppTxnFactory:       vppTxnFactory,
		vppResyncTxnFactory: vppResyncTxnFactory,
		govppChan:           govppChan,
		swIfIndex:           index,
		dhcpIndex:           dhcpIndex,
		agentLabel:          agentLabel,
		nodeID:              nodeID,
		ipam:                ipam,
		nodeConfig:          nodeConfig,
		config:              config,
		http:                http,
	}
	server.reset()
	server.inSyncCond = sync.NewCond(&server.Mutex)
	server.ctx, server.ctxCancelFunc = context.WithCancel(context.Background())
	if nodeConfig != nil && nodeConfig.Gateway != "" {
		server.defaultGw = net.ParseIP(nodeConfig.Gateway)
	}
	server.registerHandlers()
	return server, nil
}

// reset resets the CNI server to pre-resync state.
func (s *remoteCNIserver) reset() {
	s.hostIPs = []net.IP{}
	s.mainPhysicalIf = ""
	s.otherPhysicalIfs = []string{}
	s.stnIP = ""
	s.stnGw = ""
	s.otherNodeIDs = make(map[string]struct{})
	s.podContainer = make(map[pod.ID]PodContainer)
	s.podContainerByIfName = make(map[string]PodContainer)
	s.inSync = false
}

// resync is called by the plugin infra when the state of the GRPC server needs to be resynchronized,
// including the initialization phase
func (s *remoteCNIserver) resync(dataResyncEv datasync.ResyncEvent) error {
	s.Lock()
	defer s.Unlock()
	var wasErr error

	s.reset()
	txn := s.vppResyncTxnFactory()

	err := s.configureVswitchConnectivity(txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	err = s.otherNodesResync(dataResyncEv, txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// TODO pods

	err = txn.Send().ReceiveReply()
	if err != nil {
		wasErr = fmt.Errorf("failed to resync vswitch configuration: %v ", err)
	}

	// set the state to configured and broadcast
	s.inSync = true
	s.inSyncCond.Broadcast()

	return wasErr
}

func (s *remoteCNIserver) update(dataChng datasync.ProtoWatchResp) error {
	s.Lock()
	defer s.Unlock()

	return s.processOtherNodeChangeEvent(dataChng)
}

// close is called by the plugin infra when the CNI server needs to be stopped.
func (s *remoteCNIserver) close() {
	s.cleanupVswitchConnectivity()
	s.ctxCancelFunc()
}

// Add handles CNI Add request, connects the container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)

	// wait for the CNI server to be in-sync
	s.Lock()
	for !s.inSync {
		s.inSyncCond.Wait()
	}

	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
	reply, err := s.configureContainerConnectivity(request)
	s.Unlock() // unlock before running post-Add hooks
	if err != nil {
		return reply, err
	}

	// Run all registered post add hooks. But only after remote cni server lock is released.
	for _, hook := range s.podPostAddHook {
		err = hook(extraArgs[podNamespaceExtraArg], extraArgs[podNameExtraArg])
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod post add hook has failed")
			err = nil
		}
	}
	return reply, err
}

// Delete handles CNI Delete request, disconnects the container from the network.
func (s *remoteCNIserver) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Delete request received ", *request)

	// wait for the CNI server to be in-sync
	s.Lock()
	for !s.inSync {
		s.inSyncCond.Wait()
	}
	s.Unlock() // run pre-removal hooks with unlocked CNI server

	// Run all registered pre-removal hooks, before lock is acquired
	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
	for _, hook := range s.podPreRemovalHooks {
		err := hook(extraArgs[podNamespaceExtraArg], extraArgs[podNameExtraArg])
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod pre-removal hook has failed")
			err = nil
		}
	}

	s.Lock()
	defer s.Unlock()
	return s.unconfigureContainerConnectivity(request)
}

// configureVswitchConnectivity configures base vSwitch VPP connectivity to the host IP stack and to the other hosts.
// Namely, it configures:
//  - physical NIC interface + static routes to PODs on other hosts
//  - veth pair to host IP stack + AF_PACKET on VPP side
//  - default static route to the host via the veth pair
func (s *remoteCNIserver) configureVswitchConnectivity(txn linuxclient.DataResyncDSL) error {
	s.Logger.Info("Applying base vSwitch config.")

	// configure physical NIC
	// NOTE that needs to be done as the first step, before adding any other
	//      interfaces to VPP to properly fnd the physical NIC name.
	err := s.configureVswitchNICs(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	s.configureVswitchHostConnectivity(txn)

	// configure inter-VRF routing
	s.configureVswitchVrfRoutes(txn)

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (s *remoteCNIserver) configureVswitchNICs(txn linuxclient.DataResyncDSL) error {
	s.Logger.Info("Existing interfaces: ", s.swIfIndex.ListAllInterfaces())

	// configure the main VPP NIC interface
	err := s.configureMainVPPInterface(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if s.nodeConfig != nil && len(s.nodeConfig.OtherVPPInterfaces) > 0 {
		s.Logger.Debug("Configuring VPP for additional interfaces")
		s.configureOtherVPPInterfaces(txn)
	}

	// enable IP neighbor scanning (to clean up old ARP entries)
	s.enableIPNeighborScan(txn)

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	s.subscribeVnetFibCounters()

	// enable packet trace if requested (should be used for debugging only)
	if s.config.EnablePacketTrace {
		s.executeDebugCLI("trace add dpdk-input 100000")
		s.executeDebugCLI("trace add virtio-input 100000")
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(txn linuxclient.DataResyncDSL) error {
	var err error

	// find name of the main VPP NIC interface
	nicName := ""
	useDHCP := false
	if s.nodeConfig != nil {
		// use name as as specified in node config YAML
		nicName = s.nodeConfig.MainVPPInterface.InterfaceName
		s.Logger.Debugf("Physical NIC name taken from nodeConfig: %v ", nicName)
	}

	if nicName == "" {
		// name not specified in config, use heuristic - first non-virtual interface
		for _, name := range s.swIfIndex.ListAllInterfaces() {
			if strings.HasPrefix(name, "local") || strings.HasPrefix(name, "loop") ||
				strings.HasPrefix(name, "host") || strings.HasPrefix(name, "tap") ||
				name == vxlanBVIInterfaceName {
				continue
			} else {
				nicName = name
				break
			}
		}
		s.Logger.Debugf("Physical NIC not taken from nodeConfig, but heuristic was used: %v ", nicName)
	}
	// IP of the main interface
	nicIP := ""
	if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.IP != "" {
		nicIP = s.nodeConfig.MainVPPInterface.IP
	} else if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.UseDHCP {
		useDHCP = true
	} else if s.ipam.NodeInterconnectDHCPEnabled() {
		// inherit DHCP from global setting
		useDHCP = true
	}

	if s.UseSTN() {
		// get IP address of the STN interface
		var gwIP string
		if s.nodeConfig != nil && s.nodeConfig.StealInterface != "" {
			s.Logger.Infof("STN of the host interface %s requested.", s.nodeConfig.StealInterface)
			nicIP, gwIP, err = s.getSTNInterfaceIP(s.nodeConfig.StealInterface)
		} else if s.config.StealInterface != "" {
			s.Logger.Infof("STN of the interface %s requested.", s.config.StealInterface)
			nicIP, gwIP, err = s.getSTNInterfaceIP(s.config.StealInterface)
		} else {
			s.Logger.Infof("STN of the first interface (%s) requested.", nicName)
			nicIP, gwIP, err = s.getSTNInterfaceIP("")
		}

		if err != nil || nicIP == "" {
			s.Logger.Errorf("Unable to get STN interface info: %v, disabling the interface.", err)
			return err
		}

		s.Logger.Infof("STN-configured interface %s (IP %s, GW %s), skip main interface config.", nicName, nicIP, gwIP)
		s.stnIP = nicIP
		s.stnGw = gwIP
	}

	// determine main node IP address
	if !s.UseSTN() && useDHCP {
		// ip address will be assigned by DHCP server, not known yet
		s.Logger.Infof("Configuring %v to use dhcp", nicName)
	} else if nicIP != "" {
		s.setNodeIP(nicIP)
		s.Logger.Infof("Configuring %v to use %v", nicName, nicIP)
	} else {
		nodeIP, err := s.ipam.NodeIPWithPrefix(s.ipam.NodeID())
		if err != nil {
			s.Logger.Error("Unable to generate node IP address.")
			return err
		}
		s.setNodeIP(nodeIP.String())
		s.Logger.Infof("Configuring %v to use %v", nicName, nodeIP.String())
	}

	if !s.UseSTN() {
		if nicName != "" {
			// configure the physical NIC
			s.Logger.Info("Configuring physical NIC ", nicName)

			nic := s.physicalInterface(nicName, s.nodeIP)
			if useDHCP {

				// clear IP addresses
				nic.IpAddresses = []string{}
				nic.SetDhcpClient = true
				// start watching dhcp notif
				s.dhcpIndex.Watch("cniserver", s.handleDHCPNotification)
				// do lookup to cover the case where dhcp was configured by resync
				// and ip address is already assigned
				dhcpData, exists := s.dhcpIndex.GetValue(nicName)
				if exists {
					dhcpLease := dhcpData.(*vpp_intf.DHCPLease)
					s.Logger.Infof("DHCP notification already received: %v", dhcpLease)
					s.applyDHCPLease(dhcpLease)
				} else {
					s.Logger.Debugf("Waiting for DHCP notification. Existing DHCP events: %v", s.dhcpIndex.ListAllNames())
				}
			}
			txn.VppInterface(nic)
			s.mainPhysicalIf = nicName
		} else {
			// configure loopback instead of the physical NIC
			s.Logger.Debug("Physical NIC not found, configuring loopback instead.")
			txn.VppInterface(s.physicalInterfaceLoopback(s.nodeIP))
		}

		if nicName != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
			// configure the default gateway
			txn.StaticRoute( s.defaultRoute(s.nodeConfig.Gateway, nicName))
		}

	} else {
		s.mainPhysicalIf = nicName
	}

	return nil
}

// getSTNInterfaceIP returns IP address of the interface before stealing it from the host stack.
func (s *remoteCNIserver) getSTNInterfaceIP(ifName string) (ip string, gw string, err error) {
	s.Logger.Debugf("Getting STN info for interface %s", ifName)

	// connect to STN GRPC server
	if s.config.STNSocketFile == "" {
		s.config.STNSocketFile = defaultSTNSocketFile
	}
	conn, err := grpc.Dial(
		s.config.STNSocketFile,
		grpc.WithInsecure(),
		grpc.WithDialer(
			func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
	)
	if err != nil {
		s.Logger.Errorf("Unable to connect to STN GRPC: %v", err)
		return
	}
	defer conn.Close()
	c := stn_grpc.NewSTNClient(conn)

	// request info about the stolen interface
	reply, err := c.StolenInterfaceInfo(context.Background(), &stn_grpc.STNRequest{
		InterfaceName: ifName,
	})
	if err != nil {
		s.Logger.Errorf("Error by executing STN GRPC: %v", err)
		return
	}

	s.Logger.Debugf("STN GRPC reply: %v", reply)

	// STN IP address
	if len(reply.IpAddresses) == 0 {
		return
	}
	ip = reply.IpAddresses[0]

	// try to find the default gateway in the list of routes
	for _, r := range reply.Routes {
		if r.DestinationSubnet == "" || strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			gw = r.NextHopIp
			s.defaultGw = net.ParseIP(gw)
		}
	}
	if gw == "" {
		// no default gateway in routes, calculate fake gateway address for route pointing to VPP
		_, ipNet, _ := net.ParseCIDR(ip)
		firstIP, lastIP := cidr.AddressRange(ipNet)
		if cidr.Inc(firstIP).String() != ip {
			gw = cidr.Inc(firstIP).String()
		} else {
			gw = cidr.Dec(lastIP).String()
		}
	}

	return
}

// handleDHCPNotifications handles DHCP state change notifications
func (s *remoteCNIserver) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	s.Logger.Info("DHCP notification received")
	if notif.Del {
		return
	}
	if notif.Value == nil {
		s.Logger.Warn("DHCP notification metadata is empty")
		return
	}

	dhcpLease, isDHCPLease := notif.Value.(*vpp_intf.DHCPLease)
	if !isDHCPLease {
		s.Logger.Warn("received invalid DHCP notification")
		return
	}

	if dhcpLease.InterfaceName != s.mainPhysicalIf {
		s.Logger.Warn("DHCP notification for a non-main interface")
		return
	}

	s.Lock()
	s.applyDHCPLease(dhcpLease)
	s.Unlock()
}

func (s *remoteCNIserver) applyDHCPLease(lease *vpp_intf.DHCPLease) {
	s.Logger.Debug("Processing DHCP event", lease)

	var err error
	s.defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
	if err != nil {
		s.Logger.Errorf("failed to parse DHCP route IP address: %v", err)
	}

	if s.nodeIP != "" && s.nodeIP != lease.HostIpAddress {
		s.Logger.Error("Update of Node IP address is not supported")
	}

	s.setNodeIP(lease.HostIpAddress)
	s.Logger.Info("DHCP event processed", lease)
}

// configureOtherVPPInterfaces other interfaces that were configured in contiv plugin YAML configuration.
func (s *remoteCNIserver) configureOtherVPPInterfaces(txn linuxclient.DataResyncDSL) {

	// match existing interfaces and configuration settings and create VPP configuration objects
	interfaces := make(map[string]*vpp_intf.Interface)
	for _, name := range s.swIfIndex.ListAllInterfaces() {
		for _, intIP := range s.nodeConfig.OtherVPPInterfaces {
			if intIP.InterfaceName == name {
				interfaces[name] = s.physicalInterface(name, intIP.IP)
			}
		}
	}

	// configure the interfaces on VPP
	if len(interfaces) > 0 {
		// add individual interfaces
		for _, intf := range interfaces {
			txn.VppInterface(intf)
			s.otherPhysicalIfs = append(s.otherPhysicalIfs, intf.Name)
		}
	}
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(txn linuxclient.DataResyncDSL) {
	if s.config.UseTAPInterfaces {
		// TAP interface
		txn.VppInterface(s.interconnectTap())
		txn.LinuxInterface(s.interconnectTapHost())
	} else {
		// veth + AF_PACKET
		txn.VppInterface(s.interconnectAfpacket()).
			LinuxInterface(s.interconnectVethHost()).
			LinuxInterface(s.interconnectVethVpp())
	}

	// configure the routes from VPP to host interfaces
	var routesToHost []*vpp_l3.StaticRoute
	if s.stnIP == "" {
		routesToHost = s.routesToHost(s.ipam.VEthHostEndIP().String())
	} else {
		routesToHost = s.routesToHost(s.ipPrefixToAddress(s.stnIP))
	}
	for _, r := range routesToHost {
		s.Logger.Debug("Adding route to host IP: ", r)
		txn.StaticRoute(r)
	}

	// configure the route from the host to PODs
	var routeFromHost *linux_l3.LinuxStaticRoute
	if s.stnGw == "" {
		routeFromHost = s.routePODsFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		routeFromHost = s.routePODsFromHost(s.stnGw)
	}
	txn.LinuxRoute(routeFromHost)

	// route from the host to k8s service range from the host
	var routeForServices *linux_l3.LinuxStaticRoute
	if s.stnGw == "" {
		routeForServices = s.routeServicesFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		routeForServices = s.routeServicesFromHost(s.stnGw)
	}
	txn.LinuxRoute(routeForServices)
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (s *remoteCNIserver) configureVswitchVrfRoutes(txn linuxclient.DataResyncDSL) {
	// routes from main towards POD VRF: PodSubnet + VPPHostSubnet
	vrfR1, vrfR2 := s.routesToPodVRF()
	txn.StaticRoute(vrfR1)
	txn.StaticRoute(vrfR2)

	// routes from POD towards main VRF: default route + VPPHostNetwork
	vrfR3, vrfR4 := s.routesPodToMainVRF()
	txn.StaticRoute(vrfR3)
	txn.StaticRoute(vrfR4)

	// add DROP routes into POD VRF to avoid loops: the same routes that point from main VRF to POD VRF are installed
	// into POD VRF as DROP, to not go back into the main VRF via default route in case that PODs are not reachable
	dropR1, dropR2 := s.dropRoutesIntoPodVRF()
	txn.StaticRoute(dropR1)
	txn.StaticRoute(dropR2)
}

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {

	// prepare the config transaction
	txn := s.vppTxnFactory().Delete()

	// unconfigure VPP-host interconnect interfaces
	if s.config.UseTAPInterfaces {
		tapVpp := s.interconnectTap()
		tapHost := s.interconnectTapHost()
		txn.VppInterface(tapVpp.Name).
			LinuxInterface(tapHost.Name)
	} else {
		vethHost := s.interconnectVethHost()
		vethVpp := s.interconnectVethVpp()

		txn.LinuxInterface(vethHost.Name).
			LinuxInterface(vethVpp.Name)
	}

	// execute the config transaction
	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Warn(err)
	}
}

// configureContainerConnectivity connects the POD to vSwitch VPP based on the CNI server configuration:
// either via virtual ethernet interface pair and AF_PACKET, or via TAP interface.
// It also configures the VPP TCP stack for this container, in case it would be LD_PRELOAD-ed.
func (s *remoteCNIserver) configureContainerConnectivity(request *cni.CNIRequest) (reply *cni.CNIReply, err error) {
	var (
		podIP     net.IP
		txn       linuxclient.PutDSL
	)

	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
	id := request.ContainerId

	defer func() {
		if err != nil {
			// XXX Reverting will be done automatically by KVScheduler
			if podIP != nil {
				s.ipam.ReleasePodIP(id)
			}
		}
	}()

	// assign an IP address for this POD
	podIP, err = s.ipam.NextPodIP(id)
	if err != nil {
		return nil, fmt.Errorf("Can't get new IP address for pod: %v", err)
	}
	podIPCIDR := podIP.String() + "/32"

	// prepare configuration for the POD interface
	txn = s.vppTxnFactory().Put()
	err = s.configurePodInterface(request, podIP, txn)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// prepare VPP-side of the POD-related configuration
	s.configurePodVPPSide(request, podIP, txn)

	// execute the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// prepare and send reply for the CNI request
	reply = s.generateCniReply(request, podIPCIDR)
	return reply, nil
}

// unconfigureContainerConnectivity disconnects the POD from vSwitch VPP.
func (s *remoteCNIserver) unconfigureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
	var err error

	txn := s.vppTxnFactory().Delete()

	// delete POD-related config on VPP
	s.unconfigurePodVPPSide(config, txn)

	// unconfigure POD interface
	s.unconfigurePodInterface(request, config, txn)

	// execute the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// release IP address of the POD
	err = s.ipam.ReleasePodIP(id)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// prepare and send reply for the CNI request
	reply := s.generateCniEmptyOKReply()
	return reply, nil
}

// configurePodInterface prepares transaction <txn> to configure POD's
// network interface and its routes + ARPs.
func (s *remoteCNIserver) configurePodInterface(request *cni.CNIRequest, podIP net.IP, txn linuxclient.PutDSL) (err error) {

	// this is necessary for the latest docker where ipv6 is disabled by default.
	// OS assigns automatically ipv6 addr to a newly created TAP. We
	// try to reassign all IPs once interfaces is moved to a namespace. Without explicitly enabled ipv6,
	// we receive an error while moving interface to a namespace.
	if !s.test {
		err = s.enableIPv6(request)
		if err != nil {
			s.Logger.Error("unable to enable ipv6 in the namespace")
			return err
		}
	}

	podIPCIDR := podIP.String() + "/32"
	podIPNet := &net.IPNet{
		IP:   podIP,
		Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
	}

	// create VPP to POD interconnect interface
	if s.config.UseTAPInterfaces {
		// TAP
		txn.VppInterface(s.tapFromRequest(request, podIP.String())).
			LinuxInterface(s.podTAP(request, podIPNet))
	} else {
		// VETH pair + AF_PACKET
		txn.LinuxInterface(s.veth1FromRequest(request, podIPCIDR)).
			LinuxInterface(s.veth2FromRequest(request)).
			VppInterface(s.afpacketFromRequest(request, podIP.String()))

	}

	// ARP to VPP
	_, linuxIfName := s.podInterfaceNameFromRequest(request)
	txn.LinuxArpEntry(s.podArpEntry(request, linuxIfName, s.generateHwAddrForPodVPPIf(request)))

	// link scope route
	txn.LinuxRoute(s.podLinkRouteFromRequest(request, linuxIfName))

	// Add default route for the container
	txn.LinuxRoute(s.podDefaultRouteFromRequest(request, linuxIfName))

	return nil
}

// unconfigurePodInterface prepares transaction <txn> to unconfigure POD's network
// interface and its routes + ARPs.
func (s *remoteCNIserver) unconfigurePodInterface(request *cni.CNIRequest, txn linuxclient.DeleteDSL) {

	// delete VPP to POD interconnect interface
	txn.VppInterface(config.VppIfName)
	if s.config.UseTAPInterfaces {
		txn.LinuxInterface(config.PodTapName)
	} else {
		txn.LinuxInterface(config.Veth1Name).
			LinuxInterface(config.Veth2Name)
	}

	txn.LinuxRoute(config.PodLinkRouteDest, config.PodLinkRouteInterface)
	txn.LinuxArpEntry(config.PodARPEntryInterface, config.PodARPEntryIP)
	txn.LinuxRoute(ipv4NetAny, config.PodDefaultRouteInterface)
}

// configurePodVPPSide prepares transaction <txn> to configure vswitch VPP part
// of the POD networking.
func (s *remoteCNIserver) configurePodVPPSide(request *cni.CNIRequest, podIP net.IP, txn linuxclient.PutDSL) {
	// route to PodIP via AF_PACKET / TAP
	txn.StaticRoute(s.vppRouteFromRequest(request, podIP))

	// ARP entry for POD IP
	vppIfName, _ := s.podInterfaceNameFromRequest(request)
	txn.Arp(s.vppArpEntry(vppIfName, podIP, s.hwAddrForContainer()))
}

// unconfigurePodVPPSide prepares transaction <txn> to delete vswitch VPP part of the POD networking.
func (s *remoteCNIserver) unconfigurePodVPPSide(config *container.Persisted, txn linuxclient.DeleteDSL) {
	// route to PodIP via AF_PACKET / TAP
	txn.StaticRoute(config.VppRouteVrf, config.VppRouteDest, config.VppRouteNextHop)

	// ARP entry for POD IP
	txn.Arp(config.VppARPEntryInterface, config.VppARPEntryIP)
}

// parseCniExtraArgs parses CNI extra arguments from a string into a map.
func (s *remoteCNIserver) parseCniExtraArgs(input string) map[string]string {
	res := map[string]string{}

	pairs := strings.Split(input, ";")
	for i := range pairs {
		kv := strings.Split(pairs[i], "=")
		if len(kv) == 2 {
			res[kv[0]] = kv[1]
		}
	}
	return res
}

// generateCniReply fills the CNI reply with the data of an interface.
func (s *remoteCNIserver) generateCniReply(request *cni.CNIRequest, podIP string) *cni.CNIReply {
	return &cni.CNIReply{
		Result: resultOk,
		Interfaces: []*cni.CNIReply_Interface{
			{
				Name:    request.InterfaceName,
				Sandbox: request.NetworkNamespace,
				IpAddresses: []*cni.CNIReply_Interface_IP{
					{
						Version: cni.CNIReply_Interface_IP_IPV4,
						Address: podIP,
						Gateway: s.ipam.PodGatewayIP().String(),
					},
				},
			},
		},
		Routes: []*cni.CNIReply_Route{
			{
				Dst: "0.0.0.0/0",
				Gw:  s.ipam.PodGatewayIP().String(),
			},
		},
	}
}

// generateCniEmptyOKReply generates CNI reply with OK result code and empty body.
func (s *remoteCNIserver) generateCniEmptyOKReply() *cni.CNIReply {
	return &cni.CNIReply{
		Result: resultOk,
	}
}

// generateCniErrorReply generates CNI error reply with the proper result code and error message.
func (s *remoteCNIserver) generateCniErrorReply(err error) (*cni.CNIReply, error) {
	reply := &cni.CNIReply{
		Result: resultErr,
		Error:  err.Error(),
	}
	return reply, err
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (s *remoteCNIserver) GetMainPhysicalIfName() string {
	s.Lock()
	defer s.Unlock()

	return s.mainPhysicalIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (s *remoteCNIserver) GetOtherPhysicalIfNames() []string {
	s.Lock()
	defer s.Unlock()

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
	return s.hostInterconnectIfName()
}

// GetNodeIP returns the IP address of this node.
func (s *remoteCNIserver) GetNodeIP() (ip net.IP, network *net.IPNet) {
	s.Lock()
	defer s.Unlock()

	if s.nodeIP == "" {
		return nil, nil
	}

	nodeIP, nodeNet, err := net.ParseCIDR(s.nodeIP)
	if err != nil {
		return nil, nil
	}

	return nodeIP, nodeNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (s *remoteCNIserver) GetHostIPs() []net.IP {
	s.Lock()
	defer s.Unlock()

	return s.hostIPs
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (s *remoteCNIserver) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	// TODO
	return "", "", false
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (s *remoteCNIserver) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	// TODO
	return "", false
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (s *remoteCNIserver) WatchNodeIP(subscriber chan string) {
	s.Lock()
	defer s.Unlock()

	s.nodeIPsubscribers = append(s.nodeIPsubscribers, subscriber)
}

// RegisterPodPreRemovalHook allows to register callback that will be run for each
// pod immediately before its removal.
func (s *remoteCNIserver) RegisterPodPreRemovalHook(hook PodActionHook) {
	s.Lock()
	defer s.Unlock()

	s.podPreRemovalHooks = append(s.podPreRemovalHooks, hook)
}

// RegisterPodPostAddHook allows to register callback that will be run for each
// pod once it is added and before the CNI reply is sent.
func (s *remoteCNIserver) RegisterPodPostAddHook(hook PodActionHook) {
	s.Lock()
	defer s.Unlock()

	s.podPostAddHook = append(s.podPostAddHook, hook)
}

// setNodeIP updates nodeIP and propagate the change to subscribers
// the method must be called with acquired mutex guarding remoteCNI server
func (s *remoteCNIserver) setNodeIP(nodeIP string) error {

	s.nodeIP = nodeIP

	for _, sub := range s.nodeIPsubscribers {
		select {
		case sub <- nodeIP:
		default:
			// skip subscribers who are not ready to receive notification
		}
	}

	return nil
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (s *remoteCNIserver) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	s.Lock()
	defer s.Unlock()

	if s.defaultGw != nil {
		if s.mainPhysicalIf != "" {
			nodeIP, nodeNet, _ := net.ParseCIDR(s.nodeIP)
			if nodeNet != nil && nodeNet.Contains(s.defaultGw) {
				return s.mainPhysicalIf, nodeIP
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
	return s.config.StealFirstNIC || s.config.StealInterface != "" || (s.nodeConfig != nil && s.nodeConfig.StealInterface != "")
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
