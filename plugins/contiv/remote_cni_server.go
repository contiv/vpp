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
	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/vpp-agent/clientv1/linux"
	linux_intf "github.com/ligato/vpp-agent/plugins/linux/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linux/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vpp/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vpp/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	"github.com/ligato/vpp-agent/plugins/vpp/model/stn"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"time"
)

const (
	resultOk               uint32 = 0
	resultErr              uint32 = 1
	linuxIfMaxLen                 = 15
	afPacketNamePrefix            = "afpacket"
	tapNamePrefix                 = "tap"
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
	vppTxnFactory func() linuxclient.DataChangeDSL

	// kvdbsync plugin with ability to filter the change events
	proxy kvdbproxy.Proxy

	// GoVPP channel for direct binary API calls (if needed)
	govppChan api.Channel

	// VPP interface index map
	swIfIndex ifaceidx.SwIfIndex

	// VPP dhcp index map
	dhcpIndex ifaceidx.DhcpIndex

	// map of configured containers
	configuredContainers *containeridx.ConfigIndex

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// set to true when running unit tests
	test bool

	// agent microservice label
	agentLabel string

	// unique identifier of the node
	nodeID uint32

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

	// other configuration
	tcpChecksumOffloadDisabled bool

	// the variables ensures that add/del requests are processed
	// only when vswitch connectivity is configured
	vswitchConnectivityConfigured bool
	vswitchCond                   *sync.Cond

	// if the flag is true only veth without stn and tcp stack is configured
	disableTCPstack bool

	// if the flag is true, TAP interfaces are used instead of VETHs for VPP-Pod
	// interconnection.
	useTAPInterfaces bool

	// version of the TAP interface to use (if useTAPInterfaces==true)
	tapVersion uint8

	// Rx/Tx ring size for TAPv2
	tapV2RxRingSize uint16
	tapV2TxRingSize uint16

	// use pure L2 node interconnect instead of VXLANs
	useL2Interconnect bool

	// bridge domain used for VXLAN tunnels
	vxlanBD *vpp_l2.BridgeDomains_BridgeDomain

	// name of the main physical interface
	mainPhysicalIf string

	// name of extra physical interfaces configured by the agent
	otherPhysicalIfs []string

	// name of the interface interconnecting VPP with the host stack
	hostInterconnectIfName string

	// the name of an BVI interface facing towards VXLAN tunnels to other hosts
	vxlanBVIIfName string

	stnIP string
	stnGw string

	// default gateway IP address
	defaultGw net.IP

	// dhcpNotif is channel where dhcp events are forwarded
	dhcpNotif chan ifaceidx.DhcpIdxDto

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	// the map holds containerID of pods that have been configured in this vswitch run
	// this structure is intentionally not persisted
	configuredInThisRun map[string]bool

	// nodeIDResyncRev is the latest revision in the resync event. Buffered changes generated
	// before the resync revision are ignored
	nodeIDResyncRev int64

	// nodeIDChangeEvs is buffer where change events are stored until resync event is processed
	nodeIDChangeEvs []datasync.ChangeEvent

	http rest.HTTPHandlers
}

// vswitchConfig holds base vSwitch VPP configuration.
type vswitchConfig struct {
	// configured if set to true denotes that vswitch configuration is applied by resync of default plugins
	// the local client txns are not executed only local variables are filled in order to provide correct values by getters
	configured bool

	nics         []*vpp_intf.Interfaces_Interface
	defaultRoute *vpp_l3.StaticRoutes_Route

	tapHost        *linux_intf.LinuxInterfaces_Interface
	tapVpp         *vpp_intf.Interfaces_Interface
	vethHost       *linux_intf.LinuxInterfaces_Interface
	vethVpp        *linux_intf.LinuxInterfaces_Interface
	interconnectAF *vpp_intf.Interfaces_Interface

	routesToHost     []*vpp_l3.StaticRoutes_Route
	routeFromHost    *linux_l3.LinuxStaticRoutes_Route
	routeForServices *linux_l3.LinuxStaticRoutes_Route
	vrfRoutes        []*vpp_l3.StaticRoutes_Route
	l4Features       *vpp_l4.L4Features

	vxlanBVI *vpp_intf.Interfaces_Interface
	vxlanBD  *vpp_l2.BridgeDomains_BridgeDomain
}

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linuxclient.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govppChan api.Channel, index ifaceidx.SwIfIndex, dhcpIndex ifaceidx.DhcpIndex, agentLabel string,
	config *Config, nodeConfig *NodeConfig, nodeID uint32, nodeExcludeIPs []net.IP, broker keyval.ProtoBroker, http rest.HTTPHandlers) (*remoteCNIserver, error) {

	ipam, err := ipam.New(logger, nodeID, agentLabel, &config.IPAMConfig, nodeExcludeIPs, broker)
	if err != nil {
		return nil, err
	}

	server := &remoteCNIserver{
		Logger:               logger,
		vppTxnFactory:        vppTxnFactory,
		proxy:                proxy,
		configuredContainers: configuredContainers,
		govppChan:            govppChan,
		swIfIndex:            index,
		dhcpIndex:            dhcpIndex,
		agentLabel:           agentLabel,
		nodeID:               nodeID,
		ipam:                 ipam,
		nodeConfig:           nodeConfig,
		config:               config,
		http:                 http,
		tcpChecksumOffloadDisabled: config.TCPChecksumOffloadDisabled,
		useTAPInterfaces:           config.UseTAPInterfaces,
		tapVersion:                 config.TAPInterfaceVersion,
		tapV2RxRingSize:            config.TAPv2RxRingSize,
		tapV2TxRingSize:            config.TAPv2TxRingSize,
		disableTCPstack:            config.TCPstackDisabled,
		useL2Interconnect:          config.UseL2Interconnect,
		configuredInThisRun:        map[string]bool{},
	}
	server.vswitchCond = sync.NewCond(&server.Mutex)
	server.ctx, server.ctxCancelFunc = context.WithCancel(context.Background())
	if nodeConfig != nil && nodeConfig.Gateway != "" {
		server.defaultGw = net.ParseIP(nodeConfig.Gateway)
	}
	server.dhcpNotif = make(chan ifaceidx.DhcpIdxDto, 1)
	server.registerHandlers()
	return server, nil
}

// resync is called by the plugin infra when the state of the GRPC server needs to be resynchronized,
// including the initialization phase
func (s *remoteCNIserver) resync() error {
	s.Lock()
	defer s.Unlock()

	err := s.configureVswitchConnectivity()
	if err != nil {
		s.Logger.Error(err)
	}

	return err
}

// close is called by the plugin infra when the CNI server needs to be stopped.
func (s *remoteCNIserver) close() {
	s.cleanupVswitchConnectivity()
	s.ctxCancelFunc()
	close(s.dhcpNotif)
}

// Add handles CNI Add request, connects the container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)

	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)

	reply, err := s.configureContainerConnectivity(request)
	if err != nil {
		return reply, err
	}
	// Run all registered post add hooks. Once remote cni server lock is released.
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
	return s.unconfigureContainerConnectivity(request)
}

// configureVswitchConnectivity configures base vSwitch VPP connectivity to the host IP stack and to the other hosts.
// Namely, it configures:
//  - physical NIC interface + static routes to PODs on other hosts
//  - veth pair to host IP stack + AF_PACKET on VPP side
//  - default static route to the host via the veth pair
func (s *remoteCNIserver) configureVswitchConnectivity() error {

	s.Logger.Info("Applying base vSwitch config.")
	s.Logger.Info("Existing interfaces: ", s.swIfIndex.GetMapping().ListNames())

	// determine interface name that can be used to check whether vswitch connectivity is already configured
	var expectedIfName string
	if s.useTAPInterfaces {
		expectedIfName = TapVPPEndLogicalName
	} else {
		expectedIfName = s.interconnectAfpacketName()
	}
	if s.UseSTN() {
		// For STN case, do not rely on TAP interconnect, since it has been pre-configured by contiv-init.
		// Let's relay on VXLAN BVI interface name. Note that this may not work in case that VXLANs are disabled.
		expectedIfName = vxlanBVIInterfaceName
		if s.config.UseL2Interconnect {
			s.Logger.Warn("Unable to reliably determine whether VSwitch connectivity is configured, proceeeding with config.")
		}
	}

	// prepare empty vswitch config struct to be filled in
	config := &vswitchConfig{nics: []*vpp_intf.Interfaces_Interface{}}

	// only apply the config if resync hasn't done it already
	if _, _, found := s.swIfIndex.LookupIdx(expectedIfName); found {
		s.Logger.Info("VSwitch connectivity is considered configured, skipping...")
		config.configured = true
	}

	// configure physical NIC
	// NOTE that needs to be done as the first step, before adding any other interfaces to VPP to properly fnd the physical NIC name.
	err := s.configureVswitchNICs(config)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	err = s.configureVswitchHostConnectivity(config)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if !s.useL2Interconnect {
		// configure VXLAN tunnel bridge domain
		err = s.configureVswitchVxlanBridgeDomain(config)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	// configure inter-VRF routing
	err = s.configureVswitchVrfRoutes(config)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// persist vswitch configuration in ETCD
	err = s.persistVswitchConfig(config)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if s.nodeIP != "" {
		// set the state to configured and broadcast
		s.vswitchConnectivityConfigured = true
		s.vswitchCond.Broadcast()
	}
	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (s *remoteCNIserver) configureVswitchNICs(config *vswitchConfig) error {

	if s.swIfIndex == nil {
		return fmt.Errorf("no VPP interfaces found in the swIfIndex map")
	}
	s.Logger.Info("Existing interfaces: ", s.swIfIndex.GetMapping().ListNames())

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
		for _, name := range s.swIfIndex.GetMapping().ListNames() {
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

	// configure the main VPP NIC interface
	err := s.configureMainVPPInterface(config, nicName, nicIP, useDHCP)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if s.nodeConfig != nil && len(s.nodeConfig.OtherVPPInterfaces) > 0 {
		s.Logger.Debug("Configuring VPP for additional interfaces")

		err := s.configureOtherVPPInterfaces(config, s.nodeConfig)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	// enable IP neighbor scanning (to clean up old ARP entries)
	// TODO: handle by localclient/resync once implemented in VPP agent
	s.enableIPNeighborScan()

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	s.subscribeVnetFibCounters()

	// Disable NAT virtual reassembly (drop fragmented packets) if requested
	if s.config.DisableNATVirtualReassembly {
		s.disableNatVirtualReassembly()
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(config *vswitchConfig, nicName string, nicIP string, useDHCP bool) error {
	var err error
	txn := s.vppTxnFactory().Put()

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
				s.dhcpIndex.WatchNameToIdx("cniserver", s.dhcpNotif)
				go s.handleDHCPNotifications(s.dhcpNotif)
				// do lookup to cover the case where dhcp was configured by resync
				// and ip address is already assigned
				_, metadata, exists := s.dhcpIndex.LookupIdx(nicName)
				if exists {
					s.Logger.Infof("DHCP notification already recieved: %v", metadata)
					s.applyDHCPdata(metadata)
				} else {
					s.Logger.Debugf("Waiting for DHCP notification. Existing DHCP events: %v", s.dhcpIndex.GetMapping().ListNames())
				}
			}
			txn.VppInterface(nic)
			config.nics = append(config.nics, nic)
			s.mainPhysicalIf = nicName
		} else {
			// configure loopback instead of the physical NIC
			s.Logger.Debug("Physical NIC not found, configuring loopback instead.")

			loop := s.physicalInterfaceLoopback(s.nodeIP)
			txn.VppInterface(loop)
			config.nics = append(config.nics, loop)
		}

		if nicName != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
			// configure the default gateway
			config.defaultRoute = s.defaultRoute(s.nodeConfig.Gateway, nicName)
			txn.StaticRoute(config.defaultRoute)
		}

		// execute the config transaction
		if !config.configured {
			err = txn.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
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
func (s *remoteCNIserver) handleDHCPNotifications(notifCh chan ifaceidx.DhcpIdxDto) {

	for {
		select {
		case notif := <-notifCh:
			s.Logger.Info("DHCP notification received")
			if notif.Del {
				continue
			}
			if notif.Metadata == nil {
				s.Logger.Warn("DHCP notification metadata is empty")
				continue

			}
			if notif.Metadata.IfName != s.mainPhysicalIf {
				continue
			}

			s.Lock()
			s.applyDHCPdata(notif.Metadata)
			s.Unlock()

		case <-s.ctx.Done():
			return
		}
	}

}

func (s *remoteCNIserver) applyDHCPdata(notif *ifaceidx.DHCPSettings) {

	s.Logger.Debug("Processing DHCP event", notif)

	ipAddr := fmt.Sprintf("%s/%d", notif.IPAddress, notif.Mask)
	s.defaultGw = net.ParseIP(notif.RouterAddress)

	if s.nodeIP != "" && s.nodeIP != ipAddr {
		s.Logger.Error("Update of Node IP address is not supported")
	}
	s.vswitchConnectivityConfigured = true
	s.vswitchCond.Broadcast()
	s.setNodeIP(ipAddr)

	s.Logger.Info("DHCP event processed", notif)
}

// configureOtherVPPInterfaces other interfaces that were configured in contiv plugin YAML configuration.
func (s *remoteCNIserver) configureOtherVPPInterfaces(config *vswitchConfig, nodeConfig *NodeConfig) error {

	// match existing interfaces and configuration settings and create VPP configuration objects
	interfaces := make(map[string]*vpp_intf.Interfaces_Interface)
	for _, name := range s.swIfIndex.GetMapping().ListNames() {
		for _, intIP := range nodeConfig.OtherVPPInterfaces {
			if intIP.InterfaceName == name {
				interfaces[name] = s.physicalInterface(name, intIP.IP)
			}
		}
	}

	// configure the interfaces on VPP
	if len(interfaces) > 0 {
		// prepare the config transaction
		txn := s.vppTxnFactory().Put()

		// add individual interfaces
		for _, intf := range interfaces {
			txn.VppInterface(intf)
			config.nics = append(config.nics, intf)
			s.otherPhysicalIfs = append(s.otherPhysicalIfs, intf.Name)
		}

		if !config.configured {
			// execute the config transaction
			err := txn.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		}
	}

	return nil
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(config *vswitchConfig) error {
	var err error
	txn := s.vppTxnFactory().Put()

	if s.stnIP == "" {
		// execute only if STN has not already configured this

		if s.useTAPInterfaces {
			// TAP interface
			config.tapVpp = s.interconnectTap()
			config.tapHost = s.interconnectTapHost()

			s.hostInterconnectIfName = config.tapVpp.Name

			txn.VppInterface(config.tapVpp)
			txn.LinuxInterface(config.tapHost)
		} else {
			// veth + AF_PACKET
			config.vethHost = s.interconnectVethHost()
			config.vethVpp = s.interconnectVethVpp()
			config.interconnectAF = s.interconnectAfpacket()

			s.hostInterconnectIfName = config.interconnectAF.Name

			txn.LinuxInterface(config.vethHost).
				LinuxInterface(config.vethVpp)
		}
	} else {
		if s.useTAPInterfaces {
			s.hostInterconnectIfName = TapVPPEndLogicalName
		} else {
			s.hostInterconnectIfName = s.interconnectAfpacketName()
		}
	}

	// configure the routes from VPP to host interfaces
	//
	// TODO: this is a temporary solution, should be removed once
	// the main node IP address as seen by k8s is determined by k8s API
	if s.stnIP == "" {
		config.routesToHost = s.routesToHost(s.ipam.VEthHostEndIP().String())
	} else {
		config.routesToHost = s.routesToHost(s.ipPrefixToAddress(s.stnIP))
	}
	for _, r := range config.routesToHost {
		s.Logger.Debug("Adding route to host IP: ", r)
		txn.StaticRoute(r)
	}

	// configure the route from the host to PODs
	if s.stnGw == "" {
		config.routeFromHost = s.routePODsFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		config.routeFromHost = s.routePODsFromHost(s.stnGw)
	}
	txn.LinuxRoute(config.routeFromHost)

	// route from the host to k8s service range from the host
	if s.stnGw == "" {
		config.routeForServices = s.routeServicesFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		config.routeForServices = s.routeServicesFromHost(s.stnGw)
	}
	txn.LinuxRoute(config.routeForServices)

	// enable L4 features
	config.l4Features = s.l4Features(!s.disableTCPstack)
	txn.L4Features(config.l4Features)

	if !config.configured {
		// execute the config transaction
		err = txn.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}

		// finalize AFPacket+VETH configuration
		if !s.useTAPInterfaces {
			// AFPacket is intentionally configured in a txn different from the one that configures veth.
			// Otherwise if the veth exists before the first transaction (i.e. vEth pair was not deleted after last run)
			// configuring AfPacket might return an error since linux plugin deletes the existing veth and creates a new one.
			err = s.vppTxnFactory().Put().VppInterface(config.interconnectAF).Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		}

	}

	return nil
}

// configureVswitchVxlanBridgeDomain configures bridge domain for the VXLAN tunnels.
func (s *remoteCNIserver) configureVswitchVxlanBridgeDomain(config *vswitchConfig) error {
	var err error
	txn := s.vppTxnFactory().Put()

	// VXLAN BVI loopback
	config.vxlanBVI, err = s.vxlanBVILoopback()
	if err != nil {
		s.Logger.Error(err)
		return err
	}
	txn.VppInterface(config.vxlanBVI)
	s.vxlanBVIIfName = config.vxlanBVI.Name

	// bridge domain for the VXLAN tunnel
	config.vxlanBD = s.vxlanBridgeDomain(config.vxlanBVI.Name)
	// create deep copy since the config will be overwritten when a node joins the cluster
	newbd := proto.Clone(config.vxlanBD)
	txn.BD(newbd.(*vpp_l2.BridgeDomains_BridgeDomain))
	// remember the VXLAN config - needs to be reconfigured with each new VXLAN (each new node)
	s.vxlanBD = config.vxlanBD

	// execute the config transaction
	if !config.configured {
		err = txn.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (s *remoteCNIserver) configureVswitchVrfRoutes(config *vswitchConfig) error {
	var err error
	txn := s.vppTxnFactory().Put()

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

	config.vrfRoutes = []*vpp_l3.StaticRoutes_Route{vrfR1, vrfR2, vrfR3, vrfR4, dropR1, dropR2}

	// execute the config transaction
	if !config.configured {
		err = txn.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// persistVswitchConfig persists vswitch configuration in ETCD
func (s *remoteCNIserver) persistVswitchConfig(config *vswitchConfig) error {
	if config.configured {
		s.Logger.Info("Persisting of vswitch configuration is skipped")
		return nil
	}

	var err error
	changes := map[string]proto.Message{}

	// physical NICs + default route
	for _, nic := range config.nics {
		changes[vpp_intf.InterfaceKey(nic.Name)] = nic
	}
	if config.defaultRoute != nil {
		changes[vpp_l3.RouteKey(config.defaultRoute.VrfId, config.defaultRoute.DstIpAddr, config.defaultRoute.NextHopAddr)] = config.defaultRoute
	}

	// VXLAN-related data
	if !s.useL2Interconnect {
		changes[vpp_intf.InterfaceKey(config.vxlanBVI.Name)] = config.vxlanBVI
	}

	// TAP / veths + AF_APCKET
	if s.useTAPInterfaces {
		if config.tapHost != nil {
			changes[vpp_intf.InterfaceKey(config.tapVpp.Name)] = config.tapVpp
			changes[linux_intf.InterfaceKey(config.tapHost.Name)] = config.tapHost
		}
	} else {
		changes[linux_intf.InterfaceKey(config.vethHost.Name)] = config.vethHost
		changes[linux_intf.InterfaceKey(config.vethVpp.Name)] = config.vethVpp
		changes[vpp_intf.InterfaceKey(config.interconnectAF.Name)] = config.interconnectAF
	}

	// routes + l4 config
	if config.routesToHost != nil {
		for _, r := range config.routesToHost {
			changes[vpp_l3.RouteKey(r.VrfId, r.DstIpAddr, r.NextHopAddr)] = r
		}
	}
	changes[linux_l3.StaticRouteKey(config.routeFromHost.Name)] = config.routeFromHost
	changes[linux_l3.StaticRouteKey(config.routeForServices.Name)] = config.routeForServices
	if config.vrfRoutes != nil {
		for _, r := range config.vrfRoutes {
			changes[vpp_l3.RouteKey(r.VrfId, r.DstIpAddr, r.NextHopAddr)] = r
		}
	}
	changes[vpp_l4.FeatureKey()] = config.l4Features

	// persist the changes in ETCD
	err = s.persistChanges(nil, changes, true)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {

	// prepare the config transaction
	txn := s.vppTxnFactory().Delete()

	// unconfigure VPP-host interconnect interfaces
	if s.useTAPInterfaces {
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
		podIP          net.IP
		persisted      bool
		txn            linuxclient.PutDSL
		revertTxn      linuxclient.DeleteDSL
		revertFirstTxn linuxclient.DeleteDSL
	)

	// do not connect any containers until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	// prepare config details struct
	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
	config := &PodConfig{
		ID:           request.ContainerId,
		PodName:      extraArgs[podNameExtraArg],
		PodNamespace: extraArgs[podNamespaceExtraArg],
	}

	id := config.ID

	defer func() {
		if err != nil {
			if persisted {
				s.deletePersistedPodConfig(podConfigToProto(config))
				delete(s.configuredInThisRun, id)
			}
			if revertFirstTxn != nil {
				revertFirstTxn.Send().ReceiveReply()
			}
			if revertTxn != nil {
				revertTxn.Send().ReceiveReply()
			}
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
	revertTxn = s.vppTxnFactory().Delete()
	txn = s.vppTxnFactory().Put()
	err = s.configurePodInterface(request, podIP, config, txn, revertTxn)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// create a separate revert txn because the route must be deleted
	// before its outgoing interface. Otherwise, it remains dangling.
	revertFirstTxn = s.vppTxnFactory().Delete()
	// prepare VPP-side of the POD-related configuration
	err = s.configurePodVPPSide(request, podIP, config, txn, revertFirstTxn)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// execute the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// if requested, disable TCP checksum offload on the eth0 veth/TAP interface in the container.
	if s.tcpChecksumOffloadDisabled {
		err = s.disableTCPChecksumOffload(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
	}

	// persist POD configuration in ETCD
	err = s.persistPodConfig(config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}
	s.configuredInThisRun[id] = true
	persisted = true

	// store configuration internally for other plugins in the internal map
	if s.configuredContainers != nil {
		// Remove previous entry for the pod if there is any.
		podNamesMatch := s.configuredContainers.LookupPodName(config.PodName)
		for _, containerID := range podNamesMatch {
			podData, _ := s.configuredContainers.LookupContainer(containerID)
			if podData.PodNamespace == config.PodNamespace {
				s.Logger.WithFields(
					logging.Fields{
						"name":        config.PodName,
						"namespace":   config.PodNamespace,
						"containerID": containerID,
					}).Info("Removing outdated pod")
				delRequest := &cni.CNIRequest{
					ContainerId: containerID,
				}
				_, err := s.unconfigureContainerConnectivityWithoutLock(delRequest)
				if err != nil {
					s.Logger.Warn("Error while removing outdated pod ", err)
				}
				break
			}
		}

		err = s.configuredContainers.RegisterContainer(id, podConfigToProto(config))
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
	}

	// verify that the POD has the allocated IP address configured / wait until it is actually configured
	err = s.verifyPodIP(request.NetworkNamespace, request.InterfaceName, podIP)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// prepare and send reply for the CNI request
	reply = s.generateCniReply(config, request.NetworkNamespace, podIPCIDR)
	return reply, nil
}

// unconfigureContainerConnectivity disconnects the POD from vSwitch VPP.
func (s *remoteCNIserver) unconfigureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
	// do not try to disconnect any containers until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	s.Unlock()

	var err error
	// configuredContainers should not be nil unless this is a unit test
	if s.configuredContainers == nil {
		err = fmt.Errorf("configuration was not stored for container: %s", request.ContainerId)
		s.Logger.Warn(err)
		return s.generateCniEmptyOKReply(), nil
	}

	id := request.ContainerId
	// load container config
	config, found := s.configuredContainers.LookupContainer(id)
	if !found {
		s.Logger.Warnf("cannot find configuration for container: %s\n", id)
		reply := s.generateCniEmptyOKReply()
		return reply, nil
	}

	// Run all registered pre-removal hooks, before lock is acquired
	for _, hook := range s.podPreRemovalHooks {
		err = hook(config.PodNamespace, config.PodName)
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod pre-removal hook has failed")
			err = nil
		}
	}

	s.Lock()
	defer s.Unlock()

	s.Logger.Infof("Delete hooks executed, processing of del request started %v %v", config.PodName, config.PodNamespace)

	return s.unconfigureContainerConnectivityWithoutLock(request)
}

// unconfigureContainerConnectivity disconnects the POD from vSwitch VPP the method expect the lock to be already acquired.
func (s *remoteCNIserver) unconfigureContainerConnectivityWithoutLock(request *cni.CNIRequest) (*cni.CNIReply, error) {
	var err error

	// configuredContainers should not be nil unless this is a unit test
	if s.configuredContainers == nil {
		err = fmt.Errorf("configuration was not stored for container: %s", request.ContainerId)
		s.Logger.Warn(err)
		return s.generateCniEmptyOKReply(), nil
	}

	id := request.ContainerId
	// load container config
	config, found := s.configuredContainers.LookupContainer(id)
	if !found {
		s.Logger.Warnf("cannot find configuration for container: %s\n", id)
		reply := s.generateCniEmptyOKReply()
		return reply, nil
	}

	txn := s.vppTxnFactory().Delete()

	// delete POD-related config on VPP
	err = s.unconfigurePodVPPSide(config, txn)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// unconfigure POD interface
	err = s.unconfigurePodInterface(request, config, txn)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// execute the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// delete persisted POD configuration from ETCD
	err = s.deletePersistedPodConfig(config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// remove POD configuration from the internal map
	if s.configuredContainers != nil {
		_, _, err = s.configuredContainers.UnregisterContainer(id)
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
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
func (s *remoteCNIserver) configurePodInterface(request *cni.CNIRequest, podIP net.IP, config *PodConfig,
	txn linuxclient.PutDSL, revertTxn linuxclient.DeleteDSL) error {

	// this is necessary for the latest docker where ipv6 is disabled by default.
	// OS assigns automatically ipv6 addr to a newly created TAP. We
	// try to reassign all IPs once interfaces is moved to a namespace. Without explicitly enabled ipv6,
	// we receive an error while moving interface to a namespace.
	if !s.test {
		err := s.enableIPv6(request)
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

	podIfName := ""

	// create VPP to POD interconnect interface
	if s.useTAPInterfaces {
		// TAP interface
		config.VppIf = s.tapFromRequest(request, podIP.String(), !s.disableTCPstack, podIPCIDR)
		config.PodTap = s.podTAP(request, podIPNet)

		podIfName = config.PodTap.Name

		// VPP-side of the TAP
		txn.VppInterface(config.VppIf)
		revertTxn.VppInterface(config.VppIf.Name)

		// Linux-side of the TAP
		txn.LinuxInterface(config.PodTap)
	} else {
		// veth pair + AF_PACKET
		config.Veth1 = s.veth1FromRequest(request, podIPCIDR)
		config.Veth2 = s.veth2FromRequest(request)
		config.VppIf = s.afpacketFromRequest(request, podIP.String(), !s.disableTCPstack, podIPCIDR)

		txn.LinuxInterface(config.Veth1).
			LinuxInterface(config.Veth2).
			VppInterface(config.VppIf)
		revertTxn.VppInterface(config.VppIf.Name)
		podIfName = config.Veth1.Name
	}

	// link scope route
	config.PodLinkRoute = s.podLinkRouteFromRequest(request, podIfName)
	txn.LinuxRoute(config.PodLinkRoute)

	// ARP to VPP
	config.PodARPEntry = s.podArpEntry(request, podIfName, config.VppIf.PhysAddress)
	txn.LinuxArpEntry(config.PodARPEntry)

	// Add default route for the container
	config.PodDefaultRoute = s.podDefaultRouteFromRequest(request, podIfName)
	txn.LinuxRoute(config.PodDefaultRoute)

	return nil
}

// unconfigurePodInterface prepares transaction <txn> to unconfigure POD's network
// interface.
func (s *remoteCNIserver) unconfigurePodInterface(request *cni.CNIRequest, config *container.Persisted,
	txn linuxclient.DeleteDSL) error {

	// delete VPP to POD interconnect interface
	txn.VppInterface(config.VppIfName)
	if !s.useTAPInterfaces {
		txn.LinuxInterface(config.Veth1Name).
			LinuxInterface(config.Veth2Name)
	}

	return nil
}

// configurePodVPPSide prepares transaction <txn> to configure vswitch VPP part
// of the POD networking.
func (s *remoteCNIserver) configurePodVPPSide(request *cni.CNIRequest, podIP net.IP, config *PodConfig,
	txn linuxclient.PutDSL, revertTxn linuxclient.DeleteDSL) error {

	podIPCIDR := podIP.String() + "/32"

	if !s.disableTCPstack {
		// VPP TCP stack config
		config.Loopback = s.loopbackFromRequest(request, podIP.String())
		config.AppNamespace = s.appNamespaceFromRequest(request)
		config.StnRule = s.stnRule(podIP, config.VppIf.Name)

		txn.VppInterface(config.Loopback).
			AppNamespace(config.AppNamespace).
			StnRule(config.StnRule)
		revertTxn.VppInterface(config.Loopback.Name).
			AppNamespace(config.AppNamespace.NamespaceId).
			StnRule(config.StnRule.RuleName)
	} else {
		// route to PodIP via AF_PACKET / TAP
		config.VppRoute = s.vppRouteFromRequest(request, podIPCIDR)

		txn.StaticRoute(config.VppRoute)
		revertTxn.StaticRoute(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr)
	}

	// ARP entry for POD IP
	config.VppARPEntry = s.vppArpEntry(config.VppIf.Name, podIP, s.hwAddrForContainer())
	txn.Arp(config.VppARPEntry)
	revertTxn.Arp(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress)

	return nil
}

// unconfigurePodVPPSide prepares transaction <txn> to delete vswitch VPP part of the POD networking.
func (s *remoteCNIserver) unconfigurePodVPPSide(config *container.Persisted, txn linuxclient.DeleteDSL) error {

	// TODO: remove once agent can handle simultaneous removal of route+arp+interface
	txn2 := s.vppTxnFactory().Delete()

	if !s.disableTCPstack {
		// VPP TCP stack config
		txn2.VppInterface(config.LoopbackName).
			AppNamespace(config.AppNamespaceID).
			StnRule(config.StnRuleName)
	} else {
		// route to PodIP via AF_PACKET / TAP
		txn2.StaticRoute(config.VppRouteVrf, config.VppRouteDest, config.VppRouteNextHop)
	}

	// ARP entry for POD IP
	txn2.Arp(config.VppARPEntryInterface, config.VppARPEntryIP)

	// TODO: remove once agent can handle simultaneous removal of route+arp+interface
	err := txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// deletePersistedPodConfig persists POD configuration into ETCD.
func (s *remoteCNIserver) persistPodConfig(config *PodConfig) error {
	var err error
	changes := map[string]proto.Message{}

	// POD interface configuration
	changes[vpp_intf.InterfaceKey(config.VppIf.Name)] = config.VppIf
	if !s.useTAPInterfaces {
		changes[linux_intf.InterfaceKey(config.Veth1.Name)] = config.Veth1
		changes[linux_intf.InterfaceKey(config.Veth2.Name)] = config.Veth2
	} else {
		changes[linux_intf.InterfaceKey(config.PodTap.Name)] = config.PodTap
	}
	changes[linux_l3.StaticRouteKey(config.PodLinkRoute.Name)] = config.PodLinkRoute
	changes[linux_l3.StaticRouteKey(config.PodDefaultRoute.Name)] = config.PodDefaultRoute
	changes[linux_l3.StaticArpKey(config.PodARPEntry.Name)] = config.PodARPEntry

	// VPP-side configuration
	if !s.disableTCPstack {
		changes[vpp_intf.InterfaceKey(config.Loopback.Name)] = config.Loopback
		changes[stn.Key(config.StnRule.RuleName)] = config.StnRule
		changes[vpp_l4.AppNamespacesKey(config.AppNamespace.NamespaceId)] = config.AppNamespace
	} else {
		changes[vpp_l3.RouteKey(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr)] = config.VppRoute
	}
	changes[vpp_l3.ArpEntryKey(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress)] = config.VppARPEntry

	// persist the configuration
	err = s.persistChanges(nil, changes, true)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// deletePersistedPodConfig deletes persisted POD configuration from ETCD.
func (s *remoteCNIserver) deletePersistedPodConfig(config *container.Persisted) error {
	// collect keys to be removed from ETCD
	var removedKeys []string

	removedKeys = append(removedKeys, linux_l3.StaticRouteKey(config.PodLinkRouteName),
		linux_l3.StaticRouteKey(config.PodDefaultRouteName),
		linux_l3.StaticArpKey(config.PodARPEntryName))

	// VPP-side configuration
	if !s.disableTCPstack {
		removedKeys = append(removedKeys,
			vpp_intf.InterfaceKey(config.LoopbackName),
			stn.Key(config.StnRuleName),
			vpp_l4.AppNamespacesKey(config.AppNamespaceID))
	} else {
		removedKeys = append(removedKeys,
			vpp_l3.RouteKey(config.VppRouteVrf, config.VppRouteDest, config.VppRouteNextHop))
	}
	removedKeys = append(removedKeys, vpp_l3.ArpEntryKey(config.VppARPEntryInterface, config.VppARPEntryIP))

	// POD interface configuration
	if !s.useTAPInterfaces {
		removedKeys = append(removedKeys,
			linux_intf.InterfaceKey(config.Veth1Name),
			linux_intf.InterfaceKey(config.Veth2Name),
		)
	} else {
		removedKeys = append(removedKeys, linux_intf.InterfaceKey(config.PodTapName))
	}
	removedKeys = append(removedKeys, vpp_intf.InterfaceKey(config.VppIfName))

	_, skip := s.configuredInThisRun[config.ID]

	// remove persisted configuration from ETCD
	err := s.persistChanges(removedKeys, nil, skip)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
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
func (s *remoteCNIserver) generateCniReply(config *PodConfig, nsName string, podIP string) *cni.CNIReply {
	var ifName string
	if s.useTAPInterfaces {
		ifName = config.PodTap.HostIfName
	} else {
		ifName = config.Veth1.HostIfName
	}
	return &cni.CNIReply{
		Result: resultOk,
		Interfaces: []*cni.CNIReply_Interface{
			{
				Name:    ifName,
				Sandbox: nsName,
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

// persistChanges persists the changes passed as input arguments into ETCD.
func (s *remoteCNIserver) persistChanges(removedKeys []string, putChanges map[string]proto.Message, ignoreDel bool) error {
	var err error
	// TODO rollback in case of error

	for _, key := range removedKeys {
		// ignore the next delete event on this key
		if ignoreDel {
			s.proxy.AddIgnoreEntry(key, datasync.Delete)
		}

		// delete the key
		_, err = s.proxy.Delete(key)
		if err != nil {
			return err
		}
	}

	for k, v := range putChanges {
		// ignore the next put event on this key
		s.proxy.AddIgnoreEntry(k, datasync.Put)

		// put the key
		err = s.proxy.Put(k, v)
		if err != nil {
			return err
		}
	}
	return err
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
	s.Lock()
	defer s.Unlock()

	if s.useL2Interconnect {
		return ""
	}

	return s.vxlanBVIIfName
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (s *remoteCNIserver) GetHostInterconnectIfName() string {
	s.Lock()
	defer s.Unlock()

	return s.hostInterconnectIfName
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
