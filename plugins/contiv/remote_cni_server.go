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

//go:generate binapi-generator --input-file=/usr/share/vpp/api/dhcp.api.json --output-dir=bin_api

package contiv

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"git.fd.io/govpp.git/api"
	govppapi "git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"
	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/bin_api/dhcp"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l4"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/stn"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/l3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
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
	tapHostEndName                = "vpp1"
	tapVPPEndLogicalName          = "tap-vpp2"
	tapVPPEndName                 = "vpp2"
	podIfIPPrefix                 = "10.2.1"
)

// remoteCNIserver represents the remote CNI server instance. It accepts the requests from the contiv-CNI
// (acting as a GRPC-client) and configures the networking between VPP and the PODs.
type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	// VPP local client transaction factory
	vppTxnFactory func() linux.DataChangeDSL

	// kvdbsync plugin with ability to filter the change events
	proxy kvdbproxy.Proxy

	// GoVPP channel for direct binary API calls (if needed)
	govppChan *api.Channel

	// VPP interface index map
	swIfIndex ifaceidx.SwIfIndex

	// map of configured containers
	configuredContainers *containeridx.ConfigIndex

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// counter of connected containers. It is used for generating afpacket names and assigned IP addresses.
	// TODO: do not rely on counter, since it can overflow uint8 after many container add/remove transactions
	counter int

	// set to true when running unit tests
	test bool

	// agent microservice label
	agentLabel string

	// unique identifier of the node
	nodeID uint8

	// this node's main IP address
	nodeIP string

	// nodeIPsubsribers is a slice of channels that are notified when nodeIP is changed
	nodeIPsubscribers []chan string

	// node specific configuration
	nodeConfig *OneNodeConfig

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

	// name of physical interfaces configured by the agent
	physicalIfs []string

	// name of the interface interconnecting VPP with the host stack
	hostInterconnectIfName string

	// the name of an BVI interface facing towards VXLAN tunnels to other hosts
	vxlanBVIIfName string

	stnIP string
	stnGw string

	dhcpNotif chan govppapi.Message

	ctx           context.Context
	ctxCancelFunc context.CancelFunc
}

// vswitchConfig holds base vSwitch VPP configuration.
type vswitchConfig struct {
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
	l4Features       *vpp_l4.L4Features

	vxlanBVI *vpp_intf.Interfaces_Interface
	vxlanBD  *vpp_l2.BridgeDomains_BridgeDomain
}

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linux.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govppChan *api.Channel, index ifaceidx.SwIfIndex, agentLabel string,
	config *Config, nodeConfig *OneNodeConfig, nodeID uint8) (*remoteCNIserver, error) {
	ipam, err := ipam.New(logger, nodeID, &config.IPAMConfig)
	if err != nil {
		return nil, err
	}

	server := &remoteCNIserver{
		Logger:                     logger,
		vppTxnFactory:              vppTxnFactory,
		proxy:                      proxy,
		configuredContainers:       configuredContainers,
		govppChan:                  govppChan,
		swIfIndex:                  index,
		agentLabel:                 agentLabel,
		nodeID:                     nodeID,
		ipam:                       ipam,
		nodeConfig:                 nodeConfig,
		tcpChecksumOffloadDisabled: config.TCPChecksumOffloadDisabled,
		useTAPInterfaces:           config.UseTAPInterfaces,
		tapVersion:                 config.TAPInterfaceVersion,
		tapV2RxRingSize:            config.TAPv2RxRingSize,
		tapV2TxRingSize:            config.TAPv2TxRingSize,
		disableTCPstack:            config.TCPstackDisabled,
		useL2Interconnect:          config.UseL2Interconnect,
	}
	server.vswitchCond = sync.NewCond(&server.Mutex)
	server.ctx, server.ctxCancelFunc = context.WithCancel(context.Background())
	server.dhcpNotif = make(chan govppapi.Message, 1)
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
	return s.configureContainerConnectivity(request)
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

	// only apply the config if resync hasn't done it already
	if _, _, found := s.swIfIndex.LookupIdx(s.interconnectAfpacketName()); found {
		s.Logger.Info("VSwitch connectivity is considered configured, skipping...")
		s.vswitchConnectivityConfigured = true
		s.vswitchCond.Broadcast()
		return nil
	}

	// prepare empty vswitch config struct to be filled in
	config := &vswitchConfig{nics: []*vpp_intf.Interfaces_Interface{}}

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
				strings.HasPrefix(name, "host") || strings.HasPrefix(name, "tap") {
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

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(config *vswitchConfig, nicName string, nicIP string, useDHCP bool) error {
	var err error
	txn1 := s.vppTxnFactory().Put()

	useSTN := false
	if s.nodeConfig != nil && s.nodeConfig.StealInterface != "" {
		useSTN = true
		s.Logger.Infof("STN of the host interface %s requested.", s.nodeConfig.StealInterface)

		// get IP address of the STN interface
		var gwIP string
		nicIP, gwIP, err = s.getSTNInterfaceIP(s.nodeConfig.StealInterface)
		if err != nil {
			s.Logger.Warnf("Unable to get STN interface info: %v, skipping STN config", err)
		}

		if nicIP != "" {
			s.Logger.Infof("STN-configured interface %s (IP %s, GW %s), skip main interface config.", nicName, nicIP, gwIP)
			s.stnIP = nicIP
			s.stnGw = gwIP
		} else {
			s.Logger.Infof("STN-configured interface %s, but there is no IP, continue with main interface config.", nicName)
			useSTN = false
		}
	}

	// determine main node IP address
	if useDHCP {
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

	if !useSTN {
		if nicName != "" {
			// configure the physical NIC
			s.Logger.Info("Configuring physical NIC ", nicName)

			nic := s.physicalInterface(nicName, s.nodeIP)
			if useDHCP {
				// clear IP addresses
				nic.IpAddresses = []string{}
			}
			txn1.VppInterface(nic)
			config.nics = append(config.nics, nic)
			s.physicalIfs = append(s.physicalIfs, nicName)
		} else {
			// configure loopback instead of the physical NIC
			s.Logger.Debug("Physical NIC not found, configuring loopback instead.")

			loop := s.physicalInterfaceLoopback(s.nodeIP)
			txn1.VppInterface(loop)
			config.nics = append(config.nics, loop)
		}

		if nicName != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
			// configure the default gateway
			config.defaultRoute = s.defaultRoute(s.nodeConfig.Gateway, nicName)
			txn1.StaticRoute(config.defaultRoute)
		}

		// execute the config transaction
		err = txn1.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	if useDHCP {
		err = s.configureDHCP(nicName)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// getSTNInterfaceIP returns IP address of the interface before stealing it from the host stack.
func (s *remoteCNIserver) getSTNInterfaceIP(ifName string) (ip string, gw string, err error) {
	s.Logger.Debugf("Getting STN info for interface %s", ifName)

	// connect to STN GRPC server
	conn, err := grpc.Dial(fmt.Sprintf(":%d", 50051), grpc.WithInsecure()) // TODO configurable server port
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
		if strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			gw = r.NextHopIp
		}
	}
	if gw == "" {
		// no deafult gateway in routes, calculate fake gateway address for route pointing to VPP
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

// configureDHCP configures DHCP on an interface on VPP
func (s *remoteCNIserver) configureDHCP(nicName string) error {

	_, err := s.govppChan.SubscribeNotification(s.dhcpNotif, dhcp.NewDhcpComplEvent)
	if err != nil {
		return err
	}

	idx, _, found := s.swIfIndex.LookupIdx(nicName)

	if found {
		req := &dhcp.DhcpClientConfig{}
		req.SwIfIndex = idx
		req.IsAdd = 1
		req.WantDhcpEvent = 1

		reply := &dhcp.DhcpClientConfigReply{}
		err = s.govppChan.SendRequest(req).ReceiveReply(reply)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("DHCP interfaces not found")
	}

	go s.handleDHCPNotifications(s.dhcpNotif)
	return nil
}

// handleDHCPNotifications handles DHCP state change notifications
func (s *remoteCNIserver) handleDHCPNotifications(notifCh chan govppapi.Message) {

	for {
		select {
		case msg := <-notifCh:
			switch notif := msg.(type) {
			case *dhcp.DhcpComplEvent:
				var ipAddr string
				if notif.IsIpv6 == 1 {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(notif.HostAddress).To16().String(), notif.MaskWidth)
				} else {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(notif.HostAddress[:4]).To4().String(), notif.MaskWidth)
				}
				s.Lock()
				if s.nodeIP != "" && s.nodeIP != ipAddr {
					s.Logger.Error("Update of Node IP address is not supported")
				}
				s.vswitchConnectivityConfigured = true
				s.vswitchCond.Broadcast()
				s.setNodeIP(ipAddr)
				s.Unlock()

				s.Logger.Info("DHCP event", *notif)
			}
		case <-s.ctx.Done():
			return
		}
	}

}

// configureOtherVPPInterfaces other interfaces that were configured in contiv plugin YAML configuration.
func (s *remoteCNIserver) configureOtherVPPInterfaces(config *vswitchConfig, nodeConfig *OneNodeConfig) error {

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
			s.physicalIfs = append(s.physicalIfs, intf.Name)
		}

		// execute the config transaction
		err := txn.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(config *vswitchConfig) error {

	if s.stnIP == "" {
		// execute only if STN has not already configured this
		txn1 := s.vppTxnFactory().Put()

		if s.useTAPInterfaces {
			// TAP interface
			config.tapVpp = s.interconnectTap()

			s.hostInterconnectIfName = config.tapVpp.Name

			txn1.VppInterface(config.tapVpp)
		} else {
			// veth + AF_PACKET
			config.vethHost = s.interconnectVethHost()
			config.vethVpp = s.interconnectVethVpp()
			config.interconnectAF = s.interconnectAfpacket()

			s.hostInterconnectIfName = config.interconnectAF.Name

			txn1.LinuxInterface(config.vethHost).
				LinuxInterface(config.vethVpp)
		}

		// execute the config transaction
		err := txn1.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}

		// finish TAP configuration
		if s.useTAPInterfaces {
			config.tapHost = s.interconnectTapHost()
			err = s.vppTxnFactory().Put().LinuxInterface(config.tapHost).Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		} else {
			// AFPacket is intentionally configured in a txn different from the one that configures veth.
			// Otherwise if the veth exists before the first transaction (i.e. vEth pair was not deleted after last run)
			// configuring AfPacket might return an error since linux plugin deletes the existing veth and creates a new one.
			err = s.vppTxnFactory().Put().VppInterface(config.interconnectAF).Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		}
	} else {
		if s.useTAPInterfaces {
			s.hostInterconnectIfName = tapVPPEndLogicalName
		} else {
			s.hostInterconnectIfName = s.interconnectAfpacketName()
		}
	}

	txn2 := s.vppTxnFactory().Put()

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
		txn2.StaticRoute(r)
	}

	// configure the route from the host to PODs
	if s.stnGw == "" {
		config.routeFromHost = s.routePODsFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		config.routeFromHost = s.routePODsFromHost(s.stnGw)
	}
	txn2.LinuxRoute(config.routeFromHost)

	// route from the host to k8s service range from the host
	if s.stnGw == "" {
		config.routeForServices = s.routeServicesFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		config.routeForServices = s.routeServicesFromHost(s.stnGw)
	}
	txn2.LinuxRoute(config.routeForServices)

	// enable L4 features
	config.l4Features = s.l4Features(!s.disableTCPstack)
	txn2.L4Features(config.l4Features)

	// execute the config transaction
	err := txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
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
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// persistVswitchConfig persits vswitch configuration in ETCD
func (s *remoteCNIserver) persistVswitchConfig(config *vswitchConfig) error {
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
		changes[vpp_l2.BridgeDomainKey(config.vxlanBD.Name)] = config.vxlanBD
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
	changes[vpp_l4.FeatureKey()] = config.l4Features

	// persist the changes in ETCD
	err = s.persistChanges(nil, changes)
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
func (s *remoteCNIserver) configureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {

	// do not connect any containers until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	// increment request counter
	s.counter++

	// prepare config details struct
	extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
	config := &containeridx.Config{
		PodName:      extraArgs[podNameExtraArg],
		PodNamespace: extraArgs[podNamespaceExtraArg],
	}

	// assign an IP address for this POD
	podIP, err := s.ipam.NextPodIP(request.NetworkNamespace)
	if err != nil {
		return nil, fmt.Errorf("Can't get new IP address for pod: %v", err)
	}
	podIPCIDR := podIP.String() + "/32"

	// TODO: merge transactions into one once linuxplugin supports TAPs and all race-conditions are fixed.

	// configure POD interface
	err = s.configurePodInterface(request, podIP, config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// configure POD-related config on on VPP
	err = s.configurePodVPPSide(request, podIP, config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// persist POD configuration in ETCD
	err = s.persistPodConfig(config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// store configuration internally for other plugins in the internal map
	if s.configuredContainers != nil {
		s.configuredContainers.RegisterContainer(request.ContainerId, config)
	}

	// prepare and send reply for the CNI request
	reply := s.generateCniReply(config, request.NetworkNamespace, podIPCIDR)
	return reply, err
}

// unconfigureContainerConnectivity disconnects the POD from vSwitch VPP.
func (s *remoteCNIserver) unconfigureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
	var err error

	// do not try to disconnect any containers until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	// configuredContainers should not be nil unless this is a unit test
	if s.configuredContainers == nil {
		err = fmt.Errorf("configuration was not stored for container: %s", request.ContainerId)
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// load container config
	config, found := s.configuredContainers.LookupContainer(request.ContainerId)
	if !found {
		s.Logger.Warnf("cannot find configuration for container: %s\n", request.ContainerId)
		reply := s.generateCniEmptyOKReply()
		return reply, nil
	}

	// delete POD-related config on VPP
	err = s.unconfigurePodVPPSide(config)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// configure POD interface
	err = s.unconfigurePodInterface(request, config)
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
		s.configuredContainers.UnregisterContainer(request.ContainerId)
	}

	// release IP address of the POD
	err = s.ipam.ReleasePodIP(request.NetworkNamespace)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// prepare and send reply for the CNI request
	reply := s.generateCniEmptyOKReply()
	return reply, nil
}

// configurePodInterface configures POD's network interface and its routes + ARPs.
func (s *remoteCNIserver) configurePodInterface(request *cni.CNIRequest, podIP net.IP, config *containeridx.Config) error {

	podIPCIDR := podIP.String() + "/32"
	podIPNet := &net.IPNet{
		IP:   podIP,
		Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
	}

	// prepare the config transaction 1
	txn1 := s.vppTxnFactory().Put()

	podIfName := ""

	// create VPP to POD interconnect interface
	if s.useTAPInterfaces {
		// TAP interface
		config.VppIf = s.tapFromRequest(request, !s.disableTCPstack, podIPCIDR)

		txn1.VppInterface(config.VppIf)
	} else {
		// veth pair + AF_PACKET
		config.Veth1 = s.veth1FromRequest(request, podIPCIDR)
		config.Veth2 = s.veth2FromRequest(request)
		config.VppIf = s.afpacketFromRequest(request, !s.disableTCPstack, podIPCIDR)

		txn1.LinuxInterface(config.Veth1).
			LinuxInterface(config.Veth2).
			VppInterface(config.VppIf)
		podIfName = config.Veth1.Name
	}

	if !s.useTAPInterfaces {
		// TODO: temporary bypass this section for TAP interfaces, configured in configureHostTAP

		// link scope route - must be added before the default route
		config.PodLinkRoute = s.podLinkRouteFromRequest(request, podIfName)
		txn1.LinuxRoute(config.PodLinkRoute)

		// ARP to VPP
		config.PodARPEntry = s.podArpEntry(request, podIfName, config.VppIf.PhysAddress)
		txn1.LinuxArpEntry(config.PodARPEntry)
	}

	// execute the config transaction
	err := txn1.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// finish the TAP interface configuration (rename, move to proper namespace, etc.)
	if s.useTAPInterfaces {
		err = s.configureHostTAP(request, podIPNet, config.VppIf.PhysAddress)
		// TODO: not stored in config, this will not be resynced in case of resync!!!
		if err != nil {
			s.Logger.Error(err)
			if !s.test {
				// skip error by tests
				return err
			}
		}
	}

	if !s.useTAPInterfaces {
		// TODO: temporary bypass this section for TAP interfaces, configured in configureHostTAP

		// prepare the config transaction 2
		// the default route needs to be configured after the first transaction,
		// since it depends on the link-local route in the transaction 1
		txn2 := s.vppTxnFactory().Put()

		// Add default route for the container
		config.PodDefaultRoute = s.podDefaultRouteFromRequest(request, podIfName)
		txn2.LinuxRoute(config.PodDefaultRoute)

		// execute the config transaction
		err = txn2.Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// unconfigurePodInterface unconfigures POD's network interface and its routes + ARPs.
func (s *remoteCNIserver) unconfigurePodInterface(request *cni.CNIRequest, config *containeridx.Config) error {

	// prepare the config transaction
	txn2 := s.vppTxnFactory().Delete()

	// delete VPP to POD interconnect interface
	txn2.VppInterface(config.VppIf.Name)
	if !s.useTAPInterfaces {
		txn2.LinuxInterface(config.Veth1.Name).
			LinuxInterface(config.Veth2.Name)
	}

	if !s.useTAPInterfaces && !s.test {
		// TODO: temporary bypass this section for TAP interfaces

		// delete static routes
		txn2.LinuxRoute(config.PodLinkRoute.Name).
			LinuxRoute(config.PodDefaultRoute.Name)

		// delete the ARP entry
		txn2.LinuxArpEntry(config.PodARPEntry.Name)
	}

	// execute the config transaction
	err := txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// delete the TAP interface from the host stack
	if s.useTAPInterfaces {
		err = s.unconfigureHostTAP(request)
		// TODO: not stored in config, this will not be resynced in case of resync!!!
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// configurePodVPPSide configures vswitch VPP part of the POD networking.
func (s *remoteCNIserver) configurePodVPPSide(request *cni.CNIRequest, podIP net.IP, config *containeridx.Config) error {
	podIPCIDR := podIP.String() + "/32"

	// prepare the config transaction
	txn := s.vppTxnFactory().Put()

	if !s.disableTCPstack {
		// VPP TCP stack config
		config.Loopback = s.loopbackFromRequest(request, podIP.String())
		config.AppNamespace = s.appNamespaceFromRequest(request)
		config.StnRule = s.stnRule(podIP, config.VppIf.Name)

		txn.VppInterface(config.Loopback).
			AppNamespace(config.AppNamespace).
			StnRule(config.StnRule)
	} else {
		// route to PodIP via AF_PACKET / TAP
		config.VppRoute = s.vppRouteFromRequest(request, podIPCIDR)

		txn.StaticRoute(config.VppRoute)
	}

	// ARP entry for POD IP
	config.VppARPEntry = s.vppArpEntry(config.VppIf.Name, podIP, s.hwAddrForContainer())
	txn.Arp(config.VppARPEntry)

	// execute the config transaction
	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// if requested, disable TCP checksum offload on the eth0 veth/TAP interface in the container.
	if s.tcpChecksumOffloadDisabled {
		err = s.disableTCPChecksumOffload(request)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// unconfigurePodVPPSide deletes vswitch VPP part of the POD networking.
func (s *remoteCNIserver) unconfigurePodVPPSide(config *containeridx.Config) error {

	// prepare the config transaction
	txn := s.vppTxnFactory().Delete()

	if !s.disableTCPstack {
		// VPP TCP stack config
		txn.VppInterface(config.Loopback.Name).
			AppNamespace(config.AppNamespace.NamespaceId).
			StnRule(config.StnRule.RuleName)
	} else {
		// route to PodIP via AF_PACKET / TAP
		txn.StaticRoute(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr)
	}

	// ARP entry for POD IP
	txn.Arp(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress)

	// execute the config transaction
	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// deletePersistedPodConfig persists POD configuration into ETCD.
func (s *remoteCNIserver) persistPodConfig(config *containeridx.Config) error {
	var err error
	changes := map[string]proto.Message{}

	// POD interface configuration
	changes[vpp_intf.InterfaceKey(config.VppIf.Name)] = config.VppIf
	if !s.useTAPInterfaces {
		changes[linux_intf.InterfaceKey(config.Veth1.Name)] = config.Veth1
		changes[linux_intf.InterfaceKey(config.Veth2.Name)] = config.Veth2

		//FIXME: the following items should be persisted once arp and routes can be configured with TAPs
		changes[linux_l3.StaticRouteKey(config.PodLinkRoute.Name)] = config.PodLinkRoute
		changes[linux_l3.StaticRouteKey(config.PodDefaultRoute.Name)] = config.PodDefaultRoute
		changes[linux_l3.StaticArpKey(config.PodARPEntry.Name)] = config.PodARPEntry
	}

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
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
}

// deletePersistedPodConfig deletes persisted POD configuration from ETCD.
func (s *remoteCNIserver) deletePersistedPodConfig(config *containeridx.Config) error {
	// collect keys to be removed from ETCD
	var removedKeys []string

	// POD interface configuration
	removedKeys = append(removedKeys, vpp_intf.InterfaceKey(config.VppIf.Name))
	if !s.useTAPInterfaces {
		removedKeys = append(removedKeys,
			linux_intf.InterfaceKey(config.Veth1.Name),
			linux_intf.InterfaceKey(config.Veth2.Name),
			//FIXME: the following items should be deleted once arp and routes can be configured with TAPs
			linux_l3.StaticRouteKey(config.PodLinkRoute.Name),
			linux_l3.StaticRouteKey(config.PodDefaultRoute.Name),
			linux_l3.StaticArpKey(config.PodARPEntry.Name),
		)
	}

	// VPP-side configuration
	if !s.disableTCPstack {
		removedKeys = append(removedKeys,
			vpp_intf.InterfaceKey(config.Loopback.Name),
			stn.Key(config.StnRule.RuleName),
			vpp_l4.AppNamespacesKey(config.AppNamespace.NamespaceId))
	} else {
		removedKeys = append(removedKeys,
			vpp_l3.RouteKey(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr))
	}
	removedKeys = append(removedKeys, vpp_l3.ArpEntryKey(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress))

	// remove persisted configuration from ETCD
	err := s.persistChanges(removedKeys, nil)
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
func (s *remoteCNIserver) generateCniReply(config *containeridx.Config, nsName string, podIP string) *cni.CNIReply {
	return &cni.CNIReply{
		Result: resultOk,
		Interfaces: []*cni.CNIReply_Interface{
			{
				Name:    config.VppIf.Name,
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

// generateCniEmptyOKReply generates CNI reply with OK result code and ampty body.
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
func (s *remoteCNIserver) persistChanges(removedKeys []string, putChanges map[string]proto.Message) error {
	var err error
	// TODO rollback in case of error

	for _, key := range removedKeys {
		// ignore the next delete event on this key
		s.proxy.AddIgnoreEntry(key, datasync.Delete)

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

// GetPhysicalIfNames returns a slice of names of all configured physical interfaces.
func (s *remoteCNIserver) GetPhysicalIfNames() []string {
	s.Lock()
	defer s.Unlock()

	return s.physicalIfs
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
func (s *remoteCNIserver) GetNodeIP() net.IP {
	s.Lock()
	defer s.Unlock()

	if s.nodeIP == "" {
		return nil
	}

	nodeIP, _, err := net.ParseCIDR(s.nodeIP)
	if err != nil {
		return nil
	}

	return nodeIP
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (s *remoteCNIserver) WatchNodeIP(subscriber chan string) {
	s.Lock()
	defer s.Unlock()

	s.nodeIPsubscribers = append(s.nodeIPsubscribers, subscriber)
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
