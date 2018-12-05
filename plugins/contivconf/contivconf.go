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

package contivconf

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	govpp "git.fd.io/govpp.git/api"
	"github.com/go-errors/errors"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	intf_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"

	"github.com/apparentlymart/go-cidr/cidr"
	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/ksr"
)

const (
	// socket file where the GRPC STN server listens for client connections by default
	DefaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// by default, NodeConfig CRD is not waited for (can be applied later for smaller
	// changed, such as interface IP address, DHCP option, etc.)
	defaultCRDNodeConfigurationDisabled = true

	// by default, TAP interfaces are used over AF-PACKETs and VETHs
	defaultUseTAPInterfaces = true

	// by default, virtio-based TAP is used to connect pods and the host stack with VPP
	defaultTAPInterfaceVersion = 2

	// by default, TCP checksum offloading is disabled on VETH interfaces
	// (not supported by TAPs).
	defaultTCPChecksumOffloadDisabled = true

	// by default, traffic leaving the node and heading outside the cluster
	// is NATed
	defaultNatExternalTraffic = true

	// by default, IP Neighbor scanning is enabled
	defaultScanIPNeighbors          = true
	defaultIPNeighborScanInterval   = 1
	defaultIPNeighborStaleThreshold = 4

	defaultMainVrfID = 0
	defaultPodVrfID  = 1
)

// ContivConf plugins simplifies the Contiv configuration processing for other
// plugins. Contiv has multiple sources of configuration:
//   - configuration file, further split between the global options and node-specific
//     sections
//   - NodeConfig CRD
//   - STN daemon
//   - implicit values determined on run-time - e.g. use the first interface by name/index
// ContivConf reads all the sources of the configuration and for each option
// determines the right value based on priorities.
type ContivConf struct {
	Deps

	// configuration loaded from the file
	config *Config

	// node-specific configuration defined via CRD, can be nil
	nodeConfigCRD *NodeConfig

	// GoVPP channel used to get the list of DPDK interfaces
	govppCh govpp.Channel

	// list of DPDK interfaces configured on VPP sorted by index
	dpdkIfaces []string

	// STN run-time configuration
	stnInterface   string
	stnIPAddresses []*IPWithNetwork
	stnGW          net.IP
	stnRoutes      []*stn_grpc.STNReply_Route

	// node interface run-time configuration
	useDHCP          bool
	mainInterface    string
	mainInterfaceIPs []*IPWithNetwork
	otherInterfaces  []*OtherInterfaceConfig
	staticGW         net.IP
}

// Deps lists dependencies of the ContivConf plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	GoVPP        govppmux.API

	// The ContivConf plugin can be run either from contiv-init or contiv-agent:
	//  - for contiv-init the plugin requires KV broker factory to reload
	//    NodeConfig CRD during Init (inject ContivInitDeps)
	//  - for contiv-agent the plugin requires access to the event loop provided
	//    by the Controller plugin (inject ContivAgentDeps)
	*ContivInitDeps
	*ContivAgentDeps
}

// ContivAgentDeps lists dependencies of the plugin for use in contiv-agent.
type ContivAgentDeps struct {
	EventLoop controller.EventLoop
}

// ContivInitDeps lists dependencies of the plugin for use in contiv-init.
type ContivInitDeps struct {
	RemoteDB KVBrokerFactory // can be nil
	LocalDB  KVBrokerFactory // can be nil
}

// KVBrokerFactory is used to generalize different means of accessing KV-store
// for the purpose of reading CRD-defined node configuration.
type KVBrokerFactory interface {
	NewBroker(keyPrefix string) keyval.ProtoBroker
}

// Config represents configuration for the Contiv agent.
// The path to the configuration file can be specified in two ways:
//  - using the `-contiv-config=<path to config>` argument, or
//  - using the `CONTIV_CONFIG=<path to config>` environment variable
type Config struct {
	InterfaceConfig
	RoutingConfig
	IPNeighborScanConfig
	IPAMConfig

	StealFirstNIC  bool   `json:"stealFirstNIC"`
	StealInterface string `json:"stealInterface"`
	STNSocketFile  string `json:"stnSocketFile"`

	NatExternalTraffic           bool `json:"natExternalTraffic"`
	EnablePacketTrace            bool `json:"enablePacketTrace"`
	CRDNodeConfigurationDisabled bool `json:"crdNodeConfigurationDisabled"`

	NodeConfig []NodeConfig `json:"nodeConfig"`
}

// NodeConfig represents configuration specific to a given node.
type NodeConfig struct {
	// name of the node, should match with the hostname
	NodeName string `json:"nodeName"`

	// node config specification can be defined either via the configuration file
	// or using CRD
	nodeconfigcrd.NodeConfigSpec
}

// GetNodeConfig returns configuration specific to a given node, or nil if none was found.
func (cfg *Config) getNodeConfig(nodeName string) *NodeConfig {
	for _, nodeConfig := range cfg.NodeConfig {
		if nodeConfig.NodeName == nodeName {
			return &nodeConfig
		}
	}
	return nil
}

// Init does several operations:
//  - loads Contiv configuration file
//  - for contiv-init:
//       * if crdNodeConfigurationDisabled=false, waits for NodeConfig CRD to be available
//       * if stealFirstNIC=true, lists Linux interfaces to obtain the first one
func (c *ContivConf) Init() error {
	// default configuration
	c.config = &Config{
		STNSocketFile:                DefaultSTNSocketFile,
		CRDNodeConfigurationDisabled: defaultCRDNodeConfigurationDisabled,
		InterfaceConfig: InterfaceConfig{
			UseTAPInterfaces:           defaultUseTAPInterfaces,
			TAPInterfaceVersion:        defaultTAPInterfaceVersion,
			TCPChecksumOffloadDisabled: defaultTCPChecksumOffloadDisabled,
		},
		IPNeighborScanConfig: IPNeighborScanConfig{
			ScanIPNeighbors:          defaultScanIPNeighbors,
			IPNeighborScanInterval:   defaultIPNeighborScanInterval,
			IPNeighborStaleThreshold: defaultIPNeighborStaleThreshold,
		},
		RoutingConfig: RoutingConfig{
			MainVRFID: defaultMainVrfID,
			PodVRFID:  defaultPodVrfID,
		},
		NatExternalTraffic: defaultNatExternalTraffic,
	}

	// load configuration from the file
	_, err := c.Cfg.LoadValue(c.config)
	if err != nil {
		return controller.NewFatalError(err)
	}
	c.Log.Infof("Contiv configuration: %+v", *c.config)

	// create GoVPP channel
	c.govppCh, err = c.GoVPP.NewAPIChannel()
	if err != nil {
		return controller.NewFatalError(err)
	}

	if c.ContivInitDeps != nil {
		// in contiv-init the Resync() method is not run, instead everything
		// relevant is loaded here
		if !c.config.CRDNodeConfigurationDisabled {
			// read / wait for NodeConfig CRD
			for c.nodeConfigCRD == nil {
				c.nodeConfigCRD = c.loadNodeConfigFromCRD(c.RemoteDB, c.LocalDB)
				if c.nodeConfigCRD == nil && c.RemoteDB == nil {
					return errors.New("nodeConfig CRD is not available")
				}
				time.Sleep(time.Second)
			}
		}
		// determine the interface to steal
		c.stnInterface = c.config.StealInterface
		nodeConfig := c.getNodeSpecificConfig()
		if nodeConfig != nil && nodeConfig.StealInterface != "" {
			c.stnInterface = nodeConfig.StealInterface
		}
		if c.stnInterface == "" && c.config.StealFirstNIC {
			c.stnInterface = c.getFirstHostInterfaceName()
			if c.stnInterface != "" {
				c.Log.Infof("No specific NIC to steal specified, stealing the first one: %s",
					c.stnInterface)
			}
		}

		// re-load node interface names, IPs, default GW, DHCP option
		c.reloadNodeInterfaces()
	}

	return nil
}

// HandlesEvent selects:
//   - any Resync event
//   - KubeStateChange for CRD node-specific config of this node
func (c *ContivConf) HandlesEvent(event controller.Event) bool {
	myNodeName := c.ServiceLabel.GetAgentLabel()
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

	// unhandled Update event
	return false
}

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (c *ContivConf) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	// re-sync NodeConfig CRD
	c.nodeConfigCRD = nil
	myNodeName := c.ServiceLabel.GetAgentLabel()
	for key, nodeConfig := range kubeStateData[nodeconfig.Keyword] {
		if key == nodeconfig.Key(myNodeName) {
			c.nodeConfigCRD = nodeConfigFromProto(nodeConfig.(*nodeconfig.NodeConfig))
			break
		}
	}
	nodeConfig := c.getNodeSpecificConfig()

	if resyncCount == 1 {
		if c.InSTNMode() {
			// obtain STN configuration from the STN daemon
			c.stnInterface = c.config.StealInterface
			if nodeConfig != nil && nodeConfig.StealInterface != "" {
				c.stnInterface = nodeConfig.StealInterface
			}
			c.stnIPAddresses, c.stnGW, c.stnRoutes, err = c.getSTNConfig(c.stnInterface)
			if err != nil {
				return controller.NewFatalError(err)
			}
		}

		// dump DPDK interfaces configured on VPP
		c.dpdkIfaces, err = c.dumpDPDKInterfaces()
		if err != nil {
			return controller.NewFatalError(err)
		}
	}

	// re-load node interface names, IPs, default GW, DHCP option
	c.reloadNodeInterfaces()
	return nil
}

// Update is called for KubeStateChange for CRD node-specific config of this node.
func (c *ContivConf) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		if ksChange.Resource == nodeconfig.Keyword {
			var nodeConfig *NodeConfig
			if ksChange.NewValue != nil {
				nodeConfig = nodeConfigFromProto(ksChange.NewValue.(*nodeconfig.NodeConfig))
			}
			followUpEv := &NodeConfigChange{nodeConfig: nodeConfig}
			err := c.EventLoop.PushEvent(followUpEv)
			if err != nil {
				return "", err
			}
		}
	}
	return "", nil
}

// Revert is NOOP.
func (c *ContivConf) Revert(event controller.Event) error {
	return nil
}

// InSTNMode returns true if the agent operates in the STN mode
// (node has single interface stolen from the host stack for VPP).
// STN configuration can be obtained via GetSTNConfig().
func (c *ContivConf) InSTNMode() bool {
	nodeConfig := c.getNodeSpecificConfig()
	return c.config.StealFirstNIC || c.config.StealInterface != "" ||
		(nodeConfig != nil && nodeConfig.StealInterface != "")
}

// UseDHCP returns true when the main VPP interface should be configured
// with DHCP instead of static IP addresses.
// With DHCP, GetMainInterfaceStaticIPs() and GetStaticDefaultGW() should
// be ignored.
func (c *ContivConf) UseDHCP() bool {
	return c.useDHCP
}

// EnablePacketTrace returns true if packets flowing through VPP should be
// captured for later inspection.
func (c *ContivConf) EnablePacketTrace() bool {
	return c.config.EnablePacketTrace
}

// GetMainInterfaceName returns the logical name of the VPP physical interface
// to use for connecting the node with the cluster.
func (c *ContivConf) GetMainInterfaceName() string {
	return c.mainInterface
}

// GetMainInterfaceStaticIPs returns the list of IP addresses to assign
// to the main interface. Ignore if DHCP is enabled.
func (c *ContivConf) GetMainInterfaceStaticIPs() []*IPWithNetwork {
	return c.mainInterfaceIPs
}

// GetOtherVPPInterfaces returns configuration to apply for non-main physical
// VPP interfaces.
func (c *ContivConf) GetOtherVPPInterfaces() []*OtherInterfaceConfig {
	return c.otherInterfaces
}

// GetStaticDefaultGW returns the IP address of the default gateway.
// Ignore if DHCP is enabled (in that case it is provided by the DHCP server)
func (c *ContivConf) GetStaticDefaultGW() net.IP {
	return c.staticGW
}

// NatExternalTraffic returns true when it is required to S-NAT traffic
// leaving the node and heading out from the cluster.
func (c *ContivConf) NatExternalTraffic() bool {
	nodeConfig := c.getNodeSpecificConfig()
	return c.config.NatExternalTraffic || (nodeConfig != nil && nodeConfig.NatExternalTraffic)
}

// GetIPAMConfig returns configuration to be used by the IPAM module.
func (c *ContivConf) GetIPAMConfig() *IPAMConfig {
	return &c.config.IPAMConfig
}

// GetInterfaceConfig returns configuration related to VPP interfaces.
func (c *ContivConf) GetInterfaceConfig() *InterfaceConfig {
	return &c.config.InterfaceConfig
}

// GetRoutingConfig returns configuration related to IP routing.
func (c *ContivConf) GetRoutingConfig() *RoutingConfig {
	return &c.config.RoutingConfig
}

// GetIPNeighborScanConfig returns configuration related to IP Neighbor
// scanning.
func (c *ContivConf) GetIPNeighborScanConfig() *IPNeighborScanConfig {
	return &c.config.IPNeighborScanConfig
}

// GetSTNConfig returns configuration related to STN feature.
// Use the method only in the STN mode - i.e. when InSTNMode() returns true.
func (c *ContivConf) GetSTNConfig() *STNConfig {
	return &STNConfig{
		StealInterface: c.stnInterface,
		STNSocketFile:  c.config.STNSocketFile,
		STNRoutes:      c.stnRoutes,
	}
}

// Close is NOOP.
func (c *ContivConf) Close() error {
	return nil
}

// reloadNodeInterfaces re-loads node interface names, IPs, default GW, DHCP option.
func (c *ContivConf) reloadNodeInterfaces() {
	nodeConfig := c.getNodeSpecificConfig()

	// DHCP
	c.useDHCP = false
	if nodeConfig == nil || nodeConfig.MainVPPInterface.IP == "" {
		if c.config.NodeInterconnectDHCP ||
			(nodeConfig != nil && nodeConfig.MainVPPInterface.UseDHCP) {
			c.useDHCP = true
		}
	}

	// main interface
	c.mainInterface = ""
	if nodeConfig != nil {
		c.mainInterface = nodeConfig.MainVPPInterface.InterfaceName
	}
	if c.mainInterface == "" {
		// name not specified in the config, use heuristic - select first DPDK interface
		// (first by index)
		for _, dpdkIface := range c.dpdkIfaces {
			// exclude "other" (non-main) NICs
			var isOther bool
			if nodeConfig != nil {
				for _, otherNIC := range nodeConfig.OtherVPPInterfaces {
					if otherNIC.InterfaceName == dpdkIface {
						isOther = true
						break
					}
				}
			}
			if isOther {
				continue
			}

			// we have the main NIC
			c.mainInterface = dpdkIface
			c.Log.Debugf("Physical NIC not taken from NodeConfig, but heuristic was used: %v ",
				c.mainInterface)
			break
		}
	}

	// main interface static IPs (FIXME: static is not good name, it is not calculated by IPAM)
	// TODO

	// other interfaces
	// TODO

	// static default GW
	// TODO
}

// getNodeSpecificConfig returns configuration specific to this node, prioritizing
// CRD over the configuration file.
func (c *ContivConf) getNodeSpecificConfig() *NodeConfig {
	if c.nodeConfigCRD != nil {
		return c.nodeConfigCRD
	}
	return c.config.getNodeConfig(c.ServiceLabel.GetAgentLabel())
}

// loadNodeConfigFromCRD loads node configuration defined via CRD, which was reflected
// into a remote kv-store by contiv-crd and mirrored into local kv-store by the agent.
func (c *ContivConf) loadNodeConfigFromCRD(remoteDB, localDB KVBrokerFactory) *NodeConfig {
	var (
		nodeConfigProto *nodeconfig.NodeConfig
		err             error
	)
	// try remote kv-store first
	if remoteDB != nil {
		nodeConfigProto, err = c.loadNodeConfigFromKVStore(remoteDB)
		if err != nil {
			c.Log.WithField("err", err).Warn("Failed to read node configuration from remote KV-store")
		}
	}

	if (remoteDB == nil || err != nil) && localDB != nil {
		// try the local mirror of the kv-store
		nodeConfigProto, err = c.loadNodeConfigFromKVStore(localDB)
		if err != nil {
			c.Log.WithField("err", err).Warn("Failed to read node configuration from local KV-store")
		}
	}

	if nodeConfigProto == nil {
		c.Log.Debug("Node configuration is not provided via CRD")
		return nil
	}

	nodeConfig := nodeConfigFromProto(nodeConfigProto)
	c.Log.Debug("Node configuration loaded from CRD: %v", nodeConfig)
	return nodeConfig
}

// loadNodeConfigFromKVStore loads node configuration defined via CRD and mirrored into a given KV-store.
func (c *ContivConf) loadNodeConfigFromKVStore(db KVBrokerFactory) (*nodeconfig.NodeConfig, error) {
	nodeName := c.ServiceLabel.GetAgentLabel()
	kvBroker := db.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
	nodeConfigProto := &nodeconfig.NodeConfig{}
	found, _, err := kvBroker.GetValue(nodeconfig.Key(nodeName), nodeConfigProto)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return nodeConfigProto, nil
}

// getFirstHostInterfaceName returns the name of the first non-virtual interface
// in the host stack.
func (c *ContivConf) getFirstHostInterfaceName() string {
	// list existing links
	links, err := netlink.LinkList()
	if err != nil {
		c.Log.Error("Unable to list links:", err)
		return ""
	}

	// find link to steal
	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") &&
			!strings.HasPrefix(l.Attrs().Name, "vir") &&
			!strings.HasPrefix(l.Attrs().Name, "docker") {
			return l.Attrs().Name
		}
	}
	return ""
}

// dumpDPDKInterfaces dumps DPDK interfaces configured on VPP.
func (c *ContivConf) dumpDPDKInterfaces() (ifaces []string, err error) {
	ifHandler := intf_vppcalls.NewIfVppHandler(c.govppCh, c.Log)

	dump, err := ifHandler.DumpInterfacesByType(interfaces.Interface_DPDK)
	if err != nil {
		return ifaces, err
	}

	// sort by sw_if_index
	var swIfIdxs []int
	for swIfIdx := range dump {
		swIfIdxs = append(swIfIdxs, int(swIfIdx))
	}
	sort.Ints(swIfIdxs)
	for _, swIfIdx := range swIfIdxs {
		iface := dump[uint32(swIfIdx)]
		ifaces = append(ifaces, iface.Interface.Name)
	}
	return ifaces, nil
}

// getSTNConfig returns IP addresses and routes associated with the main
// interface before it was stolen from the host stack.
func (c *ContivConf) getSTNConfig(ifName string) (ipNets []*IPWithNetwork, gw net.IP, routes []*stn_grpc.STNReply_Route, err error) {
	if ifName == "" {
		c.Log.Debug("Getting STN info for the first stolen interface")
	} else {
		c.Log.Debugf("Getting STN info for interface %s", ifName)
	}

	// request info about the stolen interface
	reply, err := c.requestSTNInfo(ifName)
	if err != nil {
		c.Log.Errorf("Error by executing STN GRPC: %v", err)
		return
	}
	c.Log.Debugf("STN GRPC reply: %v", reply)

	// parse STN IP addresses
	for _, address := range reply.IpAddresses {
		ipNet := &IPWithNetwork{}
		ipNet.Address, ipNet.Network, err = net.ParseCIDR(address)
		if err != nil {
			c.Log.Errorf("Failed to parse IP address returned by STN GRPC: %v", err)
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

// requestSTNInfo sends request to the STN daemon to obtain information about a stolen interface.
func (c *ContivConf) requestSTNInfo(ifName string) (reply *stn_grpc.STNReply, err error) {
	// connect to STN GRPC server
	if c.config.STNSocketFile == "" {
		c.config.STNSocketFile = c.config.STNSocketFile
	}
	conn, err := grpc.Dial(
		c.config.STNSocketFile,
		grpc.WithInsecure(),
		grpc.WithDialer(
			func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
	)
	if err != nil {
		c.Log.Errorf("Unable to connect to STN GRPC: %v", err)
		return
	}
	defer conn.Close()
	client := stn_grpc.NewSTNClient(conn)

	// request info about the stolen interface
	return client.StolenInterfaceInfo(context.Background(), &stn_grpc.STNRequest{
		InterfaceName: ifName,
	})
}

// nodeConfigFromProto converts node configuration from protobuf to an instance of NodeConfig structure.
func nodeConfigFromProto(nodeConfigProto *nodeconfig.NodeConfig) (nodeConfig *NodeConfig) {
	nodeConfig = &NodeConfig{
		NodeName: nodeConfigProto.NodeName,
		NodeConfigSpec: nodeconfigcrd.NodeConfigSpec{
			StealInterface:     nodeConfigProto.StealInterface,
			Gateway:            nodeConfigProto.Gateway,
			NatExternalTraffic: nodeConfigProto.NatExternalTraffic,
		},
	}
	if nodeConfigProto.MainVppInterface != nil {
		nodeConfig.MainVPPInterface = nodeconfigcrd.InterfaceConfig{
			InterfaceName: nodeConfigProto.MainVppInterface.InterfaceName,
			IP:            nodeConfigProto.MainVppInterface.Ip,
			UseDHCP:       nodeConfigProto.MainVppInterface.UseDhcp,
		}
	}
	for _, otherVPPInterface := range nodeConfigProto.OtherVppInterfaces {
		nodeConfig.OtherVPPInterfaces = append(nodeConfig.OtherVPPInterfaces,
			nodeconfigcrd.InterfaceConfig{
				InterfaceName: otherVPPInterface.InterfaceName,
				IP:            otherVPPInterface.Ip,
				UseDHCP:       otherVPPInterface.UseDhcp,
			})
	}
	return nodeConfig
}
