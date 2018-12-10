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

package contivconf

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	govpp "git.fd.io/govpp.git/api"
	"github.com/ghodss/yaml"
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
	// defaultSTNSocketFile is a path to the socket file where the GRPC STN server
	// listens for client connections by default
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// by default, NodeConfig CRD is disabled (and ignored if applied)
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

	// default IPAM configuration
	defaultServiceCIDR                   = "10.96.0.0/12"
	defaultPodSubnetCIDR                 = "10.1.0.0/16"
	defaultPodSubnetOneNodePrefixLen     = 24
	defaultPodVPPSubnetCIDR              = "10.2.1.0/24"
	defaultVPPHostSubnetCIDR             = "172.30.0.0/16"
	defaultVPPHostSubnetOneNodePrefixLen = 24
	defaultVxlanCIDR                     = "192.168.30.0/24"
	// NodeInterconnectCIDR & ContivCIDR can be empty

	// default VRF IDs
	defaultMainVrfID = 0
	defaultPodVrfID  = 1

	// UTs
	defaultFirstHostInterfaceForUTs = "eth0"

	// vmxnet3
	vmxnet3KernelDriver    = "vmxnet3"  // name of the kernel driver for vmxnet3 interfaces
	vmxnet3InterfacePrefix = "vmxnet3-" // prefix matching all vmxnet3 interfaces on VPP
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
	config     *Config
	ipamConfig *IPAMConfig // IPAM subnets parsed to net.IPNet

	// node-specific configuration defined via CRD, can be nil
	nodeConfigCRD *NodeConfig

	// GoVPP channel used to get the list of DPDK interfaces
	govppCh govpp.Channel

	// list of DPDK interfaces configured on VPP sorted by index
	dpdkIfaces []string

	// STN run-time configuration
	stnInterface    string
	stnIPAddresses  IPsWithNetworks
	stnGW           net.IP
	stnRoutes       []*stn_grpc.STNReply_Route
	stnKernelDriver string
	stnPCIAddress   string

	// node interface run-time configuration
	useDHCP          bool
	mainInterface    string
	mainInterfaceIPs IPsWithNetworks
	otherInterfaces  OtherInterfaces
	defaultGw        net.IP

	// callbacks that can be replaced with mocks for unit testing in UnitTestDeps.
	dumpDPDKInterfacesClb        DumpDPDKInterfacesClb
	requestSTNInfoClb            RequestSTNInfoClb
	getFirstHostInterfaceNameClb GetFirstHostInterfaceNameClb
}

// Deps lists dependencies of the ContivConf plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI

	// GoVPP is not needed for contiv-init but as a plugin it has to be here
	// to be initialized first
	GoVPP govppmux.API

	// The ContivConf plugin can be run either from contiv-init or contiv-agent:
	//  - for contiv-init the plugin requires KV broker factory to reload
	//    NodeConfig CRD during Init (inject ContivInitDeps)
	//  - for contiv-agent the plugin requires access to the event loop provided
	//    by the Controller plugin (inject ContivAgentDeps)
	*ContivInitDeps
	*ContivAgentDeps

	// Dependencies to be injected for unit testing to replace any external access
	// with mocks
	*UnitTestDeps
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

// UnitTestDeps lists dependencies for unit testing.
type UnitTestDeps struct {
	Config                       *Config
	DumpDPDKInterfacesClb        DumpDPDKInterfacesClb
	RequestSTNInfoClb            RequestSTNInfoClb
	GetFirstHostInterfaceNameClb GetFirstHostInterfaceNameClb
}

// DumpDPDKInterfacesClb is callback for dumping DPDK interfaces configured on VPP.
type DumpDPDKInterfacesClb func() (ifaces []string, err error)

// RequestSTNInfoClb is callback for sending request to the STN daemon to obtain information
// about a stolen interface.
type RequestSTNInfoClb func(ifName string) (reply *stn_grpc.STNReply, err error)

// GetFirstHostInterfaceNameClb is callback for retrieving the name of the first
// non-virtual interface in the host stack.
type GetFirstHostInterfaceNameClb func() string

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

	StealFirstNIC  bool   `json:"stealFirstNIC,omitempty"`
	StealInterface string `json:"stealInterface,omitempty"`
	STNSocketFile  string `json:"stnSocketFile,omitempty"`

	NatExternalTraffic           bool `json:"natExternalTraffic,omitempty"`
	EnablePacketTrace            bool `json:"enablePacketTrace,omitempty"`
	CRDNodeConfigurationDisabled bool `json:"crdNodeConfigurationDisabled,omitempty"`

	IPAMConfig IPAMConfigForJSON `json:"ipamConfig"`
	NodeConfig []NodeConfig      `json:"nodeConfig"`
}

// IPAMConfigForJSON groups IPAM configuration options as basic data types and with
// JSON tags, ready to be un-marshalled from the configuration.
// The string fields are then parsed to *net.IPNet and returned as such in IPAMConfig
// structure.
type IPAMConfigForJSON struct {
	ContivCIDR                    string `json:"contivCIDR,omitempty"`
	ServiceCIDR                   string `json:"serviceCIDR,omitempty"`
	NodeInterconnectDHCP          bool   `json:"nodeInterconnectDHCP,omitempty"`
	PodVPPSubnetCIDR              string `json:"podVPPSubnetCIDR,omitempty"`
	PodSubnetCIDR                 string `json:"podSubnetCIDR,omitempty"`
	PodSubnetOneNodePrefixLen     uint8  `json:"podSubnetOneNodePrefixLen,omitempty"`
	VPPHostSubnetCIDR             string `json:"vppHostSubnetCIDR,omitempty"`
	VPPHostSubnetOneNodePrefixLen uint8  `json:"vppHostSubnetOneNodePrefixLen,omitempty"`
	NodeInterconnectCIDR          string `json:"nodeInterconnectCIDR,omitempty"`
	VxlanCIDR                     string `json:"vxlanCIDR,omitempty"`
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
//  - parses IP subnets configured for IPAM
//  - for contiv-init:
//       * if crdNodeConfigurationDisabled=false, waits for NodeConfig CRD to be available
//       * if stealFirstNIC=true, lists Linux interfaces to obtain the first one
func (c *ContivConf) Init() (err error) {
	// initialize callbacks
	if c.UnitTestDeps != nil {
		// real methods replaced with mocks for unit testing
		if c.UnitTestDeps.RequestSTNInfoClb != nil {
			c.requestSTNInfoClb = c.UnitTestDeps.RequestSTNInfoClb
		} else {
			c.requestSTNInfoClb = func(ifName string) (reply *stn_grpc.STNReply, err error) {
				return nil, errors.New("callback RequestSTNInfoClb was not injected")
			}
		}
		if c.UnitTestDeps.DumpDPDKInterfacesClb != nil {
			c.dumpDPDKInterfacesClb = c.UnitTestDeps.DumpDPDKInterfacesClb
		} else {
			c.dumpDPDKInterfacesClb = func() (ifaces []string, err error) {
				return ifaces, nil
			}
		}
		if c.UnitTestDeps.GetFirstHostInterfaceNameClb != nil {
			c.getFirstHostInterfaceNameClb = c.UnitTestDeps.GetFirstHostInterfaceNameClb
		} else {
			c.getFirstHostInterfaceNameClb = func() string {
				return defaultFirstHostInterfaceForUTs
			}
		}
	} else {
		c.requestSTNInfoClb = c.requestSTNInfo
		c.dumpDPDKInterfacesClb = c.dumpDPDKInterfaces
		c.getFirstHostInterfaceNameClb = c.getFirstHostInterfaceName
	}

	// default configuration
	c.config = &Config{
		STNSocketFile:                defaultSTNSocketFile,
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
		IPAMConfig: IPAMConfigForJSON{
			ServiceCIDR:                   defaultServiceCIDR,
			PodSubnetCIDR:                 defaultPodSubnetCIDR,
			PodSubnetOneNodePrefixLen:     defaultPodSubnetOneNodePrefixLen,
			PodVPPSubnetCIDR:              defaultPodVPPSubnetCIDR,
			VPPHostSubnetCIDR:             defaultVPPHostSubnetCIDR,
			VPPHostSubnetOneNodePrefixLen: defaultVPPHostSubnetOneNodePrefixLen,
			VxlanCIDR:                     defaultVxlanCIDR,
		},
		NatExternalTraffic: defaultNatExternalTraffic,
	}

	if c.UnitTestDeps != nil {
		// use injected configuration
		marshalled, err := yaml.Marshal(c.UnitTestDeps.Config)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(marshalled, c.config)
		if err != nil {
			return err
		}
	} else {
		// load configuration from the file
		_, err = c.Cfg.LoadValue(c.config)
		if err != nil {
			return err
		}
	}
	c.Log.Infof("Contiv configuration: %+v", *c.config)

	// parse IPAM subnets
	c.ipamConfig = &IPAMConfig{
		NodeInterconnectDHCP: c.config.IPAMConfig.NodeInterconnectDHCP,
		CustomIPAMSubnets: CustomIPAMSubnets{
			PodSubnetOneNodePrefixLen:     c.config.IPAMConfig.PodSubnetOneNodePrefixLen,
			VPPHostSubnetOneNodePrefixLen: c.config.IPAMConfig.VPPHostSubnetOneNodePrefixLen,
		},
	}
	if c.config.IPAMConfig.ContivCIDR != "" {
		_, c.ipamConfig.ContivCIDR, err = net.ParseCIDR(c.config.IPAMConfig.ContivCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse ContivCIDR: %v", err)
		}
	}
	if c.config.IPAMConfig.NodeInterconnectCIDR != "" {
		_, c.ipamConfig.NodeInterconnectCIDR, err = net.ParseCIDR(c.config.IPAMConfig.NodeInterconnectCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse NodeInterconnectCIDR: %v", err)
		}
	}
	_, c.ipamConfig.ServiceCIDR, err = net.ParseCIDR(c.config.IPAMConfig.ServiceCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse ServiceCIDR: %v", err)
	}
	_, c.ipamConfig.PodSubnetCIDR, err = net.ParseCIDR(c.config.IPAMConfig.PodSubnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse PodSubnetCIDR: %v", err)
	}
	_, c.ipamConfig.PodVPPSubnetCIDR, err = net.ParseCIDR(c.config.IPAMConfig.PodVPPSubnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse PodVPPSubnetCIDR: %v", err)
	}
	_, c.ipamConfig.VPPHostSubnetCIDR, err = net.ParseCIDR(c.config.IPAMConfig.VPPHostSubnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse VPPHostSubnetCIDR: %v", err)
	}
	_, c.ipamConfig.VxlanCIDR, err = net.ParseCIDR(c.config.IPAMConfig.VxlanCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse VxlanCIDR: %v", err)
	}

	// create GoVPP channel for contiv-agent
	if c.ContivAgentDeps != nil && c.UnitTestDeps == nil {
		c.govppCh, err = c.GoVPP.NewAPIChannel()
		if err != nil {
			return err
		}
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
				c.Log.Info("Waiting 1sec for NodeConfig CRD to be applied...")
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
			c.stnInterface = c.getFirstHostInterfaceNameClb()
			if c.stnInterface != "" {
				c.Log.Infof("No specific NIC to steal specified, stealing the first one: %s",
					c.stnInterface)
			}
		}

		// re-load node interface names, IPs, default GW, DHCP option
		err = c.reloadNodeInterfaces()
		if err != nil {
			return err
		}
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
			// interested in the node config for this node if CRD is enabled
			if !c.config.CRDNodeConfigurationDisabled &&
				ksChange.Key == nodeconfig.Key(myNodeName) {
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

// Resync reloads the configuration - configuration file and STN configuration,
// however, are loaded only once during the startup resync.
func (c *ContivConf) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	// re-sync NodeConfig CRD
	c.nodeConfigCRD = nil
	if !c.config.CRDNodeConfigurationDisabled {
		myNodeName := c.ServiceLabel.GetAgentLabel()
		for key, nodeConfig := range kubeStateData[nodeconfig.Keyword] {
			if key == nodeconfig.Key(myNodeName) {
				c.nodeConfigCRD = nodeConfigFromProto(nodeConfig.(*nodeconfig.NodeConfig))
				break
			}
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
			err = c.loadSTNHostConfig(c.stnInterface)
			if err != nil {
				return controller.NewFatalError(err)
			}
		}

		// dump DPDK interfaces configured on VPP
		c.dpdkIfaces, err = c.dumpDPDKInterfacesClb()
		if err != nil {
			return controller.NewFatalError(err)
		}
	}

	// re-load node interface names, IPs, default GW, DHCP option
	err = c.reloadNodeInterfaces()
	if err != nil {
		return controller.NewFatalError(err)
	}
	return nil
}

// Update is called for KubeStateChange for CRD node-specific config of this node.
func (c *ContivConf) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	var nodeConfig *NodeConfig
	ksChange := event.(*controller.KubeStateChange)
	if ksChange.NewValue != nil {
		nodeConfig = nodeConfigFromProto(ksChange.NewValue.(*nodeconfig.NodeConfig))
	}
	followUpEv := &NodeConfigChange{nodeConfig: nodeConfig}
	err = c.EventLoop.PushEvent(followUpEv)
	if err != nil {
		return "", err
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

// GetMainInterfaceConfiguredIPs returns the list of IP addresses configured
// to be assigned to the main interface. Ignore if DHCP is enabled.
// The function may return an empty list, then it is necessary to request
// node IP from IPAM.
func (c *ContivConf) GetMainInterfaceConfiguredIPs() IPsWithNetworks {
	return c.mainInterfaceIPs
}

// GetOtherVPPInterfaces returns configuration to apply for non-main physical
// VPP interfaces.
func (c *ContivConf) GetOtherVPPInterfaces() OtherInterfaces {
	return c.otherInterfaces
}

// GetStaticDefaultGW returns the IP address of the default gateway.
// Ignore if DHCP is enabled (in that case it is provided by the DHCP server)
func (c *ContivConf) GetStaticDefaultGW() net.IP {
	return c.defaultGw
}

// NatExternalTraffic returns true when it is required to S-NAT traffic
// leaving the node and heading out from the cluster.
func (c *ContivConf) NatExternalTraffic() bool {
	nodeConfig := c.getNodeSpecificConfig()
	return c.config.NatExternalTraffic || (nodeConfig != nil && nodeConfig.NatExternalTraffic)
}

// GetIPAMConfig returns configuration to be used by the IPAM module.
func (c *ContivConf) GetIPAMConfig() *IPAMConfig {
	return c.ipamConfig
}

// GetIPAMConfigForJSON returns IPAM configuration in format suitable
// for marshalling to JSON (subnets not converted to net.IPNet + defined
// JSON flag for every option).
func (c *ContivConf) GetIPAMConfigForJSON() *IPAMConfigForJSON {
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

// UseVmxnet3 returns true if vmxnet3 driver should be used for access to physical
// interfaces instead of DPDK.
// Vmxnet3 configuration can be obtained using GetVmxnet3Config()
func (c *ContivConf) UseVmxnet3() bool {
	if c.mainInterface == "" {
		return false
	}
	return strings.HasPrefix(c.mainInterface, vmxnet3InterfacePrefix)
}

// GetVmxnet3Config returns configuration related to vmxnet3 feature.
// Use the method only if vmxnet3 is in use - i.e. when UseVmxnet3() returns true.
func (c *ContivConf) GetVmxnet3Config() (*Vmxnet3Config, error) {
	if !c.UseVmxnet3() {
		return nil, fmt.Errorf("vmxnet3 not in use")
	}

	pci, err := vmxnet3PCIFromName(c.mainInterface)
	if err != nil {
		return nil, err
	}

	return &Vmxnet3Config{
		MainInterfaceName:       c.mainInterface,
		MainInterfacePCIAddress: pci,
	}, nil
}

// Close is NOOP.
func (c *ContivConf) Close() error {
	return nil
}

// reloadNodeInterfaces re-loads node interface names, IPs, default GW, DHCP option.
func (c *ContivConf) reloadNodeInterfaces() error {
	nodeConfig := c.getNodeSpecificConfig()

	// DHCP
	c.useDHCP = false
	if c.ipamConfig.NodeInterconnectDHCP || (nodeConfig != nil && nodeConfig.MainVPPInterface.UseDHCP) {
		c.useDHCP = true
	}
	if nodeConfig != nil && nodeConfig.MainVPPInterface.IP != "" {
		// MainVPPInterface.IP overrides DHCP options
		c.useDHCP = false
	}

	// main interface
	c.mainInterface = ""
	if nodeConfig != nil {
		c.mainInterface = nodeConfig.MainVPPInterface.InterfaceName
	}
	if c.mainInterface == "" && c.InSTNMode() && c.stnKernelDriver == vmxnet3KernelDriver {
		c.mainInterface = vmxnet3IfNameFromPCI(c.stnPCIAddress)
		c.Log.Debugf("vmxnet3 interface name derived from the PCI address: %s", c.mainInterface)
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

	// main interface configured IPs
	c.mainInterfaceIPs = IPsWithNetworks{}
	if !c.useDHCP {
		if c.InSTNMode() {
			c.mainInterfaceIPs = c.stnIPAddresses
		} else if nodeConfig != nil && nodeConfig.MainVPPInterface.IP != "" {
			ipAddr, ipNet, err := net.ParseCIDR(nodeConfig.MainVPPInterface.IP)
			if err != nil {
				c.Log.Errorf("Failed to parse main interface IP address from the config: %v", err)
				return err
			}
			c.mainInterfaceIPs = []*IPWithNetwork{{Address: ipAddr, Network: ipNet}}
		}
	}

	// other interfaces
	c.otherInterfaces = OtherInterfaces{}
	if nodeConfig != nil {
		for _, iface := range nodeConfig.OtherVPPInterfaces {
			cfg := &OtherInterfaceConfig{
				InterfaceName: iface.InterfaceName,
				UseDHCP:       iface.UseDHCP,
			}
			if iface.IP != "" {
				ipAddr, ipNet, err := net.ParseCIDR(iface.IP)
				if err != nil {
					err := fmt.Errorf("failed to parse IP address configured for interface %s: %v",
						iface.InterfaceName, err)
					return err
				}
				cfg.UseDHCP = false // IP overrides UseDHCP
				cfg.IPs = []*IPWithNetwork{{Address: ipAddr, Network: ipNet}}
			}
			c.otherInterfaces = append(c.otherInterfaces, cfg)
		}
	}

	// static default GW
	c.defaultGw = net.IP{}
	if !c.useDHCP {
		if c.InSTNMode() {
			c.defaultGw = c.stnGW
		} else if nodeConfig != nil && nodeConfig.Gateway != "" {
			c.defaultGw = net.ParseIP(nodeConfig.Gateway)
			if c.defaultGw == nil {
				err := fmt.Errorf("failed to parse gateway IP address from the config (%s)",
					nodeConfig.Gateway)
				return err
			}
		}
	}

	c.Log.Infof("ContivConf state after re-load: "+
		"useDHCP=%t, mainInterface=%s, mainInterfaceIPs=%s, otherInterfaces=%s, "+
		"defaultGw=%v, dpdkIfaces=%v, stnInterface=%s, stnIPAddresses=%s, "+
		"stnGW=%v, stnRoutes=%v", c.useDHCP, c.mainInterface, c.mainInterfaceIPs.String(),
		c.otherInterfaces.String(), c.defaultGw, c.dpdkIfaces, c.stnInterface,
		c.stnIPAddresses.String(), c.stnGW, c.stnRoutes)
	return nil
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

// loadSTNHostConfig loads IP addresses and routes associated with the main interface
// before it was stolen from the host stack.
func (c *ContivConf) loadSTNHostConfig(ifName string) error {
	if ifName == "" {
		c.Log.Debug("Getting STN info for the first stolen interface")
	} else {
		c.Log.Debugf("Getting STN info for interface %s", ifName)
	}

	// request info about the stolen interface
	reply, err := c.requestSTNInfoClb(ifName)
	if err != nil {
		c.Log.Errorf("Error by executing STN GRPC: %v", err)
		return err
	}
	c.Log.Debugf("STN GRPC reply: %v", reply)

	// parse STN IP addresses
	for _, address := range reply.IpAddresses {
		ipNet := &IPWithNetwork{}
		ipNet.Address, ipNet.Network, err = net.ParseCIDR(address)
		if err != nil {
			c.Log.Errorf("Failed to parse IP address returned by STN GRPC: %v", err)
			return err
		}
		c.stnIPAddresses = append(c.stnIPAddresses, ipNet)
	}

	// try to find the default gateway in the list of routes
	for _, r := range reply.Routes {
		if r.DestinationSubnet == "" || strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			c.stnGW = net.ParseIP(r.NextHopIp)
			if err != nil {
				err = fmt.Errorf("failed to parse GW address returned by STN GRPC (%s)", r.NextHopIp)
				return err
			}
			break
		}
	}
	if len(c.stnGW) == 0 && len(c.stnIPAddresses) > 0 {
		// no default gateway in routes, calculate fake gateway address for route pointing to VPP
		firstIP, lastIP := cidr.AddressRange(c.stnIPAddresses[0].Network)
		if !cidr.Inc(firstIP).Equal(c.stnIPAddresses[0].Address) {
			c.stnGW = cidr.Inc(firstIP)
		} else {
			c.stnGW = cidr.Dec(lastIP)
		}
	}

	c.stnRoutes = reply.Routes
	c.stnPCIAddress = reply.PciAddress
	c.stnKernelDriver = reply.KernelDriver

	return nil
}

// requestSTNInfo sends request to the STN daemon to obtain information about a stolen interface.
func (c *ContivConf) requestSTNInfo(ifName string) (reply *stn_grpc.STNReply, err error) {
	// connect to STN GRPC server
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

// vmxnet3IfNameFromPCI derives vmxnet3 interface name on VPP from provided PCI address
func vmxnet3IfNameFromPCI(pciAddr string) string {
	var a, b, c, d uint32

	fmt.Sscanf(pciAddr, "%x:%x:%x.%x", &a, &b, &c, &d)                      // e.g. "0000:0b:00.0"
	return fmt.Sprintf("%s%x/%x/%x/%x", vmxnet3InterfacePrefix, a, b, c, d) // e.g. "vmxnet3-0/b/0/0"
}

// vmxnet3PCIFromName derives PCI address string from provided vmxnet3 interface name
func vmxnet3PCIFromName(ifName string) (string, error) {
	var function, slot, bus, domain uint32
	numLen, err := fmt.Sscanf(ifName, "vmxnet3-%x/%x/%x/%x", &domain, &bus, &slot, &function)
	if err != nil {
		err = fmt.Errorf("cannot parse PCI address from the vmxnet3 interface name %s: %v", ifName, err)
		return "", err
	}
	if numLen != 4 {
		err = fmt.Errorf("cannot parse PCI address from the interface name %s: expected 4 address elements, received %d",
			ifName, numLen)
		return "", err
	}
	return fmt.Sprintf("%04x:%02x:%02x.%0x", domain, bus, slot, function), nil
}
