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

//go:generate protoc -I ./model/cni --go_out=plugins=grpc:./model/cni ./model/cni/cni.proto
//go:generate protoc -I ./model/node --go_out=plugins=grpc:./model/node ./model/node/node.proto

package contiv

import (
	"context"
	"fmt"
	"math/big"
	"net"

	"strings"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	protoNode "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"
	"github.com/ligato/vpp-agent/clientv1/linux"
	linuxlocalclient "github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/vpp"
)

// Plugin represents the instance of the Contiv network plugin, that transforms CNI requests received over
// GRPC into configuration for the vswitch VPP in order to connect/disconnect a container into/from the network.
type Plugin struct {
	Deps
	govppCh api.Channel

	configuredContainers *containeridx.ConfigIndex
	cniServer            *remoteCNIserver

	nodeIDAllocator   *idAllocator
	nodeIDsresyncChan chan datasync.ResyncEvent
	nodeIDSchangeChan chan datasync.ChangeEvent
	nodeIDwatchReg    datasync.WatchRegistration
	watchReg          datasync.WatchRegistration
	resyncCh          chan datasync.ResyncEvent
	changeCh          chan datasync.ChangeEvent

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	Config        *Config
	myNodeConfig  *OneNodeConfig
	nodeIPWatcher chan string
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	GRPC         grpc.Server
	Proxy        *kvdbproxy.Plugin
	VPP          *vpp.Plugin
	GoVPP        govppmux.API
	Resync       resync.Subscriber
	ETCD         *etcd.Plugin
	Bolt         keyval.KvProtoPlugin
	Watcher      datasync.KeyValProtoWatcher
	HTTPHandlers rest.HTTPHandlers
}

// Config represents configuration for the Contiv plugin.
// It can be injected or loaded from external config file. Injection has priority to external config. To use external
// config file, add `-contiv-config="<path to config>` argument when running the contiv-agent.
type Config struct {
	TCPChecksumOffloadDisabled  bool
	TCPstackDisabled            bool
	UseL2Interconnect           bool
	UseTAPInterfaces            bool
	TAPInterfaceVersion         uint8
	TAPv2RxRingSize             uint16
	TAPv2TxRingSize             uint16
	MTUSize                     uint32
	StealFirstNIC               bool
	StealInterface              string
	STNSocketFile               string
	NatExternalTraffic          bool   // if enabled, traffic with cluster-outside destination is SNATed on node output (for all nodes)
	CleanupIdleNATSessions      bool   // if enabled, the agent will periodically check for idle NAT sessions and delete inactive ones
	TCPNATSessionTimeout        uint32 // NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on
	OtherNATSessionTimeout      uint32 // NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on
	ScanIPNeighbors             bool   // if enabled, periodically scans and probes IP neighbors to maintain the ARP table
	IPNeighborScanInterval      uint8
	IPNeighborStaleThreshold    uint8
	MainVRFID                   uint32
	PodVRFID                    uint32
	ServiceLocalEndpointWeight  uint8
	DisableNATVirtualReassembly bool // if true, NAT plugin will drop fragmented packets
	IPAMConfig                  ipam.Config
	NodeConfig                  []OneNodeConfig
}

// OneNodeConfig represents configuration for one node. It contains only settings specific to given node.
type OneNodeConfig struct {
	NodeName           string            // name of the node, should match withs the hostname
	MainVPPInterface   InterfaceWithIP   // main VPP interface used for the inter-node connectivity
	OtherVPPInterfaces []InterfaceWithIP // other interfaces on VPP, not necessarily used for inter-node connectivity
	StealInterface     string            // interface to be stolen from the host stack and bound to VPP
	Gateway            string            // IP address of the default gateway
	NatExternalTraffic bool              // if enabled, traffic with cluster-outside destination is SNATed on node output
}

// InterfaceWithIP binds interface name with IP address for configuration purposes.
type InterfaceWithIP struct {
	InterfaceName string
	IP            string
	UseDHCP       bool
}

// Init initializes the Contiv plugin. Called automatically by plugin infra upon contiv-agent startup.
func (plugin *Plugin) Init() error {
	// init map with configured containers
	plugin.configuredContainers = containeridx.NewConfigIndex(plugin.Log, "containers",
		plugin.ETCD.NewBroker(plugin.ServiceLabel.GetAgentPrefix()))

	// load config file
	plugin.ctx, plugin.ctxCancelFunc = context.WithCancel(context.Background())
	if plugin.Config == nil {
		if err := plugin.loadExternalConfig(); err != nil {
			return err
		}
		plugin.myNodeConfig = plugin.loadNodeSpecificConfig()
	}

	var err error
	plugin.govppCh, err = plugin.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	// init node ID allocator
	nodeIP := ""
	if plugin.myNodeConfig != nil {
		nodeIP = plugin.myNodeConfig.MainVPPInterface.IP
	}
	plugin.nodeIDAllocator = newIDAllocator(plugin.ETCD, plugin.ServiceLabel.GetAgentLabel(), nodeIP)
	nodeID, err := plugin.nodeIDAllocator.getID()
	if err != nil {
		return err
	}
	plugin.Log.Infof("ID of the node is %v", nodeID)

	plugin.nodeIDsresyncChan = make(chan datasync.ResyncEvent)
	plugin.nodeIDSchangeChan = make(chan datasync.ChangeEvent)
	plugin.resyncCh = make(chan datasync.ResyncEvent)
	plugin.changeCh = make(chan datasync.ChangeEvent)

	plugin.nodeIDwatchReg, err = plugin.Watcher.Watch("contiv-plugin-ids", plugin.nodeIDSchangeChan, plugin.nodeIDsresyncChan, node.AllocatedIDsKeyPrefix)
	if err != nil {
		return err
	}

	plugin.watchReg, err = plugin.Watcher.Watch("contiv-plugin-node", plugin.changeCh, plugin.resyncCh, protoNode.KeyPrefix())
	if err != nil {
		return err
	}

	// start the GRPC server handling the CNI requests
	plugin.cniServer, err = newRemoteCNIServer(plugin.Log,
		func() linuxclient.DataChangeDSL {
			return linuxlocalclient.DataChangeRequest(plugin.String())
		},
		plugin.Proxy,
		plugin.configuredContainers,
		plugin.govppCh,
		plugin.VPP.GetSwIfIndexes(),
		plugin.VPP.GetDHCPIndices(),
		plugin.ServiceLabel.GetAgentLabel(),
		plugin.Config,
		plugin.myNodeConfig,
		nodeID,
		plugin.excludedIPsFromNodeCIDR(),
		plugin.Bolt.NewBroker(plugin.ServiceLabel.GetAgentPrefix()),
		plugin.HTTPHandlers)
	if err != nil {
		return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
	}
	cni.RegisterRemoteCNIServer(plugin.GRPC.GetServer(), plugin.cniServer)

	plugin.nodeIPWatcher = make(chan string, 1)
	go plugin.watchEvents()
	plugin.cniServer.WatchNodeIP(plugin.nodeIPWatcher)

	// start goroutine handling changes in nodes within the k8s cluster
	go plugin.cniServer.handleNodeEvents(plugin.ctx, plugin.nodeIDsresyncChan, plugin.nodeIDSchangeChan)

	return nil
}

// AfterInit is called by the plugin infra after Init of all plugins is finished.
// It registers to the ResyncOrchestrator. The registration is done in this phase
// in order to trigger the resync for this plugin once the resync of VPP plugins is finished.
func (plugin *Plugin) AfterInit() error {
	if plugin.Resync != nil {
		reg := plugin.Resync.Register(string(plugin.PluginName))
		go plugin.handleResync(reg.StatusChan())
	}
	return nil
}

// Close is called by the plugin infra upon agent cleanup. It cleans up the resources allocated by the plugin.
func (plugin *Plugin) Close() error {
	plugin.ctxCancelFunc()
	plugin.cniServer.close()
	//plugin.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(plugin.govppCh, plugin.nodeIDwatchReg, plugin.watchReg)
	return err
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (plugin *Plugin) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	ids := plugin.configuredContainers.LookupPodIf(ifname)
	if len(ids) != 1 {
		return "", "", false
	}
	config, found := plugin.configuredContainers.LookupContainer(ids[0])
	if !found {
		return "", "", false
	}
	return config.PodNamespace, config.PodName, true
}

// GetPodByAppNsIndex looks up podName and podNamespace that is associated with the VPP application namespace.
func (plugin *Plugin) GetPodByAppNsIndex(nsIndex uint32) (podNamespace string, podName string, exists bool) {
	nsID, _, found := plugin.VPP.GetAppNsIndexes().LookupName(nsIndex)
	if !found {
		return "", "", false
	}
	ids := plugin.configuredContainers.LookupPodAppNs(nsID)
	if len(ids) != 1 {
		return "", "", false
	}
	config, found := plugin.configuredContainers.LookupContainer(ids[0])
	if !found {
		return "", "", false
	}
	return config.PodNamespace, config.PodName, true
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil && config.VppIfName != "" {
		return config.VppIfName, true
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return "", false
}

// GetNsIndex returns the index of the VPP session namespace associated with the given POD name.
func (plugin *Plugin) GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil {
		nsIndex, _, exists = plugin.VPP.GetAppNsIndexes().LookupIdx(config.AppNamespaceID)
		return nsIndex, exists
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return 0, false
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (plugin *Plugin) GetPodSubnet() *net.IPNet {
	return plugin.cniServer.ipam.PodSubnet()
}

// GetPodNetwork provides subnet used for allocating pod IP addresses on this node.
func (plugin *Plugin) GetPodNetwork() *net.IPNet {
	return plugin.cniServer.ipam.PodNetwork()
}

// GetContainerIndex returns the index of configured containers/pods
func (plugin *Plugin) GetContainerIndex() containeridx.Reader {
	return plugin.configuredContainers
}

// IsTCPstackDisabled returns true if the VPP TCP stack is disabled and only VETHs/TAPs are configured.
func (plugin *Plugin) IsTCPstackDisabled() bool {
	return plugin.Config.TCPstackDisabled
}

// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
func (plugin *Plugin) InSTNMode() bool {
	return plugin.cniServer.UseSTN()
}

// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
// with node IP before being sent out from the node.
func (plugin *Plugin) NatExternalTraffic() bool {
	if plugin.Config.NatExternalTraffic ||
		(plugin.myNodeConfig != nil && plugin.myNodeConfig.NatExternalTraffic) {
		return true
	}
	return false
}

// CleanupIdleNATSessions returns true if cleanup of idle NAT sessions is enabled.
func (plugin *Plugin) CleanupIdleNATSessions() bool {
	return plugin.Config.CleanupIdleNATSessions
}

// GetTCPNATSessionTimeout returns NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (plugin *Plugin) GetTCPNATSessionTimeout() uint32 {
	return plugin.Config.TCPNATSessionTimeout
}

// GetOtherNATSessionTimeout returns NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (plugin *Plugin) GetOtherNATSessionTimeout() uint32 {
	return plugin.Config.OtherNATSessionTimeout
}

// GetServiceLocalEndpointWeight returns the load-balancing weight assigned to locally deployed service endpoints.
func (plugin *Plugin) GetServiceLocalEndpointWeight() uint8 {
	return plugin.Config.ServiceLocalEndpointWeight
}

// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (plugin *Plugin) GetNatLoopbackIP() net.IP {
	// Last unicast IP from the pod subnet is used as NAT-loopback.
	podNet := plugin.cniServer.ipam.PodNetwork()
	_, broadcastIP := cidr.AddressRange(podNet)
	return cidr.Dec(broadcastIP)
}

// GetNodeIP returns the IP address of this node.
func (plugin *Plugin) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return plugin.cniServer.GetNodeIP()
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (plugin *Plugin) GetHostIPs() []net.IP {
	return plugin.cniServer.GetHostIPs()
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (plugin *Plugin) WatchNodeIP(subscriber chan string) {
	plugin.cniServer.WatchNodeIP(subscriber)
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (plugin *Plugin) GetMainPhysicalIfName() string {
	return plugin.cniServer.GetMainPhysicalIfName()
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (plugin *Plugin) GetOtherPhysicalIfNames() []string {
	return plugin.cniServer.GetOtherPhysicalIfNames()
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (plugin *Plugin) GetHostInterconnectIfName() string {
	return plugin.cniServer.GetHostInterconnectIfName()
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (plugin *Plugin) GetVxlanBVIIfName() string {
	return plugin.cniServer.GetVxlanBVIIfName()
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (plugin *Plugin) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	return plugin.cniServer.GetDefaultInterface()
}

// RegisterPodPreRemovalHook allows to register callback that will be run for each
// pod immediately before its removal.
func (plugin *Plugin) RegisterPodPreRemovalHook(hook PodActionHook) {
	plugin.cniServer.RegisterPodPreRemovalHook(hook)
}

// RegisterPodPostAddHook allows to register callback that will be run for each
// pod once it is added and before the CNI reply is sent.
func (plugin *Plugin) RegisterPodPostAddHook(hook PodActionHook) {
	plugin.cniServer.RegisterPodPostAddHook(hook)
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (plugin *Plugin) GetMainVrfID() uint32 {
	return plugin.cniServer.GetMainVrfID()
}

// GetPodVrfID returns the ID of the POD VRF.
func (plugin *Plugin) GetPodVrfID() uint32 {
	return plugin.cniServer.GetPodVrfID()
}

// handleResync handles resync events of the plugin. Called automatically by the plugin infra.
func (plugin *Plugin) handleResync(resyncChan chan resync.StatusEvent) {
	for {
		select {
		case ev := <-resyncChan:
			status := ev.ResyncStatus()
			if status == resync.Started {
				err := plugin.cniServer.resync()
				if err != nil {
					plugin.Log.Error(err)
				}
			}
			ev.Ack()
		case <-plugin.ctx.Done():
			return
		}
	}
}

// loadExternalConfig attempts to load external configuration from a YAML file.
func (plugin *Plugin) loadExternalConfig() error {
	externalCfg := &Config{}
	found, err := plugin.Cfg.LoadValue(externalCfg) // It tries to lookup `PluginName + "-config"` in the executable arguments.
	if err != nil {
		return fmt.Errorf("External Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("External Contiv plugin configuration was not found")
	}
	plugin.Config = externalCfg

	externalCfg = getIPAMConfig(externalCfg)

	// use tap version 2 as default in case that TAPs are enabled
	if plugin.Config.TAPInterfaceVersion == 0 {
		plugin.Config.TAPInterfaceVersion = 2
	}

	// By default connections are equally distributed between service endpoints.
	if plugin.Config.ServiceLocalEndpointWeight == 0 {
		plugin.Config.ServiceLocalEndpointWeight = 1
	}

	return nil
}

// loadNodeSpecificConfig loads config specific for this node (given by its agent label).
func (plugin *Plugin) loadNodeSpecificConfig() *OneNodeConfig {
	for _, oneNodeConfig := range plugin.Config.NodeConfig {
		if oneNodeConfig.NodeName == plugin.ServiceLabel.GetAgentLabel() {
			return &oneNodeConfig
		}
	}
	return nil
}

// getContainerConfig returns the configuration of the container associated with the given POD name.
func (plugin *Plugin) getContainerConfig(podNamespace string, podName string) *container.Persisted {
	podNamesMatch := plugin.configuredContainers.LookupPodName(podName)
	podNamespacesMatch := plugin.configuredContainers.LookupPodNamespace(podNamespace)

	for _, pod1 := range podNamespacesMatch {
		for _, pod2 := range podNamesMatch {
			if pod1 == pod2 {
				data, found := plugin.configuredContainers.LookupContainer(pod1)
				if found {
					return data
				}
			}
		}
	}

	return nil
}

func (plugin *Plugin) watchEvents() {
	for {
		select {
		case newIP := <-plugin.nodeIPWatcher:
			if newIP != "" {
				err := plugin.nodeIDAllocator.updateIP(newIP)
				if err != nil {
					plugin.Log.Error(err)
				}
			}
		case changeEv := <-plugin.changeCh:
			var err error
			key := changeEv.GetKey()
			if strings.HasPrefix(key, protoNode.KeyPrefix()) {
				err = plugin.handleKsrNodeChange(changeEv)
			} else {
				plugin.Log.Warn("Change for unknown key %v received", key)
			}
			changeEv.Done(err)
		case resyncEv := <-plugin.resyncCh:
			var err error
			data := resyncEv.GetValues()

			for prefix, it := range data {
				if prefix == protoNode.KeyPrefix() {
					err = plugin.handleKsrNodeResync(it)
				}
			}
			resyncEv.Done(err)
		case <-plugin.ctx.Done():
		}
	}
}

// handleKsrNodeChange handles change event for the prefix where node data
// is stored by ksr. The aim is to extract node Internal IP - ip address
// that k8s use to access node(management IP). This IP is used as an endpoint
// for services where backends use host networking.
func (plugin *Plugin) handleKsrNodeChange(change datasync.ChangeEvent) error {
	var err error
	// look for our InternalIP skip the others
	if change.GetKey() != protoNode.Key(plugin.ServiceLabel.GetAgentLabel()) {
		return nil
	}
	if change.GetChangeType() == datasync.Delete {
		plugin.Log.Warn("Unexpected delete for node data received")
		return nil
	}
	value := &protoNode.Node{}
	err = change.GetValue(value)
	if err != nil {
		plugin.Log.Error(err)
		return err
	}
	var internalIP string
	for i := range value.Addresses {
		if value.Addresses[i].Type == protoNode.NodeAddress_NodeInternalIP {
			internalIP = value.Addresses[i].Address
			plugin.Log.Info("Internal IP of the node is ", internalIP)
			return plugin.nodeIDAllocator.updateManagementIP(internalIP)
		}
	}
	plugin.Log.Warn("Internal IP of the node is missing in ETCD.")

	return err
}

// handleKsrNodeResync handles resync event for the prefix where node data
// is stored by ksr. The aim is to extract node Internal IP - ip address
// that k8s use to access node(management IP). This IP is used as an endpoint
// for services where backends use host networking.
func (plugin *Plugin) handleKsrNodeResync(it datasync.KeyValIterator) error {
	var err error
	for {
		kv, stop := it.GetNext()
		if stop {
			break
		}
		value := &protoNode.Node{}
		err = kv.GetValue(value)
		if err != nil {
			return err
		}

		if value.Name == plugin.ServiceLabel.GetAgentLabel() {
			var internalIP string
			for i := range value.Addresses {
				if value.Addresses[i].Type == protoNode.NodeAddress_NodeInternalIP {
					internalIP = value.Addresses[i].Address
					plugin.Log.Info("Internal IP of the node is ", internalIP)
					return plugin.nodeIDAllocator.updateManagementIP(internalIP)
				}
			}
		}
		plugin.Log.Debug("Internal IP of the node is not in ETCD yet.")
	}
	return err
}

func (plugin *Plugin) excludedIPsFromNodeCIDR() []net.IP {
	if plugin.Config == nil {
		return nil
	}
	var excludedIPs []string
	for _, oneNodeConfig := range plugin.Config.NodeConfig {
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

func appendIfMissing(slice []string, s string) []string {
	for _, el := range slice {
		if el == s {
			return slice
		}
	}
	return append(slice, s)
}

// getIPAMConfig populates the Config struct with the calculated subnets
func getIPAMConfig(config *Config) *Config {
	_, contivNetwork, _ := net.ParseCIDR(config.IPAMConfig.ContivCIDR)
	maskSize, _ := contivNetwork.Mask.Size()
	subnetPrefixLength := 24 - maskSize

	podSubnetCIDR, _ := subnet(contivNetwork, 1, 0)
	podNetworkPrefixLen := uint8(24)
	vppHostSubnetCIDR, _ := subnet(contivNetwork, 1, 1)
	vppHostNetworkPrefixLen := uint8(24)
	nodeInterconnectCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 253)
	podIfIPCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 254)
	vxlanCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 255)

	config.IPAMConfig = ipam.Config{
		PodIfIPCIDR:             podIfIPCIDR.String(),
		PodSubnetCIDR:           podSubnetCIDR.String(),
		PodNetworkPrefixLen:     podNetworkPrefixLen,
		VPPHostSubnetCIDR:       vppHostSubnetCIDR.String(),
		VPPHostNetworkPrefixLen: vppHostNetworkPrefixLen,
		VxlanCIDR:               vxlanCIDR.String(),
	}

	if config.IPAMConfig.NodeInterconnectDHCP != true {
		config.IPAMConfig.NodeInterconnectCIDR = nodeInterconnectCIDR.String()
	}

	return config
}

// subnet takes a CIDR range and creates a subnet from it
// base: parent CIDR range
// newBits: number of additional prefix bits
// num: given network number.
//
// Example: 10.1.0.0/16, with additional 8 bits and a network number of 5
// result = 10.3.5.0/24
func subnet(base *net.IPNet, newBits int, num int) (*net.IPNet, error) {
	ip := base.IP
	mask := base.Mask

	baseLength, addressLength := mask.Size()
	newPrefixLen := baseLength + newBits

	// check if there is sufficient address space to extend the network prefix
	if newPrefixLen > addressLength {
		return nil, fmt.Errorf("not enought space to extend prefix of %d by %d", baseLength, newBits)
	}

	// calculate the maximum network number
	maxNetNum := uint64(1<<uint64(newBits)) - 1
	if uint64(num) > maxNetNum {
		return nil, fmt.Errorf("prefix extension of %d does not accommodate a subnet numbered %d", newBits, num)
	}

	return &net.IPNet{
		IP:   insertNetworkNumIntoIP(ip, num, newPrefixLen),
		Mask: net.CIDRMask(newPrefixLen, addressLength),
	}, nil
}

// ipToInt is simple utility function for conversion between IPv4/IPv6 and int.
func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32
	} else if len(ip) == net.IPv6len {
		return val, 128
	} else {
		return nil, 0
	}
}

// intToIP is simple utility function for conversion between int and IPv4/IPv6.
func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	val := make([]byte, bits/8)

	// big.Int.Bytes() removes front zero padding.
	// IP bytes packed at the end of the return array,
	for i := 1; i <= len(ipBytes); i++ {
		val[len(val)-i] = ipBytes[len(ipBytes)-i]
	}

	return net.IP(val)
}

func insertNetworkNumIntoIP(ip net.IP, num int, prefixLen int) net.IP {
	ipInt, totalBits := ipToInt(ip)
	bigNum := big.NewInt(int64(num))
	bigNum.Lsh(bigNum, uint(totalBits-prefixLen))
	ipInt.Or(ipInt, bigNum)

	return intToIP(ipInt, totalBits)
}
