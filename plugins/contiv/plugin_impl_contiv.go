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

//go:generate protoc -I ./model/cni --gogo_out=plugins=grpc:./model/cni ./model/cni/cni.proto
//go:generate protoc -I ./model/node --gogo_out=plugins=grpc:./model/node ./model/node/node.proto

package contiv

import (
	"context"
	"fmt"
	"net"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"

	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	k8sNode "github.com/contiv/vpp/plugins/ksr/model/node"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"

	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/clientv2/linux"
	linuxlocalclient "github.com/ligato/vpp-agent/clientv2/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"
)

// MgmtIPSeparator is a delimiter inserted between management IPs in nodeInfo structure
const MgmtIPSeparator = ","

// Plugin represents the instance of the Contiv network plugin, that transforms CNI requests received over
// GRPC into configuration for the vswitch VPP in order to connect/disconnect a container into/from the network.
type Plugin struct {
	Deps
	govppCh api.Channel

	cniServer       *remoteCNIserver
	nodeIDAllocator *idAllocator

	// CRD config watching
	nodeConfigResyncChan chan datasync.ResyncEvent
	nodeConfigChangeChan chan datasync.ChangeEvent
	nodeConfigWatchReg   datasync.WatchRegistration

	// kubernetes state data watching
	watchReg datasync.WatchRegistration
	resyncCh chan datasync.ResyncEvent
	changeCh chan datasync.ChangeEvent

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	Config        *Config
	myNodeConfig  *NodeConfig

	nodeIPWatcher chan string

	// synchronization between resync and data change events
	resyncCounter  uint
	k8sStateData   map[string]datasync.KeyVal // key -> value, revision
	pendingChanges []datasync.ChangeEvent
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	GRPC         grpc.Server
	VPPIfPlugin  vpp_ifplugin.API
	GoVPP        govppmux.API
	Resync       resync.Subscriber
	ETCD         *etcd.Plugin
	Bolt         keyval.KvProtoPlugin
	Watcher      datasync.KeyValProtoWatcher
	HTTPHandlers rest.HTTPHandlers
}

// Init initializes the Contiv plugin. Called automatically by plugin infra upon contiv-agent startup.
func (plugin *Plugin) Init() error {
	// load config file
	plugin.ctx, plugin.ctxCancelFunc = context.WithCancel(context.Background())
	if plugin.Config == nil {
		if err := plugin.loadExternalConfig(); err != nil {
			return err
		}
		plugin.myNodeConfig = plugin.loadNodeConfig()
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

	plugin.nodeConfigResyncChan = make(chan datasync.ResyncEvent)
	plugin.nodeConfigChangeChan = make(chan datasync.ChangeEvent)

	plugin.resyncCh = make(chan datasync.ResyncEvent)
	plugin.changeCh = make(chan datasync.ChangeEvent)

	plugin.nodeConfigWatchReg, err = plugin.Watcher.Watch("contiv-plugin-node-config",
		plugin.nodeConfigChangeChan, plugin.nodeConfigResyncChan, nodeconfig.Key(plugin.ServiceLabel.GetAgentLabel()))
	if err != nil {
		return err
	}

	plugin.watchReg, err = plugin.Watcher.Watch("contiv-plugin-k8s-state",
		plugin.changeCh, plugin.resyncCh, node.AllocatedIDsKeyPrefix, k8sNode.KeyPrefix(), k8sPod.KeyPrefix())
	if err != nil {
		return err
	}

	// start the GRPC server handling the CNI requests
	plugin.cniServer, err = newRemoteCNIServer(plugin.Log,
		func() linuxclient.DataChangeDSL {
			return linuxlocalclient.DataChangeRequest(plugin.String())
		},
		func() linuxclient.DataResyncDSL {
			return linuxlocalclient.DataResyncRequest(plugin.String())
		},
		plugin.govppCh,
		plugin.VPPIfPlugin.GetInterfaceIndex(),
		plugin.VPPIfPlugin.GetDHCPIndex(),
		plugin.ServiceLabel.GetAgentLabel(),
		plugin.Config,
		plugin.myNodeConfig,
		nodeID,
		plugin.excludedIPsFromNodeCIDR(),
		plugin.ETCD.NewBroker(plugin.ServiceLabel.GetAgentPrefix()),
		plugin.HTTPHandlers)
	if err != nil {
		return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
	}
	cni.RegisterRemoteCNIServer(plugin.GRPC.GetServer(), plugin.cniServer)

	plugin.nodeIPWatcher = make(chan string, 1)
	go plugin.watchEvents()
	plugin.cniServer.WatchNodeIP(plugin.nodeIPWatcher)

	// start goroutine handling changes in the configuration specific to this node
	go plugin.cniServer.handleNodeConfigEvents(plugin.ctx, plugin.nodeConfigResyncChan, plugin.nodeConfigChangeChan)

	return nil
}

// Close is called by the plugin infra upon agent cleanup. It cleans up the resources allocated by the plugin.
func (plugin *Plugin) Close() error {
	plugin.ctxCancelFunc()
	plugin.cniServer.close()
	//plugin.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(plugin.govppCh, plugin.nodeConfigWatchReg, plugin.watchReg)
	return err
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (plugin *Plugin) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	return plugin.cniServer.GetPodByIf(ifname)
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	return plugin.cniServer.GetIfName(podNamespace, podName)
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (plugin *Plugin) GetPodSubnet() *net.IPNet {
	return plugin.cniServer.ipam.PodSubnet()
}

// GetPodNetwork provides subnet used for allocating pod IP addresses on this node.
func (plugin *Plugin) GetPodNetwork() *net.IPNet {
	return plugin.cniServer.ipam.PodNetwork()
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

// DisableNATVirtualReassembly returns true if fragmented packets should be dropped by NAT.
func (plugin *Plugin) DisableNATVirtualReassembly() bool {
	return plugin.Config.DisableNATVirtualReassembly
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
	plugin.Log.Info("Contiv config: ", externalCfg)
	err = plugin.Config.ApplyIPAMConfig()
	if err != nil {
		return err
	}
	plugin.Config.ApplyDefaults()

	return nil
}

// loadNodeConfig loads config specific for this node (given by its agent label).
func (plugin *Plugin) loadNodeConfig() *NodeConfig {
	myNodeName := plugin.ServiceLabel.GetAgentLabel()
	// first try to get node config from CRD, reflected by contiv-crd into etcd
	// and mirrored into Bolt by us
	nodeConfig := LoadNodeConfigFromCRD(myNodeName, plugin.ETCD, plugin.Bolt, plugin.Log)
	if nodeConfig != nil {
		return nodeConfig
	}
	// try to find the node-specific configuration inside the config file
	return plugin.Config.GetNodeConfig(myNodeName)
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
			// TODO: delay before the first resync, drop those older than the last resync

			var err error
			for _, dataChng := range changeEv.GetChanges() {
				updateErr := plugin.processThisNodeChangeEvent(dataChng)
				if updateErr != nil {
					err = updateErr
				}

				updateErr = plugin.cniServer.update(dataChng)
				if updateErr != nil {
					err = updateErr
				}
			}
			changeEv.Done(err)

		case resyncEv := <-plugin.resyncCh:
			var err error
			resyncErr := plugin.thisNodeResync(resyncEv)
			if resyncErr != nil {
				err = resyncErr
			}

			resyncErr = plugin.cniServer.resync(resyncEv)
			if resyncErr != nil {
				err = resyncErr
			}

			resyncEv.Done(err)

		case <-plugin.ctx.Done():
		}
	}
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
