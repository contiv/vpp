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
	"net"

	"git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/utils/safeclose"
	"github.com/ligato/vpp-agent/clientv1/linux"
	linuxlocalclient "github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/govppmux"
)

// Plugin represents the instance of the Contiv network plugin, that transforms CNI requests recieved over
// GRPC into configuration for the vswitch VPP in order to connect/disconnect a container into/from the network.
type Plugin struct {
	Deps
	govppCh *api.Channel

	configuredContainers *containeridx.ConfigIndex
	cniServer            *remoteCNIserver

	nodeIDAllocator   *idAllocator
	nodeIDsresyncChan chan datasync.ResyncEvent
	nodeIDSchangeChan chan datasync.ChangeEvent
	nodeIDwatchReg    datasync.WatchRegistration

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	Config        *Config
	myNodeConfig  *OneNodeConfig
	nodeIPWatcher chan string
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	local.PluginInfraDeps
	GRPC    grpc.Server
	Proxy   *kvdbproxy.Plugin
	VPP     *defaultplugins.Plugin
	GoVPP   govppmux.API
	Resync  resync.Subscriber
	ETCD    *etcdv3.Plugin
	Watcher datasync.KeyValProtoWatcher
}

// Config represents configuration for the Contiv plugin.
// It can be injected or loaded from external config file. Injection has priority to external config. To use external
// config file, add `-contiv-config="<path to config>` argument when running the contiv-agent.
type Config struct {
	TCPChecksumOffloadDisabled bool
	TCPstackDisabled           bool
	UseL2Interconnect          bool
	UseTAPInterfaces           bool
	TAPInterfaceVersion        uint8
	TAPv2RxRingSize            uint16
	TAPv2TxRingSize            uint16
	IPAMConfig                 ipam.Config
	NodeConfig                 []OneNodeConfig
}

// OneNodeConfig represents configuration for one node. It contains only settings specific to given node.
type OneNodeConfig struct {
	NodeName           string            // name of the node, should match withs the hostname
	MainVPPInterface   InterfaceWithIP   // main VPP interface used for the inter-node connectivity
	OtherVPPInterfaces []InterfaceWithIP // other interfaces on VPP, not necessarily used for inter-node connectivity
	Gateway            string            // IP address of the default gateway
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
	plugin.configuredContainers = containeridx.NewConfigIndex(plugin.Log, plugin.PluginName, "containers")

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

	plugin.nodeIDwatchReg, err = plugin.Watcher.Watch("contiv-plugin", plugin.nodeIDSchangeChan, plugin.nodeIDsresyncChan, allocatedIDsKeyPrefix)
	if err != nil {
		return err
	}

	// start the GRPC server handling the CNI requests
	plugin.cniServer, err = newRemoteCNIServer(plugin.Log,
		func() linux.DataChangeDSL {
			return linuxlocalclient.DataChangeRequest(plugin.PluginName)
		},
		plugin.Proxy,
		plugin.configuredContainers,
		plugin.govppCh,
		plugin.VPP.GetSwIfIndexes(),
		plugin.ServiceLabel.GetAgentLabel(),
		plugin.Config,
		plugin.myNodeConfig,
		nodeID)
	if err != nil {
		return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
	}
	cni.RegisterRemoteCNIServer(plugin.GRPC.Server(), plugin.cniServer)

	plugin.nodeIPWatcher = make(chan string)
	go plugin.watchNodeIP()
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
	plugin.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(plugin.govppCh, plugin.nodeIDwatchReg)
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

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil && config.VppIf != nil {
		return config.VppIf.Name, true
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return "", false
}

// GetNsIndex returns the index of the VPP session namespace associated with the given POD name.
func (plugin *Plugin) GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil {
		nsIndex, _, exists = plugin.VPP.GetAppNsIndexes().LookupIdx(config.AppNamespace.NamespaceId)
		return nsIndex, exists
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return 0, false
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

// GetNodeIP returns the IP address of this node.
func (plugin *Plugin) GetNodeIP() net.IP {
	return plugin.cniServer.GetNodeIP()
}

// GetPhysicalIfNames returns a slice of names of all configured physical interfaces.
func (plugin *Plugin) GetPhysicalIfNames() []string {
	return plugin.cniServer.GetPhysicalIfNames()
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
	found, err := plugin.PluginConfig.GetValue(externalCfg) // It tries to lookup `PluginName + "-config"` in the executable arguments.
	if err != nil {
		return fmt.Errorf("External Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("External Contiv plugin configuration was not found")
	}
	plugin.Config = externalCfg

	// use tap version 2 as default in case that TAPs are enabled
	if plugin.Config.TAPInterfaceVersion == 0 {
		plugin.Config.TAPInterfaceVersion = 2
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
func (plugin *Plugin) getContainerConfig(podNamespace string, podName string) *containeridx.Config {
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

func (plugin *Plugin) watchNodeIP() {
	for {
		select {
		case newIP := <-plugin.nodeIPWatcher:
			if newIP != "" {
				err := plugin.nodeIDAllocator.updateIP(newIP)
				if err != nil {
					plugin.Log.Error(err)
				}
			}
		case <-plugin.ctx.Done():
		}
	}
}
