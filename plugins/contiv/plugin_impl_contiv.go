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
//go:generate protoc -I ./model/uid --go_out=plugins=grpc:./model/uid ./model/uid/uid.proto
//go:generate binapi-generator --input-file=/usr/share/vpp/api/stn.api.json --output-dir=bin_api
//go:generate binapi-generator --input-file=/usr/share/vpp/api/session.api.json --output-dir=bin_api

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
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/govppmux"
)

// Plugin transforms GRPC requests into configuration for the VPP in order
// to connect a container into the network.
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

	Config *Config
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

// Config is configuration for Contiv plugin.
// It can be injected or loaded from external config. Injection has priority to external config. To use external
// config add `<Contiv plugin name> + "-config="<absolute path to config>` in go run command flags.
type Config struct {
	TCPChecksumOffloadDisabled bool
	TCPstackDisabled           bool
	UseTAPInterfaces           bool
	TAPInterfaceVersion        uint8
	TAPv2RxRingSize            uint16
	TAPv2TxRingSize            uint16
	IPAMConfig                 ipam.Config
	NodeConfig                 []OneNodeConfig
}

// OneNodeConfig represents configuration for one node. It contains only settings specific to given node.
type OneNodeConfig struct {
	NodeName             string
	MainVppInterfaceName string
	OtherVPPInterfaces   []InterfaceWithIP // other configured interfaces get only ip address assigned in vpp
}

// InterfaceWithIP binds interface name with ip for configuration purposes.
type InterfaceWithIP struct {
	InterfaceName string
	IP            string
}

// Init initializes the grpc server handling the request from the CNI.
func (plugin *Plugin) Init() error {
	plugin.configuredContainers = containeridx.NewConfigIndex(plugin.Log, plugin.PluginName, "containers")

	plugin.ctx, plugin.ctxCancelFunc = context.WithCancel(context.Background())
	if plugin.Config == nil {
		if err := plugin.applyExternalConfig(); err != nil {
			return err
		}
	}

	var err error
	plugin.govppCh, err = plugin.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	plugin.nodeIDAllocator = newIDAllocator(plugin.ETCD, plugin.ServiceLabel.GetAgentLabel())
	uid, err := plugin.nodeIDAllocator.getID()
	if err != nil {
		return err
	}
	plugin.Log.Infof("Uid of the node is %v", uid)

	plugin.nodeIDsresyncChan = make(chan datasync.ResyncEvent)
	plugin.nodeIDSchangeChan = make(chan datasync.ChangeEvent)

	plugin.nodeIDwatchReg, err = plugin.Watcher.Watch("contiv-plugin", plugin.nodeIDSchangeChan, plugin.nodeIDsresyncChan, allocatedIDsKeyPrefix)
	if err != nil {
		return err
	}

	plugin.cniServer, err = newRemoteCNIServer(plugin.Log,
		func() linux.DataChangeDSL { return localclient.DataChangeRequest(plugin.PluginName) },
		plugin.Proxy,
		plugin.configuredContainers,
		plugin.govppCh,
		plugin.VPP.GetSwIfIndexes(),
		plugin.ServiceLabel.GetAgentLabel(),
		plugin.Config,
		uid)
	if err != nil {
		return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
	}
	cni.RegisterRemoteCNIServer(plugin.GRPC.Server(), plugin.cniServer)

	go plugin.cniServer.handleNodeEvents(plugin.ctx, plugin.nodeIDsresyncChan, plugin.nodeIDSchangeChan)

	return nil
}

func (plugin *Plugin) applyExternalConfig() error {
	externalCfg := &Config{}
	found, err := plugin.PluginConfig.GetValue(externalCfg) // It tries to lookup `PluginName + "-config"` in go run command flags.
	if err != nil {
		return fmt.Errorf("External Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("External Contiv plugin configuration was not found")
	}
	plugin.Config = externalCfg
	return nil
}

// AfterInit registers to the ResyncOrchestrator. The registration is done in this phase
// in order to trigger the resync for this plugin once the resync of defaultVPP plugins is finished.
func (plugin *Plugin) AfterInit() error {
	if plugin.Resync != nil {
		reg := plugin.Resync.Register(string(plugin.PluginName))
		go plugin.handleResync(reg.StatusChan())
	}
	return nil
}

// Close cleans up the resources allocated by the plugin
func (plugin *Plugin) Close() error {
	plugin.ctxCancelFunc()
	plugin.cniServer.close()
	plugin.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(plugin.govppCh, plugin.nodeIDwatchReg)
	return err
}

// getContainerConfig return the configuration of the container associated
// with the given pod.
func (plugin *Plugin) getContainerConfig(podNamespace string, podName string) *containeridx.Config {
	podNamesMatch := plugin.configuredContainers.LookupPodName(podName)
	podNamespacesMatch := plugin.configuredContainers.LookupPodNamespace(podNamespace)

	for _, pod1 := range podNamespacesMatch {
		for _, pod2 := range podNamesMatch {
			if pod1 == pod2 {
				found, data := plugin.configuredContainers.LookupContainer(pod1)
				if found {
					return data
				}
			}
		}
	}

	return nil
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given pod.
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil && config.PodVppIf != nil {
		return config.PodVppIf.Name, true
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return "", false
}

// GetNsIndex returns the index of the VPP session namespace associated
// with the given pod.
func (plugin *Plugin) GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool) {
	config := plugin.getContainerConfig(podNamespace, podName)
	if config != nil {
		return config.NsIndex, true
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return 0, false
}

// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
func (plugin *Plugin) GetPodNetwork() *net.IPNet {
	return plugin.cniServer.ipam.PodNetwork()
}

// IsTCPstackDisabled returns true if the tcp stack is disabled and only veths are configured
func (plugin *Plugin) IsTCPstackDisabled() bool {
	return plugin.Config.TCPstackDisabled
}

// GetHostIPNetwork returns single-host subnet with the IP address of this node.
func (plugin *Plugin) GetHostIPNetwork() *net.IPNet {
	// TODO
	return nil
}

// GetPhysicalIfNames returns a slice of names of all configured physical interfaces.
func (plugin *Plugin) GetPhysicalIfNames() []string {
	// TODO
	return []string{}
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (plugin *Plugin) GetHostInterconnectIfName() string {
	// TODO
	return ""
}

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
