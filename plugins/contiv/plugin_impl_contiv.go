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

	"git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
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

// Init initializes the grpc server handling the request from the CNI.
func (plugin *Plugin) Init() error {
	plugin.configuredContainers = containeridx.NewConfigIndex(plugin.Log, plugin.PluginName, "containers")

	plugin.ctx, plugin.ctxCancelFunc = context.WithCancel(context.Background())

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

	plugin.cniServer = newRemoteCNIServer(plugin.Log,
		func() linux.DataChangeDSL { return localclient.DataChangeRequest(plugin.PluginName) },
		plugin.Proxy,
		plugin.configuredContainers,
		plugin.govppCh,
		plugin.VPP.GetSwIfIndexes(),
		plugin.ServiceLabel.GetAgentLabel(),
		uid)
	cni.RegisterRemoteCNIServer(plugin.GRPC.Server(), plugin.cniServer)

	go plugin.cniServer.handleNodeEvents(plugin.ctx, plugin.nodeIDsresyncChan, plugin.nodeIDSchangeChan)

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

// GetIfName looks up logical interface name that corresponds to the interface associated with the given pod.
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	podNamesMatch := plugin.configuredContainers.LookupPodName(podName)
	podNamespacesMatch := plugin.configuredContainers.LookupPodNamespace(podNamespace)

	for _, pod1 := range podNamespacesMatch {
		for _, pod2 := range podNamesMatch {
			if pod1 == pod2 {
				found, data := plugin.configuredContainers.LookupContainer(pod1)
				if found && data != nil && data.Afpacket != nil {
					return data.Afpacket.Name, true
				}
			}
		}
	}

	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return "", false
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
