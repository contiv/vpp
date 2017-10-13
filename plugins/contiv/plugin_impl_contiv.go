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

package contiv

import (
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
)

// Plugin transforms GRPC requests into configuration for the VPP in order
// to connect a container into the network.
type Plugin struct {
	Deps

	configuredContainers *containeridx.ConfigIndex
	cniServer            *remoteCNIserver
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	local.PluginInfraDeps
	GRPC  grpc.Server
	Proxy *kvdbproxy.Plugin
	VPP   *defaultplugins.Plugin
}

// Init initializes the grpc server handling the request from the CNI.
func (plugin *Plugin) Init() error {
	plugin.configuredContainers = containeridx.NewConfigIndex(plugin.Log, plugin.PluginName, "containers")
	plugin.cniServer = newRemoteCNIServer(plugin.Log,
		func() linux.DataChangeDSL { return localclient.DataChangeRequest(plugin.PluginName) },
		plugin.Proxy,
		plugin.configuredContainers)
	cni.RegisterRemoteCNIServer(plugin.GRPC.Server(), plugin.cniServer)
	return nil
}

// Close cleans up the resources allocated by the plugin
func (plugin *Plugin) Close() error {
	return nil
}

// GetSwIfIndex looks up SwIfIndex that corresponds to an interface associated with the given podNamespace and the podName.
func (plugin *Plugin) GetSwIfIndex(podNamespace string, podName string) (idx uint32, meta *interfaces.Interfaces_Interface, found bool) {
	podNamesMatch := plugin.configuredContainers.LookupPodName(podName)
	podNamespacesMatch := plugin.configuredContainers.LookupPodNamespace(podNamespace)

	if len(podNamesMatch) == 1 && len(podNamespacesMatch) == 1 && podNamesMatch[0] == podNamespacesMatch[0] {
		found, data := plugin.configuredContainers.LookupContainer(podNamesMatch[0])
		if found && data != nil && data.Afpacket != nil {
			return plugin.VPP.GetSwIfIndexes().LookupIdx(data.Afpacket.Name)
		}
	}
	plugin.Log.WithFields(logging.Fields{"podNamespace": podNamespace, "podName": podName}).Warn("No matching result found")
	return 0, nil, false
}

// GetIfName looks up logical interface name that corresponds to an interface associated with the given podNamespace and the podName.
// TODO: I think the policy plugin will need the interface name for use with the localclient (?)
//        - consider removing GetSwIfIndex and implementing this without a lookup in VPP idxmap (metadata are also probably not needed)
func (plugin *Plugin) GetIfName(podNamespace string, podName string) (name string, metadata *interfaces.Interfaces_Interface, exists bool) {
	idx, _, found := plugin.GetSwIfIndex(podNamespace, podName)
	if found {
		return plugin.VPP.GetSwIfIndexes().LookupName(idx)
	}
	return "", nil, false
}
