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
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/rpc/grpc"
)

// Plugin transforms GRPC requests into configuration for the VPP in order
// to connect a container into the network.
type Plugin struct {
	Deps

	cniServer *remoteCNIserver
}

// Deps groups the dependencies of the Plugin.
type Deps struct {
	local.PluginInfraDeps
	GRPC  grpc.Server
	Proxy *kvdbproxy.Plugin
}

// Init initializes the grpc server handling the request from the CNI.
func (plugin *Plugin) Init() error {
	plugin.cniServer = newRemoteCNIServer(plugin.Log, plugin.Proxy)
	cni.RegisterRemoteCNIServer(plugin.GRPC.Server(), plugin.cniServer)
	return nil
}

// Close cleans up the resources allocated by the plugin
func (plugin *Plugin) Close() error {
	return nil
}
