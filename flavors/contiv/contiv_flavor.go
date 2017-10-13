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

// Package contiv defines flavor used for Contiv-VPP agent.
package contiv

import (
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/flavors/local"

	"github.com/contiv/vpp/flavors/ksr"
	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/contiv/vpp/plugins/policy"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	local_sync "github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/flavors/connectors"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/linuxplugin"
)

// FlavorContiv glues together multiple plugins to manage VPP and Linux
// configuration using the local client.
type FlavorContiv struct {
	*local.FlavorLocal

	ETCD            etcdv3.Plugin
	ETCDDataSync    kvdbsync.Plugin
	KsrETCDDataSync kvdbsync.Plugin

	KVProxy kvdbproxy.Plugin

	LinuxLocalClient localclient.Plugin
	GoVPP            govppmux.GOVPPPlugin
	Linux            linuxplugin.Plugin
	VPP              defaultplugins.Plugin
	GRPC             grpc.Plugin
	Contiv           contiv.Plugin
	Policy           policy.Plugin
	ResyncOrch       resync.Plugin
	injected         bool
}

// Inject sets inter-plugin references.
func (f *FlavorContiv) Inject() bool {
	if f.injected {
		return false
	}
	f.injected = true

	if f.FlavorLocal == nil {
		f.FlavorLocal = &local.FlavorLocal{}
	}
	f.FlavorLocal.Inject()

	f.ETCD.Deps.PluginInfraDeps = *f.InfraDeps("etcdv3", local.WithConf())
	connectors.InjectKVDBSync(&f.ETCDDataSync, &f.ETCD, f.ETCD.PluginName, f.FlavorLocal, &f.ResyncOrch)
	f.KsrETCDDataSync = *f.ETCDDataSync.OfDifferentAgent(ksr.MicroserviceLabel, f)

	f.KVProxy.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("kvproxy")
	f.KVProxy.Deps.KVDB = &f.ETCDDataSync

	f.GoVPP.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("govpp")
	f.Linux.Watcher = &datasync.CompositeKVProtoWatcher{Adapters: []datasync.KeyValProtoWatcher{local_sync.Get()}}

	f.VPP.Watch = &datasync.CompositeKVProtoWatcher{Adapters: []datasync.KeyValProtoWatcher{local_sync.Get(), &f.KVProxy}}
	f.VPP.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("default-plugins")
	f.VPP.Deps.Linux = &f.Linux
	f.VPP.Deps.GoVppmux = &f.GoVPP
	f.VPP.Deps.PublishStatistics = &datasync.CompositeKVProtoWriter{Adapters: []datasync.KeyProtoValWriter{&devNullWriter{}}}
	f.VPP.Deps.IfStatePub = &datasync.CompositeKVProtoWriter{Adapters: []datasync.KeyProtoValWriter{&devNullWriter{}}}

	grpc.DeclareGRPCPortFlag("grpc")
	grpcInfraDeps := f.FlavorLocal.InfraDeps("grpc")
	f.GRPC.Deps.Log = grpcInfraDeps.Log
	f.GRPC.Deps.PluginName = grpcInfraDeps.PluginName
	f.GRPC.Deps.PluginConfig = grpcInfraDeps.PluginConfig

	f.Contiv.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("cni-grpc")
	f.Contiv.Deps.GRPC = &f.GRPC
	f.Contiv.Deps.Proxy = &f.KVProxy

	f.Policy.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("policy")
	f.Policy.Deps.Watcher = &f.KsrETCDDataSync
	f.Policy.Deps.Contiv = &f.Contiv

	f.ResyncOrch.PluginLogDeps = *f.LogDeps("resync-orch")

	return true
}

// Plugins combines all Plugins in the flavor to a list.
func (f *FlavorContiv) Plugins() []*core.NamedPlugin {
	f.Inject()
	return core.ListPluginsInFlavor(f)
}

type devNullWriter struct {
}

func (d *devNullWriter) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	return nil
}
