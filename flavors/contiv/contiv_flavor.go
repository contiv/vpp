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
	"github.com/contiv/vpp/plugins/service"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	local_sync "github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/flavors/connectors"
	"github.com/ligato/cn-infra/health/probe"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/linux"
	vpp_rest "github.com/ligato/vpp-agent/plugins/rest"
	"github.com/ligato/vpp-agent/plugins/telemetry"
	"github.com/ligato/vpp-agent/plugins/vpp"
	"github.com/ligato/vpp-agent/plugins/vpp/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/nat"
	"sync"
)

const (
	// ContivConfigPath is the default location of Agent's Contiv plugin. This path reflects configuration in k8s/contiv-vpp.yaml.
	ContivConfigPath = "/etc/agent/contiv.yaml"

	// ContivConfigPathUsage explains the purpose of 'kube-config' flag.
	ContivConfigPathUsage = "Path to the Agent's Contiv plugin configuration yaml file."
)

// NewAgent returns a new instance of the Agent with plugins.
// It is an alias for core.NewAgent() to implicit use of the FlavorContiv
func NewAgent(opts ...core.Option) *core.Agent {
	return core.NewAgent(&FlavorContiv{}, opts...)
}

// WithPlugins for adding custom plugins to SFC Controller
// <listPlugins> is a callback that uses flavor input to
// inject dependencies for custom plugins that are in output
func WithPlugins(listPlugins func(local *FlavorContiv) []*core.NamedPlugin) core.WithPluginsOpt {
	return &withPluginsOpt{listPlugins}
}

// FlavorContiv glues together multiple plugins to manage VPP and Linux
// configuration using the local client.
type FlavorContiv struct {
	*local.FlavorLocal
	HTTP       rest.Plugin
	HealthRPC  probe.Plugin
	Prometheus prometheus.Plugin

	ETCD            etcd.Plugin
	ETCDDataSync    kvdbsync.Plugin
	NodeIDDataSync  kvdbsync.Plugin
	ServiceDataSync kvdbsync.Plugin
	PolicyDataSync  kvdbsync.Plugin

	KVProxy kvdbproxy.Plugin
	Stats   statscollector.Plugin

	LinuxLocalClient localclient.Plugin
	GoVPP            govppmux.GOVPPPlugin
	Linux            linux.Plugin
	VPP              vpp.Plugin
	VPPrest          vpp_rest.Plugin
	Telemetry        telemetry.Plugin
	GRPC             grpc.Plugin
	Contiv           contiv.Plugin
	Policy           policy.Plugin
	Service          service.Plugin

	// resync should the last plugin in the flavor in order to give
	// the others enough time to register
	ResyncOrch resync.Plugin

	injected bool
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

	rest.DeclareHTTPPortFlag("http")
	httpPlugDeps := *f.InfraDeps("http", local.WithConf())
	f.HTTP.Deps.Log = httpPlugDeps.Log
	f.HTTP.Deps.PluginConfig = httpPlugDeps.PluginConfig
	f.HTTP.Deps.PluginName = httpPlugDeps.PluginName

	f.Prometheus.Deps.PluginInfraDeps = *f.InfraDeps("prometheus")
	f.Prometheus.Deps.HTTP = &f.HTTP

	f.Logs.HTTP = &f.HTTP

	f.HealthRPC.Deps.PluginInfraDeps = *f.InfraDeps("health-rpc")
	f.HealthRPC.Deps.HTTP = &f.HTTP
	f.HealthRPC.Deps.StatusCheck = &f.StatusCheck

	f.ETCD.Deps.PluginInfraDeps = *f.InfraDeps("etcd", local.WithConf())
	f.ETCD.Deps.StatusCheck = nil
	connectors.InjectKVDBSync(&f.ETCDDataSync, &f.ETCD, f.ETCD.PluginName, f.FlavorLocal, &f.ResyncOrch)
	f.NodeIDDataSync = f.ETCDDataSync
	f.NodeIDDataSync.PluginInfraDeps = *f.InfraDeps("nodeid-datasync")
	f.NodeIDDataSync.Deps.PluginInfraDeps.ServiceLabel = servicelabel.OfDifferentAgent(ksr.MicroserviceLabel)
	f.PolicyDataSync = f.ETCDDataSync
	f.PolicyDataSync.PluginInfraDeps = *f.InfraDeps("policy-datasync")
	f.PolicyDataSync.Deps.PluginInfraDeps.ServiceLabel = servicelabel.OfDifferentAgent(ksr.MicroserviceLabel)
	f.ServiceDataSync = f.ETCDDataSync
	f.ServiceDataSync.PluginInfraDeps = *f.InfraDeps("service-datasync")
	f.ServiceDataSync.Deps.PluginInfraDeps.ServiceLabel = servicelabel.OfDifferentAgent(ksr.MicroserviceLabel)

	f.KVProxy.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("kvproxy")
	f.KVProxy.Deps.KVDB = &f.ETCDDataSync

	f.Stats.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("stats")
	f.Stats.Deps.Contiv = &f.Contiv
	f.Stats.Deps.Prometheus = &f.Prometheus

	// Mutex for synchronizing watching events
	var watchEventsMutex sync.Mutex

	f.GoVPP.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("govpp", local.WithConf())
	f.Linux.Watcher = &datasync.CompositeKVProtoWatcher{Adapters: []datasync.KeyValProtoWatcher{&f.KVProxy, local_sync.Get()}}
	f.Linux.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("linux", local.WithConf())
	f.Linux.Deps.WatchEventsMutex = &watchEventsMutex

	f.VPP.Watch = &datasync.CompositeKVProtoWatcher{Adapters: []datasync.KeyValProtoWatcher{&f.KVProxy, local_sync.Get()}}
	f.VPP.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("default-plugins", local.WithConf())
	f.VPP.Deps.Linux = &f.Linux
	f.VPP.Deps.GoVppmux = &f.GoVPP
	f.VPP.Deps.PublishStatistics = &datasync.CompositeKVProtoWriter{Adapters: []datasync.KeyProtoValWriter{&f.Stats}}
	f.VPP.Deps.IfStatePub = &datasync.CompositeKVProtoWriter{Adapters: []datasync.KeyProtoValWriter{&devNullWriter{}}}
	f.VPP.Deps.WatchEventsMutex = &watchEventsMutex
	f.VPP.DisableResync(acl.KeyPrefix(), nat.GlobalConfigPrefix(), nat.DNatPrefix())

	f.VPPrest.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("rest")
	f.VPPrest.Deps.HTTPHandlers = &f.HTTP
	f.VPPrest.Deps.GoVppmux = &f.GoVPP

	f.Telemetry.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("telemetry-plugin")
	f.Telemetry.Deps.Prometheus = &f.Prometheus
	f.Telemetry.Deps.GoVppmux = &f.GoVPP

	grpc.DeclareGRPCPortFlag("grpc")
	grpcInfraDeps := f.FlavorLocal.InfraDeps("grpc", local.WithConf())
	f.GRPC.Deps.Log = grpcInfraDeps.Log
	f.GRPC.Deps.PluginName = grpcInfraDeps.PluginName
	f.GRPC.Deps.PluginConfig = grpcInfraDeps.PluginConfig

	f.Contiv.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("cni-grpc")
	f.Contiv.Deps.GRPC = &f.GRPC
	f.Contiv.Deps.Proxy = &f.KVProxy
	f.Contiv.Deps.GoVPP = &f.GoVPP
	f.Contiv.Deps.VPP = &f.VPP
	f.Contiv.Deps.Resync = &f.ResyncOrch
	f.Contiv.Deps.ETCD = &f.ETCD
	f.Contiv.Deps.Watcher = &f.NodeIDDataSync
	f.Contiv.Deps.PluginConfig = config.ForPlugin("contiv", ContivConfigPath, ContivConfigPathUsage)

	f.Policy.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("policy")
	f.Policy.Deps.Resync = &f.ResyncOrch
	f.Policy.Deps.Watcher = &f.PolicyDataSync
	f.Policy.Deps.Contiv = &f.Contiv
	f.Policy.Deps.GoVPP = &f.GoVPP
	f.Policy.Deps.VPP = &f.VPP

	f.Service.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("service")
	f.Service.Deps.Resync = &f.ResyncOrch
	f.Service.Deps.Watcher = &f.ServiceDataSync
	f.Service.Deps.Contiv = &f.Contiv
	f.Service.Deps.VPP = &f.VPP
	f.Service.Deps.GoVPP = &f.GoVPP
	f.Service.Deps.Stats = &f.Stats

	f.ResyncOrch.PluginLogDeps = *f.LogDeps("resync-orch")

	// we don't want to publish status to etcd
	f.StatusCheck.Transport = nil

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

// withPluginsOpt is return value of vppLocal.WithPlugins() utility
// to easily define new plugins for the agent based on FlavorContiv.
type withPluginsOpt struct {
	callback func(local *FlavorContiv) []*core.NamedPlugin
}

// OptionMarkerCore is just for marking implementation that it implements this interface
func (opt *withPluginsOpt) OptionMarkerCore() {}

// Plugins methods is here to implement core.WithPluginsOpt go interface
// <flavor> is a callback that uses flavor input for dependency injection
// for custom plugins (returned as NamedPlugin)
func (opt *withPluginsOpt) Plugins(flavors ...core.Flavor) []*core.NamedPlugin {
	for _, flavor := range flavors {
		if f, ok := flavor.(*FlavorContiv); ok {
			return opt.callback(f)
		}
	}

	panic("wrong usage of contiv.WithPlugin() for other than FlavorContiv")
}
