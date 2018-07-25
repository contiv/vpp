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

// Package crd defines flavor used for the contiv-crd agent.
package crd

import (
	"os"

	"github.com/contiv/vpp/flavors/ksr"
	"github.com/contiv/vpp/plugins/crd"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/flavors/connectors"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/servicelabel"
)

const (
	// MicroserviceLabel is the microservice label used by contiv-crd.
	MicroserviceLabel = "contiv-crd"

	// KubeConfigUsage explains the purpose of 'kube-config' flag.
	KubeConfigUsage = "Path to the kubeconfig file to use for the client connection to K8s cluster"
)

// NewAgent returns a new instance of the Agent with plugins.
// It is an alias for core.NewAgent() to implicit use of the FlavorCrd
func NewAgent(opts ...core.Option) *core.Agent {
	return core.NewAgent(&FlavorCrd{}, opts...)
}

// WithPlugins for adding custom plugins to SFC Controller
// <listPlugins> is a callback that uses flavor input to
// inject dependencies for custom plugins that are in output
func WithPlugins(listPlugins func(local *FlavorCrd) []*core.NamedPlugin) core.WithPluginsOpt {
	return &withPluginsOpt{listPlugins}
}

// FlavorCrd glues together multiple plugins to watch selected k8s
// resources and causes all changes to be reflected in a given store.
type FlavorCrd struct {
	// Local flavor is used to access the Infra (logger, service label, status check)
	*local.FlavorLocal

	// Plugins for access to ETCD data store.
	ETCD         etcd.Plugin
	ETCDDataSync kvdbsync.Plugin
	CrdDataSync  kvdbsync.Plugin

	Crd crd.Plugin

	// resync should the last plugin in the flavor in order to give
	// the others enough time to register
	ResyncOrch resync.Plugin

	injected bool
}

// Inject sets inter-plugin references.
func (f *FlavorCrd) Inject() (allReadyInjected bool) {
	if f.injected {
		return false
	}
	f.injected = true

	if f.FlavorLocal == nil {
		f.FlavorLocal = &local.FlavorLocal{}
	}
	f.FlavorLocal.Inject()

	// KubeConfigAdmin is the default location of kubeconfig with admin credentials.
	KubeConfigAdmin := os.Getenv("HOME") + "/.kube/config"
	f.Crd.Deps.KubeConfig = config.ForPlugin("kube", KubeConfigAdmin, KubeConfigUsage)

	f.ETCD.Deps.PluginInfraDeps = *f.InfraDeps("etcd", local.WithConf())
	f.ETCD.Deps.StatusCheck = nil
	connectors.InjectKVDBSync(&f.ETCDDataSync, &f.ETCD, f.ETCD.PluginName, f.FlavorLocal, &f.ResyncOrch)

	f.CrdDataSync = f.ETCDDataSync
	f.CrdDataSync.PluginInfraDeps = *f.InfraDeps("crd-datasync")
	f.CrdDataSync.Deps.PluginInfraDeps.ServiceLabel = servicelabel.OfDifferentAgent(ksr.MicroserviceLabel)

	f.Crd.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("crd")
	f.Crd.Deps.Resync = &f.ResyncOrch
	f.Crd.Deps.Watcher = &f.CrdDataSync
	f.ResyncOrch.PluginLogDeps = *f.LogDeps("resync-orch")

	return true
}

// Plugins combines all plugins in the flavor into a slice.
func (f *FlavorCrd) Plugins() []*core.NamedPlugin {
	f.Inject()
	return core.ListPluginsInFlavor(f)
}

// withPluginsOpt is return value of vppLocal.WithPlugins() utility
// to easily define new plugins for the agent based on FlavorCrd.
type withPluginsOpt struct {
	callback func(local *FlavorCrd) []*core.NamedPlugin
}

// OptionMarkerCore is just for marking implementation that it implements this interface
func (opt *withPluginsOpt) OptionMarkerCore() {}

// Plugins methods is here to implement core.WithPluginsOpt go interface
// <flavor> is a callback that uses flavor input for dependency injection
// for custom plugins (returned as NamedPlugin)
func (opt *withPluginsOpt) Plugins(flavors ...core.Flavor) []*core.NamedPlugin {
	for _, flavor := range flavors {
		if f, ok := flavor.(*FlavorCrd); ok {
			return opt.callback(f)
		}
	}

	panic("wrong usage of crd.WithPlugin() for other than FlavorCrd")
}
