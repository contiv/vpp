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

// Package ksr defines flavor used for the contiv-ksr agent.
package ksr

import (
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/flavors/connectors"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/flavors/rpc"
)

const (
	// MicroserviceLabel is the microservice label used by contiv-ksr.
	MicroserviceLabel = "contiv-ksr"

	// KubeConfigAdmin is the default location of kubeconfig with admin credentials.
	KubeConfigAdmin = "/etc/kubernetes/admin.conf"

	// KubeConfigUsage explains the purpose of 'kube-config' flag.
	KubeConfigUsage = "Path to the kubeconfig file to use for the client connection to K8s cluster"
)

// FlavorKsr glues together multiple plugins to watch selected k8s
// resources and causes all changes to be reflected in a given store.
type FlavorKsr struct {
	// Local flavor is used to access the Infra (logger, service label, status check)
	*local.FlavorLocal
	// RPC flavor for REST-based management.
	*rpc.FlavorRPC
	// Plugins for access to ETCD data store.
	ETCD         etcdv3.Plugin
	ETCDDataSync kvdbsync.Plugin
	// Kubernetes State Reflector plugin works as a reflector for policies, pods
	// and namespaces.
	Ksr ksr.Plugin

	injected bool
}

// Inject sets inter-plugin references.
func (f *FlavorKsr) Inject() (allReadyInjected bool) {
	if f.injected {
		return false
	}
	f.injected = true

	if f.FlavorLocal == nil {
		f.FlavorLocal = &local.FlavorLocal{}
	}
	f.FlavorLocal.Inject()
	f.FlavorLocal.ServiceLabel.MicroserviceLabel = MicroserviceLabel
	if f.FlavorRPC == nil {
		f.FlavorRPC = &rpc.FlavorRPC{FlavorLocal: f.FlavorLocal}
	}
	f.FlavorRPC.Inject()

	f.ETCD.Deps.PluginInfraDeps = *f.InfraDeps("etcdv3", local.WithConf())
	connectors.InjectKVDBSync(&f.ETCDDataSync, &f.ETCD, f.ETCD.PluginName, f.FlavorLocal, nil)

	f.Ksr.Deps.PluginInfraDeps = *f.FlavorLocal.InfraDeps("ksr")
	// Reuse ForPlugin to define configuration file for 3rd party library (k8s client).
	f.Ksr.Deps.KubeConfig = config.ForPlugin("kube", KubeConfigAdmin, KubeConfigUsage)
	f.Ksr.Deps.Publish = &f.ETCDDataSync

	return true
}

// Plugins combines all plugins in the flavor into a slice.
func (f *FlavorKsr) Plugins() []*core.NamedPlugin {
	f.Inject()
	return core.ListPluginsInFlavor(f)
}
