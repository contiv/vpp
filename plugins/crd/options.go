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

package crd

import (
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/logging"
)

const (
	// ConfigFlagName is name of the flag that defines kubeconfig location
	ConfigFlagName = "kube-config"

	// KubeConfigAdmin is the default location of kubeconfig with admin credentials.
	KubeConfigAdmin = "/etc/kubernetes/admin.conf"

	// KubeConfigUsage explains the purpose of 'kube-config' flag.
	KubeConfigUsage = "Path to the kubeconfig file to use for the client connection to K8s cluster"
)

// DefaultPlugin is default instance of Plugin.
var DefaultPlugin = *NewPlugin()

// NewPlugin creates a new Plugin with the provides Options
func NewPlugin(opts ...Option) *Plugin {
	p := &Plugin{}

	p.PluginName = "crd"
	p.Resync = &resync.DefaultPlugin
	for _, o := range opts {
		o(p)
	}

	if p.Deps.Log == nil {
		p.Deps.Log = logging.ForPlugin(p.String())
	}

	if p.Deps.KubeConfig == nil {
		p.Deps.KubeConfig = config.ForPlugin(p.String(), config.WithCustomizedFlag(ConfigFlagName, KubeConfigAdmin, KubeConfigUsage),
			config.WithExtraFlags(func(flags *config.FlagSet) {
				flags.Bool("verbose", false,
					"output & logging verbosity; true = log debug, false = log error.")
			}))
	}

	return p
}

// Option is a function that acts on a Plugin to inject Dependencies or configuration
type Option func(*Plugin)

// UseDeps returns Option that can inject custom dependencies.
func UseDeps(cb func(*Deps)) Option {
	return func(p *Plugin) {
		cb(&p.Deps)
	}
}
