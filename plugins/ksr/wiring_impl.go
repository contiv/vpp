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

package ksr

import (
	"fmt"
	"github.com/contiv/vpp/wiring"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
)

const (
	defaultName = "ksr"
	packageName = "ksr"
)

const (
	// KubeConfigAdmin is the default location of kubeconfig with admin credentials.
	KubeConfigAdmin = "/etc/kubernetes/admin.conf"

	// KubeConfigUsage explains the purpose of 'kube-config' flag.
	KubeConfigUsage = "Path to the kubeconfig file to use for the client connection to K8s cluster"
)

// Wire implements wiring.Wireable allowing us to use Wiring rather than Flavors
// to configure Plugin Dependencies.
func (plugin *Plugin) Wire(wiring wiring.Wiring) error {
	if wiring == nil {
		wiring = plugin.DefaultWiring(false)
	}
	err := wiring(plugin)
	return err
}

// Name implement wiring.Named
func (plugin *Plugin) Name() string {
	return string(plugin.Deps.PluginName)
}

// DefaultWiring implements wiring.DefaultWirable allowing us to get a fully wired version of this file
// without having to specify any wiring.
func (plugin *Plugin) DefaultWiring(overwrite bool) wiring.Wiring {
	return DefaultWiring(overwrite)
}

// DefaultWiring creates a DefaultWiring for the Plugin.  If overwrite is true, it will overwrite any exiting
// dependencies with Default values.  If overwrite is false, any already set dependency will be unchanged
func DefaultWiring(overwrite bool) wiring.Wiring {
	ret := func(plugin core.Plugin) error {

		p, ok := plugin.(*Plugin)
		if ok {
			if err := p.Wire(WithName(overwrite)); err != nil {
				return err
			}
			if err := p.Wire(WithLog(overwrite)); err != nil {
				return err
			}
			if err := p.Wire(WithPluginConfig(overwrite)); err != nil {
				return err
			}
			if err := p.Wire(WithKubeConfig(overwrite)); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithNamePrefix wires a PluginName for the Plugin
// If overwrite is false, existing values will not be overwritten
// If name is provided, that will be configured as the prefix to PluginName
func WithNamePrefix(overwrite bool, name ...string) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			if overwrite || p.PluginName == "" {
				p.Wire(WithName(false)) // Make sure worst case we have the Default name
				if len(name) > 0 {
					p.PluginName = core.PluginName(name[0] + string(p.PluginName))
				}
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithName wires a PluginName for the Plugin
// If overwrite is false, existing values will not be overwritten
// If name is provided, that will be configured as the PluginName, otherwise a default will be used
func WithName(overwrite bool, name ...string) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			if overwrite || p.PluginName == "" {
				if len(name) > 0 {
					p.PluginName = core.PluginName(name[0])
				} else {
					p.PluginName = core.PluginName(defaultName)
				}
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithLog returns a wiring that sets the Log dependency of the Plugin
// If overwrite is false, WithLog will leave unchanged any existing Log wired in
// If a log value is provided, it will be wired in, otherwise, a default will be
// generated and wired in
func WithLog(overwrite bool, log ...logging.PluginLogger) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			if overwrite || p.Log == nil {
				if len(log) > 0 {
					p.Log = log[0]
				} else {
					p.Log = logging.ForPlugin(p.Name(), logrus.NewLogRegistry())
				}
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithLogFactory wires a Log dependency generated from the LogFactory (if one is provided)
// If overwrite is false, existing values will not be overwritten
// If a factory is provided, it will be used, otherwise, a default LogFactory will be generated and used
func WithLogFactory(overwrite bool, factory ...logging.LogFactory) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			err := p.Wire(WithLog(overwrite, logging.ForPlugin(p.Name(), logrus.NewLogRegistry())))
			return err
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithPluginConfig wires in a PluginConfig for the plugin
// If overwrite is false, existing values will not be overwritten
// If cfg is provided, that will be configured as the PluginConfig, otherwise a default will be used
func WithPluginConfig(overwrite bool, cfg ...config.PluginConfig) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			if len(cfg) > 0 {
				p.PluginConfig = cfg[0]
			} else {
				if err := p.Wire(WithName(false)); err != nil {
					return err
				}
				if overwrite || p.PluginConfig == nil {
					p.PluginConfig = config.ForPlugin(p.Name())
				}
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

// WithPluginConfig wires in a PluginConfig for the plugin
// If overwrite is false, existing values will not be overwritten
// If cfg is provided, that will be configured as the PluginConfig, otherwise a default will be used
func WithKubeConfig(overwrite bool, cfg ...config.PluginConfig) wiring.Wiring {
	ret := func(plugin core.Plugin) error {
		p, ok := plugin.(*Plugin)
		if ok {
			if len(cfg) > 0 {
				p.PluginConfig = cfg[0]
			} else {
				if err := p.Wire(WithName(false)); err != nil {
					return err
				}
				if overwrite || p.PluginConfig == nil {
					p.KubeConfig = config.ForPlugin("kube", KubeConfigAdmin, KubeConfigUsage)
				}
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}

//func WithPublish(overwrite bool,publish...*kvdbsync.Plugin) {
//	ret := func(plugin core.Plugin) error {
//		p, ok := plugin.(*Plugin)
//		if ok {
//			if len(publish) > 0 {
//				p.Publish = publish[0]
//			} else {
//				pub := &kvdbsync.Plugin{}
//				pub.Wire(nil)
//				p.Publish = pub
//
//			}
//		}
//	}
//}



