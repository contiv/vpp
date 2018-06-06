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

package wiring

import (
	"fmt"
	"time"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logrus"
)

// Convenience method for getting a new agent from a Plugins with
// Logger logrus.DefaultLogger and MaxStartupTimeout 15* time.Second
func newAgentFromPlugins(plugins ...*core.NamedPlugin) *core.Agent {
	return core.NewAgentDeprecated(logrus.DefaultLogger(),
		15*time.Second,
		plugins...)
}

// NamePlugin is a convenience function to create a NamedPlugin from a plugin and a name
func NamePlugin(plugin core.Plugin, name string) *core.NamedPlugin {
	return &core.NamedPlugin{
		PluginName: core.PluginName(name),
		Plugin:     plugin,
	}
}

// ComposeWirings composes a list of Wirings into a single Wiring that will apply them in the order provided
// This is really really handy when you want to simply mutate the DefaultWiring of a Plugin
// rather than taking full responsiblity for all of its wiring. Example, you could have a
// Wiring customWiring that just tweaks a single dependency:
//
// wiring := wiring.ComposeWiring(plugin.DefaultWiring,customWiring)
// plugin.wire(wiring)
func ComposeWirings(wiring ...Wiring) Wiring {
	ret := func(plugin core.Plugin) (err error) {
		for _, v := range wiring {
			err := v(plugin)
			if err != nil {
				return err
			}
		}
		return err
	}
	return ret
}

// NewAgent is a convenience method to create a NewAgent from a plugin that is Named and Wirable
// Optionally you can provide a list of wirings to be composed an applied to the plugin
// If no wirings are provided and the plugin is DefaultWirable, the DefaultWiring will be
// applied.  This lets you get an agent with a single simple call:
//
// agent,err := wiring.NewAgent(plugin)
//
// An agent with a custom wiring for the plugin can be applied with a single simple call:
//
// agent,err := wiring.NewAgent(plugin, customWiring)
func NewAgent(plugin NamedWirablePlugin, wiring ...Wiring) (agent *core.Agent, err error) {
	if plugin == nil {
		return nil, fmt.Errorf("Cannot construct an Agent for nil plugin")
	}

	wiring = append(wiring, plugin.DefaultWiring(false))

	err = plugin.Wire(ComposeWirings(wiring...))
	if err != nil {
		return nil, err
	}

	np := NamePlugin(plugin, plugin.Name())
	return newAgentFromPlugins(np), err
}

// EventLoopWithInterrupt is a convenience function to run an EventLoopWithInterupt from a single plugin, provided its Wirable and Named
// Optionally you can provide a list of wirings to be composed an applied to the plugin
// If no wirings are provided and the plugin is DefaultWirable, the DefaultWiring will be
// applied.  This lets you get a running EventLoopWithInterupt  in a single simple call:
//
// err := wiring.EventLoopWithInterupt(plugin)
//
// An EventLoop for a plugin with a custom wiring started with a single simple call:
//
// err := wiring.EventLoopWithInterupt(plugin, customWiring)
//
func EventLoopWithInterrupt(plugin NamedWirablePlugin, closeChan chan struct{}, wiring ...Wiring) error {
	agent, err := NewAgent(plugin, wiring...)
	if err != nil {
		return err
	}
	return core.EventLoopWithInterrupt(agent, closeChan)
}

// Run is a convenience function to run an EventLoop from a single plugin, provided its Wirable and Named
// Optionally you can provide a list of wirings to be composed an applied to the plugin
// If no wirings are provided and the plugin is DefaultWirable, the DefaultWiring will be
// applied.  This lets you get a running MonitorableEventLoopWithInterupt  in a single simple call:
//
// readyCh,errCh := wiring.EventLoop(plugin,closeCh)
//
// An EventLoop for a plugin with a custom wiring started with a single simple call:
//
// readyCh,errCh  := wiring.EventLoop(plugin, closeCh,customWiring)
//func Run(plugin NamedWirablePlugin, closeChan chan struct{}, wiring ...Wiring) (<-chan struct{}, <-chan error) {
//	agent, err := NewAgent(plugin, wiring...)
//	if err != nil {
//		errCh := make(chan error, 1)
//		defer close(errCh)
//		readyCh := make(chan struct{})
//		return readyCh, errCh
//	}
//	return core.Run(agent, closeChan)
//}
