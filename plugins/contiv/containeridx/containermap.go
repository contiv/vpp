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

package containeridx

import (
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
)

const podNameKey = "podNameKey"
const podNamespaceKey = "podNamespaceKey"

// Config groups applied configuration for a container
type Config struct {
	// PodName from the CNI request
	PodName string
	// PodNamespace from the CNI request
	PodNamespace string
	// Veth1 one end end of veth pair that is in the given container namespace
	Veth1 *linux_intf.LinuxInterfaces_Interface
	// Veth2 is the other end of veth pair in the default namespace
	Veth2 *linux_intf.LinuxInterfaces_Interface
	// Afpacket/TAP interface connecting pod to VPP
	PodVppIf *vpp_intf.Interfaces_Interface
	// Route to the container
	Route *l3.StaticRoutes_Route
	// Application namespace index
	NsIndex uint32
}

// ConfigIndex implements a cache for configured containers. Primary index is containerID.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, IndexFunction)}
}

// RegisterContainer adds new entry into the mapping
func (ci *ConfigIndex) RegisterContainer(containerID string, data *Config) {
	ci.mapping.Put(containerID, data)
}

// UnregisterContainer removes the entry from the mapping
func (ci *ConfigIndex) UnregisterContainer(containerID string) (data *Config, found bool) {
	d, found := ci.mapping.Delete(containerID)
	if found {
		if data, ok := d.(*Config); ok {
			return data, found
		}
	}
	return nil, false
}

// LookupContainer looks up entry in the container based on containerID.
func (ci *ConfigIndex) LookupContainer(containerID string) (found bool, data *Config) {
	d, found := ci.mapping.GetValue(containerID)
	if found {
		if data, ok := d.(*Config); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPodName performs lookup based on secondary index podName.
func (ci *ConfigIndex) LookupPodName(podName string) (containerIDs []string) {
	return ci.mapping.ListNames(podNameKey, podName)
}

// LookupPodNamespace performs lookup based on secondary index podNamespace.
func (ci *ConfigIndex) LookupPodNamespace(podNamespace string) (containerIDs []string) {
	return ci.mapping.ListNames(podNamespaceKey, podNamespace)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (containerIDs []string) {
	return ci.mapping.ListAllNames()
}

// IndexFunction creates secondary indexes. Currently podName and podNamespace fields are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	if config, ok := data.(*Config); ok && config != nil {
		res[podNameKey] = []string{config.PodName}
		res[podNamespaceKey] = []string{config.PodNamespace}
	}
	return res
}
