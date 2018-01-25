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
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/stn"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/model/l3"
	"time"
)

const podNameKey = "podNameKey"
const podNamespaceKey = "podNamespaceKey"
const podRelatedIfsKey = "podRelatedIfsKey"

// Config groups applied configuration for a container
type Config struct {
	// PodName from the CNI request
	PodName string
	// PodNamespace from the CNI request
	PodNamespace string
	// Veth1 one end end of veth pair that is in the given container namespace.
	// Nil if TAPs are used instead.
	Veth1 *linux_intf.LinuxInterfaces_Interface
	// Veth2 is the other end of veth pair in the default namespace
	// Nil if TAPs are used instead.
	Veth2 *linux_intf.LinuxInterfaces_Interface
	// VppIf is AF_PACKET/TAP interface connecting pod to VPP
	VppIf *vpp_intf.Interfaces_Interface
	// Loopback interface associated with the pod.
	// Nil if VPP TCP stack is disabled.
	Loopback *vpp_intf.Interfaces_Interface
	// StnRule is STN rule used to "punt" any traffic via VETHs/TAPs with no match in VPP TCP stack.
	// Nil if VPP TCP stack is disabled.
	StnRule *stn.StnRule
	// AppNamespace is the application namespace associated with the pod.
	// Nil if VPP TCP stack is disabled.
	AppNamespace *vpp_l4.AppNamespaces_AppNamespace
	// VppARPEntry is ARP entry configured in VPP to route traffic from VPP to pod.
	VppARPEntry *vpp_l3.ArpTable_ArpTableEntry
	// PodARPEntry is ARP entry configured in the pod to route traffic from pod to VPP.
	PodARPEntry *linux_l3.LinuxStaticArpEntries_ArpEntry
	// VppRoute is the route from VPP to the container
	VppRoute *l3.StaticRoutes_Route
	// PodLinkRoute is the route from pod to the default gateway.
	PodLinkRoute *linux_l3.LinuxStaticRoutes_Route
	// PodDefaultRoute is the default gateway for the pod.
	PodDefaultRoute *linux_l3.LinuxStaticRoutes_Route
}

// ChangeEvent represents a notification about change in ConfigIndex delivered to subscribers
type ChangeEvent struct {
	idxmap.NamedMappingEvent
	Value *Config
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
func (ci *ConfigIndex) LookupContainer(containerID string) (data *Config, found bool) {
	d, found := ci.mapping.GetValue(containerID)
	if found {
		if data, ok := d.(*Config); ok {
			return data, found
		}
	}
	return nil, false
}

// LookupPodName performs lookup based on secondary index podName.
func (ci *ConfigIndex) LookupPodName(podName string) (containerIDs []string) {
	return ci.mapping.ListNames(podNameKey, podName)
}

// LookupPodNamespace performs lookup based on secondary index podNamespace.
func (ci *ConfigIndex) LookupPodNamespace(podNamespace string) (containerIDs []string) {
	return ci.mapping.ListNames(podNamespaceKey, podNamespace)
}

// LookupPodIf performs lookup based on secondary index podRelatedIfs.
func (ci *ConfigIndex) LookupPodIf(ifname string) (containerIDs []string) {
	return ci.mapping.ListNames(podRelatedIfsKey, ifname)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (containerIDs []string) {
	return ci.mapping.ListAllNames()
}

// Watch subscribe to monitor changes in ConfigIndex
func (ci *ConfigIndex) Watch(subscriber core.PluginName, callback func(ChangeEvent)) error {
	return ci.mapping.Watch(subscriber, func(ev idxmap.NamedMappingGenericEvent) {
		if cfg, ok := ev.Value.(*Config); ok {
			callback(ChangeEvent{NamedMappingEvent: ev.NamedMappingEvent, Value: cfg})
		}
	})
}

// IndexFunction creates secondary indexes. Currently podName, podNamespace and name of the interfaces with pod are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	if config, ok := data.(*Config); ok && config != nil {
		res[podNameKey] = []string{config.PodName}
		res[podNamespaceKey] = []string{config.PodNamespace}
		if config.VppIf != nil {
			res[podRelatedIfsKey] = []string{config.VppIf.Name}
		}
		if config.Loopback != nil {
			res[podRelatedIfsKey] = append(res[podRelatedIfsKey], config.Loopback.Name)
		}
	}
	return res
}

// ToChan creates a callback that can be passed to the Watch function
// in order to receive notifications through a channel. If the notification
// can not be delivered until timeout, it is dropped.
func ToChan(ch chan ChangeEvent) func(dto ChangeEvent) {
	return func(dto ChangeEvent) {
		select {
		case ch <- dto:
		case <-time.After(time.Second):
		}
	}
}
