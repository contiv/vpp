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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/container.proto

package containeridx

import (
	"time"

	"fmt"
	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
)

const podNameKey = "podNameKey"
const podNamespaceKey = "podNamespaceKey"
const podRelatedIfsKey = "podRelatedIfsKey"
const podRelatedAppNsKey = "podRelatedAppNsKey"

// Reader provides read API to ConfigIndex
type Reader interface {
	// LookupContainer looks up entry in the container based on containerID.
	LookupContainer(containerID string) (data *container.Persisted, found bool)

	// LookupPodName performs lookup based on secondary index podName.
	LookupPodName(podName string) (containerIDs []string)

	// LookupPodNamespace performs lookup based on secondary index podNamespace.
	LookupPodNamespace(podNamespace string) (containerIDs []string)

	// LookupPodIf performs lookup based on secondary index podRelatedIfs.
	LookupPodIf(ifname string) (containerIDs []string)

	// LookupPodAppNs performs lookup based on secondary index podRelatedAppNs.
	LookupPodAppNs(namespaceID string) (containerIDs []string)

	// ListAll returns all registered names in the mapping.
	ListAll() (containerIDs []string)

	// Watch subscribe to monitor changes in ConfigIndex
	Watch(subscriber string, callback func(ChangeEvent)) error
}

// ChangeEvent represents a notification about change in ConfigIndex delivered to subscribers
type ChangeEvent struct {
	idxmap.NamedMappingEvent
	Value *container.Persisted
}

// ConfigIndex implements a cache for configured containers. Primary index is containerID.
type ConfigIndex struct {
	logger  logging.Logger
	broker  keyval.ProtoBroker
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, title string, broker keyval.ProtoBroker) *ConfigIndex {
	ci := &ConfigIndex{mapping: mem.NewNamedMapping(logger, title, IndexFunction), broker: broker, logger: logger}
	ci.loadConfigureContainers()
	return ci
}

// RegisterContainer adds new entry into the mapping
func (ci *ConfigIndex) RegisterContainer(containerID string, data *container.Persisted) error {
	var err error
	if ci.broker != nil {
		err = ci.persistConfiguredContainer(data)
		if err != nil {
			return err
		}
	}
	ci.mapping.Put(containerID, data)
	return err
}

// UnregisterContainer removes the entry from the mapping
func (ci *ConfigIndex) UnregisterContainer(containerID string) (data *container.Persisted, found bool, err error) {
	d, found := ci.mapping.Delete(containerID)
	if !found {
		return nil, false, nil
	}
	if ci.broker != nil {
		err = ci.removePersistedConfiguredContainer(containerID)
		if err != nil {
			ci.mapping.Put(containerID, d)
			return nil, true, err
		}
	}
	if data, ok := d.(*container.Persisted); ok {
		return data, found, nil
	}
	return nil, found, fmt.Errorf("unknown data")
}

// LookupContainer looks up entry in the container based on containerID.
func (ci *ConfigIndex) LookupContainer(containerID string) (data *container.Persisted, found bool) {
	d, found := ci.mapping.GetValue(containerID)
	if found {
		if data, ok := d.(*container.Persisted); ok {
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

// LookupPodAppNs performs lookup based on secondary index podRelatedNs.
func (ci *ConfigIndex) LookupPodAppNs(namespaceID string) (containerIDs []string) {
	return ci.mapping.ListNames(podRelatedAppNsKey, namespaceID)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (containerIDs []string) {
	return ci.mapping.ListAllNames()
}

// Watch subscribe to monitor changes in ConfigIndex
func (ci *ConfigIndex) Watch(subscriber string, callback func(ChangeEvent)) error {
	return ci.mapping.Watch(subscriber, func(ev idxmap.NamedMappingGenericEvent) {
		if cfg, ok := ev.Value.(*container.Persisted); ok {
			callback(ChangeEvent{NamedMappingEvent: ev.NamedMappingEvent, Value: cfg})
		}
	})
}

// IndexFunction creates secondary indexes. Currently podName, podNamespace,
// and the associated interface/namespace are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	if config, ok := data.(*container.Persisted); ok && config != nil {
		res[podNameKey] = []string{config.PodName}
		res[podNamespaceKey] = []string{config.PodNamespace}
		if config.VppIfName != "" {
			res[podRelatedIfsKey] = []string{config.VppIfName}
		}
		if config.LoopbackName != "" {
			res[podRelatedIfsKey] = append(res[podRelatedIfsKey], config.LoopbackName)
		}
		if config.AppNamespaceID != "" {
			res[podRelatedAppNsKey] = []string{config.AppNamespaceID}
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
