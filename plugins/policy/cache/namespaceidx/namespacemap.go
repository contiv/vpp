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

package namespaceidx

import (
	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
	"github.com/contiv/vpp/plugins/policy/utils"
)

const (
	namespaceLabelSelectorKey = "namespaceLabelSelectorKey"
	namespaceKeySelectorKey = "namespaceKeySelectorKey"
	)

// ConfigIndex implements a cache for configured Namespaces. Primary index is PolicyName.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, IndexFunction)}
}

// RegisterNamespace adds new Namespace entry into the mapping
func (ci *ConfigIndex) RegisterNamespace(namespaceID string, data *namespacemodel.Namespace) {
	ci.mapping.Put(namespaceID, data)
}

// UnRegisterNamespace removes the Namespace entry from the mapping
func (ci *ConfigIndex) UnRegisterNamespace(namespaceID string) (found bool, data *namespacemodel.Namespace) {
	d, found := ci.mapping.Delete(namespaceID)
	if found {
		if data, ok := d.(*namespacemodel.Namespace); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupNamespace looks up the entry of a Namespace given a namespace ID
func (ci *ConfigIndex) LookupNamespace(namespaceID string) (found bool, data *namespacemodel.Namespace) {
	d, found := ci.mapping.GetValue(namespaceID)
	if found {
		if data, ok := d.(*namespacemodel.Namespace); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupNamespacesByLabelSelector performs lookup based on secondary index namespaceLabelSelector.
func (ci *ConfigIndex) LookupNamespacesByLabelSelector(namespaceLabelSelector string) (namespaceIDs []string) {
	return ci.mapping.ListNames(namespaceLabelSelectorKey, namespaceLabelSelector)
}

// LookupNamespacesByKey performs lookup based on secondary index podNamespace/podLabelKey.
func (ci *ConfigIndex) LookupNamespacesByKey(namespaceKeySelector string) (namespaceIDs []string) {
	return ci.mapping.ListNames(namespaceKeySelectorKey, namespaceKeySelector)
}

// ListAll returns all registered namespaces in the mapping.
func (ci *ConfigIndex) ListAll() (namespaceIDs []string) {
	return ci.mapping.ListAllNames()
}

// IndexFunction creates secondary indexes. Currently podName and podNamespace fields are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	labels := []string{}
	keys := []string{}

	if config, ok := data.(*namespacemodel.Namespace); ok && config != nil {
		for _, v := range config.Label {
			namespaceSelector := v.Key + "/" + v.Value
			labels = append(labels, namespaceSelector)
			keys = append(keys, v.Key)
		}
		keys = utils.RemoveDuplicates(keys)
		res[namespaceLabelSelectorKey] = labels
		res[namespaceKeySelectorKey] = keys
	}
	return res
}
