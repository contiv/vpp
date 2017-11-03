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

package podidx

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
)

const (
	podLabelSelectorKey   = "podLabelSelectorKey"
	podKeySelectorKey     = "podKeySelectorKey"
	podNSKeySelectorKey   = "podNamespaceKey"
	podNSLabelSelectorKey = "podNamespaceLabelKey"
	podNamespace          = "podNamespace"
)

// ConfigIndex implements a cache for configured policies. Primary index is PolicyName.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, IndexFunction)}
}

// RegisterPod adds new pod entry into the mapping
func (ci *ConfigIndex) RegisterPod(podID string, data *podmodel.Pod) {
	// make the convertion here id -> string
	ci.mapping.Put(podID, data)
}

// UnregisterPod removes a pod entry from the mapping
func (ci *ConfigIndex) UnregisterPod(podID string) (found bool, data *podmodel.Pod) {
	d, found := ci.mapping.Delete(podID)
	if found {
		if data, ok := d.(*podmodel.Pod); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPod looks up an entry in the Pod map given a PodID
func (ci *ConfigIndex) LookupPod(podID string) (found bool, data *podmodel.Pod) {
	d, found := ci.mapping.GetValue(podID)
	if found {
		if data, ok := d.(*podmodel.Pod); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPodsByLabelSelector performs lookup based on secondary index podLabelSelector.
func (ci *ConfigIndex) LookupPodsByLabelSelector(podLabelSelector string) (podIDs []string) {
	return ci.mapping.ListNames(podLabelSelectorKey, podLabelSelector)
}

// LookupPodsByLabelKey performs lookup based on secondary index podKeySelector.
func (ci *ConfigIndex) LookupPodsByLabelKey(podKeySelector string) (podIDs []string) {
	return ci.mapping.ListNames(podKeySelectorKey, podKeySelector)
}

// LookupPodsByNamespace performs lookup based on secondary index podNamespace.
func (ci *ConfigIndex) LookupPodsByNamespace(podNamespace string) (podIDs []string) {
	return ci.mapping.ListNames(podNamespace, podNamespace)
}

// LookupPodsByNSLabelKey performs lookup based on secondary index podNamespace + podLabelSelector.
func (ci *ConfigIndex) LookupPodsByNSLabelSelector(podNSLabelSelector string) (podIDs []string) {
	return ci.mapping.ListNames(podNSLabelSelectorKey, podNSLabelSelector)
}

// LookupPodsByNSKey performs lookup based on secondary index podNamespace + podLabelKey.
func (ci *ConfigIndex) LookupPodsByNSKey(podNSKeySelector string) (podIDs []string) {
	return ci.mapping.ListNames(podNSKeySelectorKey, podNSKeySelector)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (podIDs []string) {
	return ci.mapping.ListAllNames()
}

// IndexFunction creates secondary indexes. Currently podName and podNamespace fields are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	labels := []string{}
	keys := []string{}
	nsLabels := []string{}
	nsKeys := []string{}
	if config, ok := data.(*podmodel.Pod); ok && config != nil {
		for _, v := range config.Label {
			labelSelector := v.Key + "/" + v.Value
			nsLabelSelector := config.Namespace + "/" + labelSelector
			nsKeySelector := config.Namespace + "/" + v.Key

			labels = append(labels, labelSelector)
			keys = append(keys, v.Key)
			nsLabels = append(nsLabels, nsLabelSelector)
			nsKeys = append(nsKeys, nsKeySelector)
		}

		keys = removeDuplicates(keys)
		nsKeys = removeDuplicates(keys)

		res[podLabelSelectorKey] = labels
		res[podKeySelectorKey] = keys
		res[podNamespace] = []string{config.Namespace}
		res[podNSLabelSelectorKey] = nsLabels
		res[podNSKeySelectorKey] = nsKeys
	}
	return res
}

func removeDuplicates(el []string) []string {
	found := map[string]bool{}

	// Create a map of all unique elements.
	for v := range el {
		found[el[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key, _ := range found {
		result = append(result, key)
	}
	return result
}
