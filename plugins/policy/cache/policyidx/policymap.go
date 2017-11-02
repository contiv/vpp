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

package policyidx

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
)

const (
	policyPodLabelKey     = "policyPodLabelKey"
	policyIngressLabelKey = "policyIngressLabelKey"
	policyEgressLabelKey  = "policyEgressLabelKey"
)

// ConfigIndex implements a cache for configured policies. Primary index is policyID.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, IndexFunction)}
}

// RegisterPolicy adds new entry into the Policy mapping
func (ci *ConfigIndex) RegisterPolicy(policyID string, data *policymodel.Policy) {
	ci.mapping.Put(policyID, data)
}

// UnregisterPolicy removes an entry from the Policy mapping given a policyID
func (ci *ConfigIndex) UnregisterPolicy(policyID string) (found bool, data *policymodel.Policy) {
	d, found := ci.mapping.Delete(policyID)
	if found {
		if data, ok := d.(*policymodel.Policy); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPolicy looks up entry in the Policy mapping given a policyID.
func (ci *ConfigIndex) LookupPolicy(policyID string) (found bool, data *policymodel.Policy) {
	d, found := ci.mapping.GetValue(policyID)
	if found {
		if data, ok := d.(*policymodel.Policy); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPolicyByLabelSelector performs lookup based on secondary index policyLabelSelector.
func (ci *ConfigIndex) LookupPolicyByLabelSelector(policyLabelSelector string) (policyIDs []string) {
	return ci.mapping.ListNames(policyPodLabelKey, policyLabelSelector)
}

// LookupIngressLabelSelector performs lookup based on secondary index ingressLabelSelector.
func (ci *ConfigIndex) LookupIngressLabelSelector(ingressLabelSelector string) (policyIDs []string) {
	return ci.mapping.ListNames(policyIngressLabelKey, ingressLabelSelector)
}

// LookupEgressLabelSelector performs lookup based on secondary index egressLabelSelector.
func (ci *ConfigIndex) LookupEgressLabelSelector(egressLabelSelector string) (policyIDs []string) {
	return ci.mapping.ListNames(policyEgressLabelKey, egressLabelSelector)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (policyIDs []string) {
	return ci.mapping.ListAllNames()
}

// IndexFunction creates secondary indexes.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	policyPodLabels := []string{}
	policyIngressLabels := []string{}
	policyEgressLabels := []string{}

	if config, ok := data.(*policymodel.Policy); ok && config != nil {
		for _, v := range config.Label {
			labelSelector := v.Key + v.Value
			policyPodLabels = append(policyPodLabels, labelSelector)
		}
		res[policyPodLabelKey] = policyPodLabels
		for _, v1 := range config.IngressRule {
			for _, v2 := range v1.From {
				ingressLabels := v2.Pods.MatchLabel
				for _, v3 := range ingressLabels {
					labelSelector := v3.Key + v3.Value
					policyIngressLabels = append(policyIngressLabels, labelSelector)
				}
			}
		}
		res[policyIngressLabelKey] = policyIngressLabels
		for _, v1 := range config.EgressRule {
			for _, v2 := range v1.To {
				egressLabels := v2.Pods.MatchLabel
				for _, v3 := range egressLabels {
					labelSelector := v3.Key + v3.Value
					policyEgressLabels = append(policyEgressLabels, labelSelector)
				}
			}
		}
		res[policyEgressLabelKey] = policyEgressLabels
	}
	return res
}
