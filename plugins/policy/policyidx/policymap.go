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
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
)

const policyLabelSelectorKey = "policyLabelSelectorKey"

// Config groups applied policy in a container
type Config struct {
	PolicyName        string
	PolicyNamespace   string
	PolicyACL         *acl.AccessLists_Acl
	PolicyTypes       []string
	PolicyLabel       []*policymodel.Policy_Label
	PolicyIngressRule []*policymodel.Policy_IngressRule
}

// ConfigIndex implements a cache for configured policies. Primary index is PolicyName.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, IndexFunction)}
}

// RegisterPolicy adds new entry into the mapping
func (ci *ConfigIndex) RegisterPolicy(policyID string, data *Config) {
	ci.mapping.Put(policyID, data)
}

// UnregisterPolicy removes the entry from the mapping
func (ci *ConfigIndex) UnregisterPolicy(policyID string) (found bool, data *Config) {
	d, found := ci.mapping.Delete(policyID)
	if found {
		if data, ok := d.(*Config); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPolicy looks up entry in the policy based on policyName.
func (ci *ConfigIndex) LookupPolicy(policyID string) (found bool, data *Config) {
	d, found := ci.mapping.GetValue(policyID)
	if found {
		if data, ok := d.(*Config); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupPolicyLabelSelector performs lookup based on secondary index policyLabelSelector.
func (ci *ConfigIndex) LookupPolicyLabelSelector(policyLabelSelector string) (policyIDs []string) {
	return ci.mapping.ListNames(policyLabelSelectorKey, policyLabelSelector)
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (policyIDs []string) {
	return ci.mapping.ListAllNames()
}

// IndexFunction creates secondary indexes. Currently podName and podNamespace fields are indexed.
func IndexFunction(data interface{}) map[string][]string {
	res := map[string][]string{}
	if config, ok := data.(*Config); ok && config != nil {
		for _, v := range config.PolicyLabel {
			labelSelector := v.Key + v.Value
			res[policyLabelSelectorKey] = []string{labelSelector}
		}
	}
	return res
}
