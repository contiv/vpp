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

package ruleidx

import (
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
)

// Config groups applied policy in a container
type Config struct {
	ACLRule *acl.AccessLists_Acl // configuration sent to VPP
}

// ConfigIndex implements a cache for configured policies. Primary index is ruleID.
type ConfigIndex struct {
	mapping idxmap.NamedMappingRW
}

// NewConfigIndex creates new instance of ConfigIndex
func NewConfigIndex(logger logging.Logger, owner core.PluginName, title string) *ConfigIndex {
	return &ConfigIndex{mapping: mem.NewNamedMapping(logger, owner, title, nil)}
}

// RegisterRule adds new entry into the mapping
func (ci *ConfigIndex) RegisterRule(ruleID string, data *Config) {
	ci.mapping.Put(ruleID, data)
}

// UnregisterRule removes the entry from the mapping
func (ci *ConfigIndex) UnregisterRule(ruleID string) (found bool, data *Config) {
	d, found := ci.mapping.Delete(ruleID)
	if found {
		if data, ok := d.(*Config); ok {
			return found, data
		}
	}
	return false, nil
}

// LookupRule looks up entry in the rulemap.
func (ci *ConfigIndex) LookupRule(ruleID string) (found bool, data *Config) {
	d, found := ci.mapping.GetValue(ruleID)
	if found {
		if data, ok := d.(*Config); ok {
			return found, data
		}
	}
	return false, nil
}

// ListAll returns all registered names in the mapping.
func (ci *ConfigIndex) ListAll() (ruleID []string) {
	return ci.mapping.ListAllNames()
}
