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

package policy

import (
	"github.com/contiv/vpp/plugins/ksr/model/ksrkey"
)

const (
	// PolicyKeyword defines the keyword identifying Network policy data.
	PolicyKeyword = "policy"
)

// KeyPrefix returns the key prefix identifying all K8s policies in the
// data store.
func KeyPrefix() string {
	return ksrkey.KeyPrefix(PolicyKeyword)
}

// ParsePolicyFromKey parses policy and namespace ids from the associated
// data-store key.
func ParsePolicyFromKey(key string) (policy string, namespace string, err error) {
	return ksrkey.ParseNameFromKey(PolicyKeyword, key)
}

// Key returns the key under which a given K8s policy is stored in the
// data store.
func Key(name string, namespace string) string {
	return ksrkey.Key(PolicyKeyword, name, namespace)
}
