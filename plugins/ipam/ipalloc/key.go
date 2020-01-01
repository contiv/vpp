// Copyright (c) 2018 Cisco and/or its affiliates.
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

package ipalloc

import (
	"strings"
)

// Keyword defines the keyword identifying custom IP allocation data.
const Keyword = "custom-ipam"

// KeyPrefix return prefix where all service function chain configs are persisted.
func KeyPrefix() string {
	return Keyword + "/"
}

// Key returns the key under which custom IPAM data of a pod should be stored in the data-store.
func Key(podName, podNamespace string) string {
	return KeyPrefix() + podName + "/" + podNamespace
}

// ParseKey parses pod name and namespace from key identifying custom IP allocation data of a pod.
// Returns empty strings if parsing fails (invalid key).
func ParseKey(key string) (podName, podNamespace string) {
	if strings.HasPrefix(key, KeyPrefix()) {
		parts := strings.Split(strings.TrimPrefix(key, KeyPrefix()), "/")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return
}
