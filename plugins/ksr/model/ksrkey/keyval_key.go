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

package ksrkey

import (
	"fmt"
	"strings"
)

const (
	// KsrK8sPrefix defines the common prefix for all K8s items that KSR stores
	// in the data store.
	KsrK8sPrefix = "k8s"
	// KsrStsPrefix defines the prefix for the plugin status that KSR stores
	// in the data store.
	KsrStsPrefix = "status"
	// NamespaceID defines keyword identifying a given K8s item's namespace".
	NamespaceID = "namespace"
)

// KeyPrefix returns the common prefix for all K8s items of a given data type.
func KeyPrefix(keyType string) string {
	return KsrK8sPrefix + "/" + keyType + "/"
}

// Key returns the key under which a configuration for a given K8s item
// should be stored in the data-store.
func Key(keyType string, name string, namespace string) string {
	return KeyPrefix(keyType) + name + "/" + NamespaceID + "/" + namespace
}

// ParseNameFromKey parses item name and namespace ids from the associated
// data-store key.
func ParseNameFromKey(keyType string, key string) (name string, namespace string, err error) {
	keywords := strings.Split(key, "/")
	if len(keywords) == 5 && keywords[0] == KsrK8sPrefix && keywords[1] == keyType && keywords[3] == NamespaceID {
		return keywords[2], keywords[4], nil
	}
	return "", "", fmt.Errorf("invalid format of the key %s", key)
}
