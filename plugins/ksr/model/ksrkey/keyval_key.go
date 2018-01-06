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
	// KsrPrefix defines the common prefix for all K8s items that KSR stores
	// in the data store.
	KsrPrefix = "k8s"
	// NamespaceId defines keyword identifying a given K8s item's namespace".
	NamespaceId = "namespace"
)

// KeyPrefix returns the common prefix for all K8s items of a given data type.
func KeyPrefix(keyType string) string {
	return KsrPrefix + "/" + keyType
}

// Key returns the key under which a configuration for a given K8s item
// should be stored in the data-store.
func Key(keyType string, name string, namespace string) string {
	return KeyPrefix(keyType) + "/" + name + "/" + NamespaceId + "/" + namespace
}

// ParseServiceFromKey parses pod and namespace ids from the associated
// data-store key.
func ParseServiceFromKey(keyType string, key string) (pod string, namespace string, err error) {
	keywords := strings.Split(key, "/")
	if len(keywords) == 5 && keywords[0] == KsrPrefix && keywords[1] == keyType && keywords[3] == NamespaceId {
		return keywords[2], keywords[4], nil
	}
	return "", "", fmt.Errorf("invalid format of the key %s", key)
}
