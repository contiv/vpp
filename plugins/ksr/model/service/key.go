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

package service

import (
	"fmt"
	"strings"

	ns "github.com/contiv/vpp/plugins/ksr/model/namespace"
)

const (
	// ServicePrefix is a key prefix *template* under which the current state
	// of every known K8s pod is stored.
	ServicePrefix = "k8s/namespace/{namespace}/service/"
)

// KeyPrefix returns the key prefix *template* used in the data-store
// to save the current state of every known K8s pod.
func KeyPrefix() string {
	return ServicePrefix
}

// ParseServiceFromKey parses pod and namespace ids from the associated data-store
// key.
func ParseServiceFromKey(key string) (pod string, namespace string, err error) {
	if strings.HasPrefix(key, ns.KeyPrefix()) {
		suffix := strings.TrimPrefix(key, ns.KeyPrefix())
		components := strings.Split(suffix, "/")
		if len(components) == 3 && components[1] == "service" {
			return components[2], components[0], nil
		}
	}
	return "", "", fmt.Errorf("invalid format of the key %s", key)
}

// Key returns the key under which a configuration for the given K8s service
// should be stored in the data-store.
func Key(name string, namespace string) string {
	return strings.Replace(ServicePrefix, "{namespace}", namespace, 1) + name
}
