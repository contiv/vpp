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

package pod

import (
	"github.com/contiv/vpp/plugins/ksr/model/ksrkey"
)

const (
	// PodKeyword defines the keyword identifying Pod data.
	PodKeyword = "pod"
)

// KeyPrefix returns the key prefix identifying all K8s Pods in the
// data store.
func KeyPrefix() string {
	return ksrkey.KeyPrefix(PodKeyword)
}

// ParsePodFromKey parses pod and namespace ids from the associated
// data-store key.
func ParsePodFromKey(key string) (pod string, namespace string, err error) {
	return ksrkey.ParseNameFromKey(PodKeyword, key)
}

// Key returns the key under which a given K8s pod is stored in the
// data store.
func Key(name string, namespace string) string {
	return ksrkey.Key(PodKeyword, name, namespace)
}
