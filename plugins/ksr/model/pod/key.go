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
	// PodKeyword returns the key prefix identifying all K8s services in the
	// data store.
	PodKeyword = "pod"
)

// KeyPrefix returns the key prefix *template* used in the data-store
// to save the current state of every known K8s pod.
func KeyPrefix() string {
	return ksrkey.KeyPrefix(PodKeyword)
}

// ParseServiceFromKey parses pod and namespace ids from the associated
// data-store key.
func ParseServiceFromKey(key string) (service string, namespace string, err error) {
	return ksrkey.ParseServiceFromKey(PodKeyword, key)
}

// Key returns the key under which a given K8s service is stored in the
// data store.
func Key(name string, namespace string) string {
	return ksrkey.Key(PodKeyword, name, namespace)
}
