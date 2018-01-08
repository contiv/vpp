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

package namespace

import (
	"fmt"
	"strings"

	"github.com/contiv/vpp/plugins/ksr/model/ksrkey"
)

const (
	// NamespaceKeyword is a key prefix under which the current state of every
	// known K8s namespace is stored.
	NamespaceKeyword = "namespace"
)

// KeyPrefix returns the key prefix used in the data-store to save
// the current state of every known K8s namespace.
func KeyPrefix() string {
	return ksrkey.KsrPrefix + "/" + NamespaceKeyword
}

// ParseNamespaceFromKey parses namespace id from the associated data-store key.
func ParseNamespaceFromKey(key string) (namespace string, err error) {
	keywords := strings.Split(key, "/")
	if len(keywords) == 3 && keywords[0] == ksrkey.KsrPrefix && keywords[1] == NamespaceKeyword {
		return keywords[2], nil
	}
	return "", fmt.Errorf("invalid format of the key %s", key)
}

// Key returns the key under which a configuration for the given
// namespace should be stored in the data-store.
func Key(namespace string) string {
	return KeyPrefix() + "/" + namespace
}
