// Copyright (c) 2019 Cisco and/or its affiliates.
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

package model

import "github.com/contiv/vpp/plugins/ksr/model/ksrkey"

// Keyword defines the keyword identifying external interface data.
const Keyword = "external-interface"

// KeyPrefix return prefix where all external interface configs are persisted.
func KeyPrefix() string {
	return ksrkey.KsrK8sPrefix + "/" + Keyword + "/"
}

// Key returns the key for configuration of a given external interface.
func Key(iface string) string {
	return KeyPrefix() + iface
}
