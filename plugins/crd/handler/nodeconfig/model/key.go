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

package model

import "github.com/contiv/vpp/plugins/ksr/model/ksrkey"

// KeyPrefix return prefix where all node configs are persisted.
func KeyPrefix() string {
	return ksrkey.KsrK8sPrefix + "/nodeconfig/"
}

// Key returns the key for configuration of a given node.
func Key(node string) string {
	return KeyPrefix() + node
}