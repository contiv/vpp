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

package vppnode

import (
	"strconv"
	"strings"
)

// Keyword defines the keyword identifying VppNode data.
const Keyword = "vppnode"

// KeyPrefix is a key prefix used in DB to store instances of VppNode,
// one for every node in the cluster.
const KeyPrefix = "allocatedIDs/"

// Key returns the key under which VppNode data for a node with the given ID
// should be stored in the data-store.
func Key(id uint32) string {
	return KeyPrefix + strconv.FormatUint(uint64(id), 10)
}

// ParseKey parses node ID from key identifying VppNode data.
// Returns 0 if parsing fails (invalid node ID).
func ParseKey(key string) (id uint32) {
	if strings.HasPrefix(key, KeyPrefix) {
		nodeID, err := strconv.Atoi(strings.TrimPrefix(key, KeyPrefix))
		if err == nil {
			return uint32(nodeID)
		}
	}
	return 0
}
