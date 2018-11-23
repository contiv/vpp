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

package nodeinfo

import (
	"strconv"
)

// Keyword defines the keyword identifying NodeInfo data.
const Keyword = "nodeinfo"

// AllocatedIDsKeyPrefix is a key prefix used in ETCD to store information
// about node ID and its IP addresses.
const AllocatedIDsKeyPrefix = "allocatedIDs/"

// Key returns the key under which NodeInfo data for a node with the given ID
// should be stored in the data-store.
func Key(index uint32) string {
	return AllocatedIDsKeyPrefix + strconv.FormatUint(uint64(index), 10)
}

