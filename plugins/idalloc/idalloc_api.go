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

package idalloc

import (
	"github.com/contiv/vpp/plugins/idalloc/idallocation"
)

// API defines methods provided by the IDAllocator plugin for use by other plugins
// to query pod memif allocation info and release pod memif allocations.
type API interface {
	// InitPool initializes ID allocation pool with given name and ID range.
	// If the pool already exists, returns success if the pool range matches with
	// existing one (and effectively does nothing), false otherwise.
	InitPool(name string, poolRange *idallocation.AllocationPool_Range) (err error)

	// GetOrAllocateID returns allocated ID in given pool for given label. If the ID was
	// not already allocated, allocates new available ID.
	GetOrAllocateID(poolName string, idLabel string) (id uint32, err error)

	// ReleaseID releases existing allocation for given pool and label.
	// NOOP if the allocation does not exist.
	ReleaseID(poolName string, idLabel string) (err error)
}
