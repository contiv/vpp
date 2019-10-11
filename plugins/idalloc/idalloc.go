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

//go:generate protoc -I ./idallocation --gogo_out=plugins=grpc:./idallocation ./idallocation/idallocation.proto

package idalloc

import (
	"fmt"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/idalloc/idallocation"
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/nodesync"
)

const (
	maxIDAllocationAttempts = 10
)

// IDAllocator plugin implements allocation of numeric identifiers in distributed manner.
type IDAllocator struct {
	Deps

	dbBrokerUnsafe keyval.BytesBrokerWithAtomic
	serializer     keyval.SerializerJSON

	poolCache map[string]*idallocation.AllocationPool // pool name to pool data
	poolMeta  map[string]*poolMetadata                // pool name to pool metadata
}

// Deps lists dependencies of the IDAllocator plugin.
type Deps struct {
	infra.PluginDeps

	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	RemoteDB     nodesync.KVDBWithAtomic
}

// poolMetadata contains metadata of a pool used for faster ID allocation.
type poolMetadata struct {
	reservedIDs  map[uint32]bool
	allocatedIDs map[uint32]string // id to label map
}

// Init initializes plugin internals.
func (a *IDAllocator) Init() (err error) {

	a.serializer = keyval.SerializerJSON{}

	return nil
}

// HandlesEvent selects:
//   - Resync
//   - KubeStateChange for ID allocation db resource
func (a *IDAllocator) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange &&
		ksChange.Resource == idallocation.Keyword {
		return true
	}
	// unhandled event
	return false
}

// Resync resynchronizes ID Allocator.
func (a *IDAllocator) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	a.poolCache = make(map[string]*idallocation.AllocationPool)
	a.poolMeta = make(map[string]*poolMetadata)

	// resync internal cache of allocation pools
	for _, poolProto := range kubeStateData[idallocation.Keyword] {
		pool := poolProto.(*idallocation.AllocationPool)
		a.poolCache[pool.Name] = pool
		a.poolMeta[pool.Name] = a.buildPoolMetadata(pool)
	}

	a.Log.Debugf("IDAllocator state after resync: %v", a.poolCache)

	return
}

// Update handles ID allocation db change events.
func (a *IDAllocator) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {

	// k8s data change
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange &&
		ksChange.Resource == idallocation.Keyword {
		if ksChange.NewValue != nil {
			// add / update pool
			pool := ksChange.NewValue.(*idallocation.AllocationPool)
			a.poolCache[pool.Name] = pool
			a.poolMeta[pool.Name] = a.buildPoolMetadata(pool)
		} else if ksChange.PrevValue != nil {
			// delete pool
			pool := ksChange.PrevValue.(*idallocation.AllocationPool)
			delete(a.poolCache, pool.Name)
			delete(a.poolMeta, pool.Name)
		}
	}
	return
}

// Revert is NOOP - never called.
func (a *IDAllocator) Revert(event controller.Event) error {
	return nil
}

// Close cleans up the resources.
func (a *IDAllocator) Close() error {
	return nil
}

// InitPool initializes ID allocation pool with given name and ID range.
// If the pool already exists, returns success if the pool range matches with
// existing one (and effectively does nothing), false otherwise.
func (a *IDAllocator) InitPool(name string, poolRange *idallocation.AllocationPool_Range) (err error) {

	// if pool with given name already exists, check if their specifications are same
	if pool, exists := a.poolCache[name]; exists {
		if proto.Equal(pool.Range, poolRange) {
			// the pool specification matches
			return nil
		}
		// the pool specification does not match
		a.Log.Errorf("ID pool %s already exists with different specification: %v", name, pool)
		return fmt.Errorf("ID pool %s already exists with different specification", name)
	}

	pool := &idallocation.AllocationPool{
		Name:          name,
		Range:         poolRange,
		IdAllocations: map[string]*idallocation.AllocationPool_Allocation{},
	}

	// save the pool in db
	encodedPool, err := a.serializer.Marshal(pool)
	if err != nil {
		a.Log.Error(err)
		return err
	}
	db, err := a.getDBBroker()
	if err != nil {
		a.Log.Error(err)
		return err
	}
	success, err := db.PutIfNotExists(idallocation.Key(name), encodedPool)

	if err == nil && success == false {
		// the pool already exists in db, check if the specification matches
		existPool, _ := a.dbReadPool(name)
		if existPool != nil {
			if !proto.Equal(pool.Range, existPool.Range) {
				return fmt.Errorf("ID pool %s already exists with different specification", name)
			}
			pool = existPool
		}
	} else if err != nil {
		// error by writing to db
		a.Log.Errorf("Error by writing allocation pool to db: %v", err)
		return err
	}

	// cache the pool
	a.poolCache[pool.Name] = pool
	a.poolMeta[pool.Name] = a.buildPoolMetadata(pool)

	a.Log.Debugf("Initialized ID allocation pool %v, metadata: %v", pool, a.poolMeta[pool.Name])

	return nil
}

// GetOrAllocateID returns allocated ID in given pool for given label. If the ID was
// not already allocated, allocates new available ID.
func (a *IDAllocator) GetOrAllocateID(poolName string, idLabel string) (id uint32, err error) {

	pool := a.poolCache[poolName]
	if pool == nil {
		err = fmt.Errorf("ID pool %s does not exist", poolName)
		a.Log.Error(err)
		return
	}
	poolMeta := a.poolMeta[poolName]
	if poolMeta == nil {
		a.poolMeta[poolName] = a.buildPoolMetadata(pool)
		poolMeta = a.poolMeta[poolName]
	}

	succeeded := false
	for i := 0; i < maxIDAllocationAttempts; i++ {
		id, succeeded, err = a.tryToAllocateID(pool, poolMeta, idLabel)
		if err != nil {
			break
		}
		if succeeded {
			// successfully allocated an ID
			poolMeta.allocatedIDs[id] = idLabel
			break
		} else {
			// pool changed in db, re-read from db and retry
			pool, err = a.dbReadPool(poolName)
			if err != nil {
				break
			}
			a.poolMeta[poolName] = a.buildPoolMetadata(pool)
			poolMeta = a.poolMeta[poolName]
		}
	}
	if !succeeded {
		err = fmt.Errorf("ID allocation for pool %s failed in %d attempts", pool.Name, maxIDAllocationAttempts)
	}
	if err != nil {
		a.Log.Errorf("Error by allocating ID: %v", err)
	}

	a.Log.Debugf("ID for label '%s' in pool %s: %d", idLabel, poolName, id)
	return
}

// ReleaseID releases existing allocation for given pool and label.
// NOOP if the pool or allocation does not exist.
func (a *IDAllocator) ReleaseID(poolName string, idLabel string) (err error) {

	pool := a.poolCache[poolName]
	if pool == nil {
		return
	}
	poolMeta := a.poolMeta[poolName]
	if poolMeta == nil {
		return
	}
	alloc := pool.IdAllocations[idLabel]

	succeeded := false
	for i := 0; i < maxIDAllocationAttempts; i++ {
		succeeded, err = a.tryToReleaseID(pool, poolMeta, idLabel)
		if err != nil {
			break
		}
		if succeeded {
			// successfully released an ID
			delete(poolMeta.allocatedIDs, alloc.Id)
			break
		} else {
			// pool changed in db, re-read from db and retry
			pool, err = a.dbReadPool(poolName)
			if err != nil {
				break
			}
			a.poolMeta[poolName] = a.buildPoolMetadata(pool)
			poolMeta = a.poolMeta[poolName]
		}
	}
	if !succeeded {
		err = fmt.Errorf("ID release from pool %s failed in %d attempts", pool.Name, maxIDAllocationAttempts)
	}
	if err != nil {
		a.Log.Errorf("Error by releasing ID: %v", err)
	}

	a.Log.Debugf("Released ID for label '%s' in pool %s: %d", idLabel, poolName, alloc.Id)

	return nil
}

// tryToAllocateID attempts to allocate an ID for given pool and label.
func (a *IDAllocator) tryToAllocateID(pool *idallocation.AllocationPool, poolMeta *poolMetadata, idLabel string) (
	id uint32, succeeded bool, err error) {

	// step 0, try to get already allocated ID number
	if alloc, exists := pool.IdAllocations[idLabel]; exists {
		return alloc.Id, true, nil
	}

	// step 1, find a free ID number
	found := false
	for id = pool.Range.MinId; id <= pool.Range.MaxId; id++ {
		if _, reserved := poolMeta.reservedIDs[id]; reserved {
			continue
		}
		if _, used := poolMeta.allocatedIDs[id]; !used {
			found = true
			break
		}
	}
	if !found {
		err = fmt.Errorf("no more space left in pool %s", pool.Name)
		return
	}

	// step 2, try to write into db
	prevData, err := a.serializer.Marshal(pool)
	if err != nil {
		return 0, false, err
	}
	pool.IdAllocations[idLabel] = &idallocation.AllocationPool_Allocation{
		Id:    id,
		Owner: a.ServiceLabel.GetAgentLabel(),
	}
	newData, err := a.serializer.Marshal(pool)
	if err != nil {
		return 0, false, err
	}
	db, err := a.getDBBroker()
	if err != nil {
		a.Log.Error(err)
		return 0, false, err
	}
	succeeded, err = db.CompareAndSwap(idallocation.Key(pool.Name), prevData, newData)

	return
}

// tryToReleaseID attempts to release an ID for given pool and label.
func (a *IDAllocator) tryToReleaseID(pool *idallocation.AllocationPool, poolMeta *poolMetadata, idLabel string) (
	succeeded bool, err error) {

	alloc, exists := pool.IdAllocations[idLabel]
	if !exists {
		// already released
		return true, nil
	}

	// delete the allocation from cache
	delete(pool.IdAllocations, idLabel)

	if alloc.Owner != a.ServiceLabel.GetAgentLabel() {
		// we do not own this allocation, do not write into db
		return true, nil
	}

	// try to write into db
	prevData, err := a.serializer.Marshal(pool)
	if err != nil {
		return false, err
	}
	newData, err := a.serializer.Marshal(pool)
	if err != nil {
		return false, err
	}
	db, err := a.getDBBroker()
	if err != nil {
		a.Log.Error(err)
		return false, err
	}
	succeeded, err = db.CompareAndSwap(idallocation.Key(pool.Name), prevData, newData)
	return
}

// dbReadPool reads pool date from database.
func (a *IDAllocator) dbReadPool(poolName string) (pool *idallocation.AllocationPool, err error) {
	db, err := a.getDBBroker()
	if err != nil {
		a.Log.Error(err)
		return nil, err
	}
	existData, found, _, err := db.GetValue(idallocation.Key(poolName))
	if err != nil {
		return nil, err
	}
	if found {
		pool = &idallocation.AllocationPool{}
		err = a.serializer.Unmarshal(existData, pool)
		if err != nil {
			return nil, err
		}
	}
	return
}

// buildPoolMetadata builds metadata for the provided allocation pool.
func (a *IDAllocator) buildPoolMetadata(pool *idallocation.AllocationPool) *poolMetadata {
	if pool == nil {
		return nil
	}
	meta := &poolMetadata{
		allocatedIDs: map[uint32]string{},
		reservedIDs:  map[uint32]bool{},
	}
	for _, id := range pool.Range.Reserved {
		meta.reservedIDs[id] = true
	}
	for label, alloc := range pool.IdAllocations {
		meta.allocatedIDs[alloc.Id] = label
	}
	return meta
}

// getDBBroker returns broker for accessing remote database, error if database is not connected.
func (a *IDAllocator) getDBBroker() (keyval.BytesBrokerWithAtomic, error) {
	// return error if ETCD is not connected
	dbIsConnected := false
	a.RemoteDB.OnConnect(func() error {
		dbIsConnected = true
		return nil
	})
	if !dbIsConnected {
		return nil, fmt.Errorf("remote database is not connected")
	}
	// return existing broker if possible
	if a.dbBrokerUnsafe == nil {
		ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
		a.dbBrokerUnsafe = a.RemoteDB.NewBrokerWithAtomic(ksrPrefix)
	}
	return a.dbBrokerUnsafe, nil
}
