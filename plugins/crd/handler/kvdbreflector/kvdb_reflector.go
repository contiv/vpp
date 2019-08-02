/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package kvdbreflector

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/plugins/ksr/model/ksrkey"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"

	k8sCache "k8s.io/client-go/tools/cache"
)

const (
	minResyncTimeout = 100  // minimum timeout between resync attempts, in ms
	maxResyncTimeout = 1000 // maximum timeout between resync attempts, in ms
)

// KvdbReflector is a generic CRD handler which just reflects created instances
// of a given CRD into a key-value database.
type KvdbReflector struct {
	Deps

	// Data store sync status and the mutex that protects access to it.
	dsSynced bool
	dsMutex  sync.Mutex

	broker keyval.ProtoBroker

	syncStopCh chan bool
}

// Handler defines the interface that needs to be implemented to use KvdbReflector
// with a specific CRD type.
type Handler interface {
	// CrdName should return a name of the CRD. Used only for logging purposes,
	// i.e. it doesn't really have to match the type name, but should be readable.
	CrdName() string

	// CrdKeyPrefix should return longest-common prefix under which the instances
	// of the given CRD are reflected into KVDB.
	// If the CRD is reflected under KSR key prefix, return <underKsrPrefix> as
	// true and <prefix> as relative to the KSR prefix.
	CrdKeyPrefix() (prefix string, underKsrPrefix bool)

	// IsCrdKeySuffix should return true if the given key suffix, found in KVDB under
	// CrdKeyPrefix(), really belongs to this CRD. Unless the prefix returned by
	// CrdKeyPrefix() overlaps with some other CRDs or KSR-reflected K8s state
	// data that need to be excluded by mark-and-sweep, just return true.
	IsCrdKeySuffix(keySuffix string) bool

	// CrdObjectToProto should convert the K8s representation of the CRD into the
	// corresponding proto message representation. The method also has to return
	// key suffix (i.e. without the prefix returned by CrdKeyPrefix) under which
	// the given object should be reflected into KVDB.
	CrdObjectToProto(obj interface{}) (data proto.Message, keySuffix string, err error)

	// CrdProtoFactory should create an empty instance of the CRD proto model.
	CrdProtoFactory() proto.Message

	// IsExclusiveKVDB should return true if KvdbReflector is the only writer
	// for the given key-space. If not, the mark-and-sweep procedure will not
	// remove extra (i.e. not defined by CRD) records from KVDB, as they
	// might have been inserted into the DB from different configuration sources
	// and should be preserved.
	IsExclusiveKVDB() bool
}

// Deps defines dependencies for KvdbReflector.
type Deps struct {
	Log      logging.Logger
	Publish  *kvdbsync.Plugin // KeyProtoValWriter does not define Delete
	Informer k8sCache.SharedIndexInformer
	Handler  Handler
}

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string]interface{}

// Init prepared broker for the KV database access.
func (h *KvdbReflector) Init() error {
	prefix, underKsr := h.Handler.CrdKeyPrefix()
	if underKsr {
		prefix = h.Publish.ServiceLabel.GetAgentPrefix() + ksrkey.KsrK8sPrefix +
			"/" + prefix
	}
	h.broker = h.Publish.Deps.KvPlugin.NewBroker(prefix)

	h.syncStopCh = make(chan bool, 1)
	return nil
}

// ObjectCreated is called when a CRD object is created
func (h *KvdbReflector) ObjectCreated(obj interface{}) {
	h.Log.Debugf("%s object created with value: %v", h.Handler.CrdName(), obj)
	data, key, err := h.Handler.CrdObjectToProto(obj)
	if err != nil {
		h.Log.Warnf("Failed to cast newly created %s object into the proto model: %v",
			h.Handler.CrdName(), err)
		return
	}

	err = h.Publish.Put(key, data)
	if err != nil {
		h.dsSynced = false
		h.startDataStoreResync()
	}
}

// ObjectDeleted is called when a CRD object is deleted
func (h *KvdbReflector) ObjectDeleted(obj interface{}) {
	h.Log.Debugf("%s object deleted with value: %v", h.Handler.CrdName(), obj)
	_, key, err := h.Handler.CrdObjectToProto(obj)
	if err != nil {
		h.Log.Warnf("Failed to cast to-be-deleted %s object into the proto model: %v",
			h.Handler.CrdName(), err)
		return
	}

	_, err = h.Publish.Delete(key)
	if err != nil {
		h.Log.WithField("rwErr", err).
			Warnf("Failed to delete %s item from data store: %v",
				h.Handler.CrdName(), err)
	}
}

// ObjectUpdated is called when a CRD object is updated
func (h *KvdbReflector) ObjectUpdated(oldObj, newObj interface{}) {
	h.Log.Debugf("%s object updated with value: %v", h.Handler.CrdName(), newObj)
	if !reflect.DeepEqual(oldObj, newObj) {

		h.Log.Debugf("Updating %s item in data store: %v",
			h.Handler.CrdName(), newObj)
		newData, key, err := h.Handler.CrdObjectToProto(newObj)
		if err != nil {
			h.Log.Warnf("Failed to updated %s object into the proto model: %v",
				h.Handler.CrdName(), err)
			return
		}

		err = h.Publish.Put(key, newData)
		if err != nil {
			h.Log.WithField("rwErr", err).
				Warnf("Failed to update %s item in data store: %v",
					h.Handler.CrdName(), err)
			h.dsSynced = false
			h.startDataStoreResync()
			return
		}
	}
}

// listDataStoreItems gets all items of a given type from the KVDB
func (h *KvdbReflector) listDataStoreItems() (DsItems, error) {
	dsDump := make(map[string]interface{})

	// Retrieve all data items for a given data type (i.e. key prefix)
	kvi, err := h.broker.ListValues("")
	if err != nil {
		return dsDump, fmt.Errorf("failed to list %s instances stored in KVDB: %s",
			h.Handler.CrdName(), err)
	}

	// Put the retrieved items to a map where an item can be addressed
	// by its key
	for {
		kv, stop := kvi.GetNext()
		if stop {
			break
		}
		key := kv.GetKey()
		if !h.Handler.IsCrdKeySuffix(key) {
			continue
		}
		item := h.Handler.CrdProtoFactory()
		err := kv.GetValue(item)
		if err != nil {
			h.Log.WithField("Key", key).
				Errorf("Failed to get %s object from data store: %s",
					h.Handler.CrdName(), err)
		} else {
			dsDump[key] = item
		}
	}

	return dsDump, nil
}

// markAndSweep performs the mark-and-sweep reconciliation between data in
// the k8s cache and data in Etcd. This function must be called with dsMutex
// locked, because it manipulates dsFlag and because no updates to the data
// store can happen while the resync is in progress.
//
// dsItems is a map containing a snapshot of the data store. This function
// will delete all elements from this map. oc is a function converting the
// K8s policy data structure to the protobuf policy data structure.
//
// If data can not be written into the data store, mark-and-sweep is aborted
// and the function returns an error.
func (h *KvdbReflector) markAndSweep(dsItems DsItems) error {
	for _, obj := range h.Informer.GetStore().List() {
		k8sProtoObj, key, err := h.Handler.CrdObjectToProto(obj)
		if err == nil {
			dsProtoObj, exists := dsItems[key]
			if exists {
				if !reflect.DeepEqual(k8sProtoObj, dsProtoObj) {
					// Object exists in the data store, but it changed in the
					// K8s cache; overwrite the data store
					err := h.broker.Put(key, k8sProtoObj.(proto.Message))
					if err != nil {
						return fmt.Errorf("update for key '%s' failed", key)
					}
				}
			} else {
				// Object does not exist in the data store, but it exists in
				// the K8s cache; create object in the data store
				err := h.broker.Put(key, k8sProtoObj.(proto.Message))
				if err != nil {
					return fmt.Errorf("add for key '%s' failed", key)
				}
			}
			delete(dsItems, key)
		} else {
			h.Log.Warnf("Failed to cast %s item listed from K8s cache: %v",
				h.Handler.CrdName(), err)
		}
	}

	// Delete from data store all objects that no longer exist in the K8s
	// cache.
	if h.Handler.IsExclusiveKVDB() {
		for key := range dsItems {
			_, err := h.broker.Delete(key)
			if err != nil {
				return fmt.Errorf("delete for key '%s' failed", key)
			}

			delete(dsItems, key)
		}
	}

	return nil
}

// syncDataStoreWithK8sCache syncs data in etcd with data in k8s cache.
// Returns ok if reconciliation is successful, error otherwise.
func (h *KvdbReflector) syncDataStoreWithK8sCache(dsItems DsItems) error {
	h.dsMutex.Lock()
	defer h.dsMutex.Unlock()

	// don't do anything unless the K8s cache itself is synced
	if !h.Informer.HasSynced() {
		return fmt.Errorf("%s data sync: k8sController not synced",
			h.Handler.CrdName())
	}

	// Reconcile data store with k8s cache using mark-and-sweep
	err := h.markAndSweep(dsItems)
	if err != nil {
		return fmt.Errorf("%s data sync: mark-and-sweep failed, '%s'",
			h.Handler.CrdName(), err)
	}

	h.dsSynced = true
	return nil
}

// dataStoreResyncWait waits for a specified time before the data store
// resync procedure is attempted again. The wait time doubles with each
// attempt until it reaches the specified maximum wait timeout. The function
// returns true if a data sync abort signal is received, at which point
// the data store resync is terminated.
func (h *KvdbReflector) dataStoreResyncWait(timeout *time.Duration) bool {
	select {
	case <-h.syncStopCh: // Data Store resync is aborted
		h.Log.Info("Data sync aborted due to data store down")
		return true
	case <-time.After(*timeout * time.Millisecond):
		t := *timeout * 2
		if t > maxResyncTimeout {
			t = maxResyncTimeout
		}
		*timeout = t
		return false
	}
}

// startDataStoreResync starts the synchronization of the data store with
// the handler's K8s cache. The resync will only stop if it's successful,
// or until it's aborted because of a data store failure or a handler process
// termination notification.
func (h *KvdbReflector) startDataStoreResync() {
	go func(h *KvdbReflector) {
		h.Log.Debug("starting data sync")
		var timeout time.Duration = minResyncTimeout

		// Keep trying to reconcile until data sync succeeds.
	Loop:
		for {
			// Try to get a snapshot of the data store.
			dsItems, err := h.listDataStoreItems()
			if err == nil {
				// Now that we have a data store snapshot, keep trying to
				// resync the cache with it
				for {
					// Make a copy of DsItems because the parameter passed to
					// syncDataStoreWithK8sCache gets destroyed in the function
					dsItemsCopy := make(DsItems)
					for k, v := range dsItems {
						dsItemsCopy[k] = v
					}
					// Try to resync the data store with the K8s cache
					err := h.syncDataStoreWithK8sCache(dsItemsCopy)
					if err == nil {
						h.Log.Infof("%s data sync done", h.Handler.CrdName())
						break Loop
					}
					h.Log.Infof("%s data sync: syncDataStoreWithK8sCache failed, '%s'",
						h.Handler.CrdName(), err)

					// Wait before attempting the resync again
					if abort := h.dataStoreResyncWait(&timeout); abort == true {
						break Loop
					}
				}
			}
			h.Log.Infof("%s data sync: error listing data store items, '%s'",
				h.Handler.CrdName(), err)

			// Wait before attempting to list data store items again
			if abort := h.dataStoreResyncWait(&timeout); abort == true {
				break Loop
			}
		}
	}(h)
}
