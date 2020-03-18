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
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/contiv/vpp/plugins/ksr/model/ksrkey"
	"go.ligato.io/cn-infra/v2/db/keyval"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/servicelabel"

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

	broker     keyval.BytesBroker
	serializer keyval.Serializer

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

	// CrdObjectToKVData should convert the K8s representation of the CRD into the
	// corresponding data that should be mirrored into KVDB.
	CrdObjectToKVData(obj interface{}) (data []KVData, err error)

	// IsExclusiveKVDB should return true if KvdbReflector is the only writer
	// for the given key-space. If not, the mark-and-sweep procedure will not
	// remove extra (i.e. not defined by CRD) records from KVDB, as they
	// might have been inserted into the DB from different configuration sources
	// and should be preserved.
	IsExclusiveKVDB() bool

	// PublishCrdStatus should update the Status information associated with the resource (if defined).
	PublishCrdStatus(obj interface{}, opRetval error) error
}

// KVData is a key->data pair to be written into KVDB to reflect a given CRD instance.
type KVData struct {
	// ProtoMsg can be used when the KVDB-mirrored CRD data are modelled using protobuf.
	// If not, then use MarshalledData instead.
	ProtoMsg proto.Message

	// MarshalledData are already marshalled data to be written into the KVDB under the given key suffix.
	// Use as an alternative when proto message is not available.
	MarshalledData []byte

	// KeySuffix under which the given data should be reflected into KVDB (i.e. without the prefix returned by CrdKeyPrefix).
	KeySuffix string
}

// Deps defines dependencies for KvdbReflector.
type Deps struct {
	Log          logging.Logger
	Publish      keyval.KvBytesPlugin
	ServiceLabel servicelabel.ReaderAPI
	Informer     k8sCache.SharedIndexInformer
	Handler      Handler
}

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string][]byte

// Init prepared broker for the KV database access.
func (r *KvdbReflector) Init() error {
	prefix, underKsr := r.Handler.CrdKeyPrefix()
	if underKsr {
		prefix = r.ServiceLabel.GetAgentPrefix() + ksrkey.KsrK8sPrefix +
			"/" + prefix
	}
	r.broker = r.Publish.NewBroker(prefix)
	r.serializer = &keyval.SerializerJSON{}

	r.syncStopCh = make(chan bool, 1)
	return nil
}

// ObjectCreated is called when a CRD object is created
func (r *KvdbReflector) ObjectCreated(obj interface{}) error {
	r.Log.Debugf("%s object created with value: %v", r.Handler.CrdName(), obj)
	kvdata, err := r.Handler.CrdObjectToKVData(obj)
	if err != nil {
		err = fmt.Errorf("failed to cast newly created %s object into the proto model: %v",
			r.Handler.CrdName(), err)
		r.Log.Error(err)
		return err
	}

	for _, kv := range kvdata {
		binData, err := r.marshalData(kv)
		if err == nil {
			err = r.broker.Put(kv.KeySuffix, binData)
		}
		if err != nil {
			err = fmt.Errorf("failed to create %s item in data store: %v",
				r.Handler.CrdName(), err)
			r.Log.Error(err)
			r.dsSynced = false
			r.startDataStoreResync()
			return err
		}
	}
	return nil
}

// PublishStatus is just forwarded to the handler.
func (r *KvdbReflector) PublishStatus(obj interface{}, opRetval error) error {
	return r.Handler.PublishCrdStatus(obj, opRetval)
}

func (r *KvdbReflector) marshalData(kvdata KVData) ([]byte, error) {
	if len(kvdata.MarshalledData) > 0 {
		// already marshalled by the handler
		return kvdata.MarshalledData, nil
	}
	return r.serializer.Marshal(kvdata.ProtoMsg)
}

// ObjectDeleted is called when a CRD object is deleted
func (r *KvdbReflector) ObjectDeleted(obj interface{}) error {
	r.Log.Debugf("%s object deleted with value: %v", r.Handler.CrdName(), obj)
	kvdata, err := r.Handler.CrdObjectToKVData(obj)
	if err != nil {
		err = fmt.Errorf("failed to cast to-be-deleted %s object into the proto model: %v",
			r.Handler.CrdName(), err)
		r.Log.Error(err)
		return err
	}

	for _, kv := range kvdata {
		_, err = r.broker.Delete(kv.KeySuffix)
		if err != nil {
			err = fmt.Errorf("failed to delete %s item from data store: %v",
				r.Handler.CrdName(), err)
			r.Log.Error(err)
			r.dsSynced = false
			r.startDataStoreResync()
			return err
		}
	}
	return nil
}

// ObjectUpdated is called when a CRD object is updated
func (r *KvdbReflector) ObjectUpdated(oldObj, newObj interface{}) error {
	r.Log.Debugf("%s object updated with value: %v", r.Handler.CrdName(), newObj)
	if !reflect.DeepEqual(oldObj, newObj) {

		r.Log.Debugf("Updating %s item in data store: %v",
			r.Handler.CrdName(), newObj)
		var (
			err            error
			oldKvs, newKvs []KVData
		)
		oldKvs, err = r.Handler.CrdObjectToKVData(oldObj)
		if err != nil {
			// non-nil error means the previous config was invalid and nothing was reflected
			oldKvs = []KVData{}
			err = nil
		}
		newKvs, err = r.Handler.CrdObjectToKVData(newObj)

		if err != nil {
			err = fmt.Errorf("failed to convert updated %s object into key-value data: %v",
				r.Handler.CrdName(), err)
			r.Log.Error(err)
			return err
		}

		updateKvs, removeKvs, err := r.diffKVData(oldKvs, newKvs)
		if err != nil {
			err = fmt.Errorf("failed to compare previous with the new key-value data for %s: %v",
				r.Handler.CrdName(), err)
			r.Log.Error(err)
			return err
		}

		for key, value := range updateKvs {
			err = r.broker.Put(key, value)
			if err != nil {
				err = fmt.Errorf("failed to update %s item in data store: %v",
					r.Handler.CrdName(), err)
				r.Log.Error(err)
				r.dsSynced = false
				r.startDataStoreResync()
				return err
			}
		}
		for key := range removeKvs {
			_, err = r.broker.Delete(key)
			if err != nil {
				err = fmt.Errorf("failed to delete %s item from data store: %v",
					r.Handler.CrdName(), err)
				r.Log.Error(err)
				r.dsSynced = false
				r.startDataStoreResync()
				return err
			}
		}
	}
	return nil
}

func (r *KvdbReflector) diffKVData(oldKvs, newKvs []KVData) (updateKvs, removeKvs DsItems, err error) {
	updateKvs = make(DsItems)
	removeKvs = make(DsItems)
	for _, newKv := range newKvs {
		newData, err := r.marshalData(newKv)
		if err != nil {
			return nil, nil, err
		}
		updateKvs[newKv.KeySuffix] = newData
	}
	for _, oldKv := range oldKvs {
		oldData, err := r.marshalData(oldKv)
		if err != nil {
			return nil, nil, err
		}
		removeKvs[oldKv.KeySuffix] = oldData
	}
	for key, newData := range updateKvs {
		oldData, hasOld := removeKvs[key]
		if hasOld {
			if bytes.Equal(newData, oldData) {
				delete(updateKvs, key)
			}
			delete(removeKvs, key)
		}
	}
	return updateKvs, removeKvs, nil
}

// listDataStoreItems gets all items of a given type from the KVDB
func (r *KvdbReflector) listDataStoreItems() (DsItems, error) {
	dsDump := make(DsItems)

	// Retrieve all data items for a given data type (i.e. key prefix)
	kvi, err := r.broker.ListValues("")
	if err != nil {
		return dsDump, fmt.Errorf("failed to list %s instances stored in KVDB: %s",
			r.Handler.CrdName(), err)
	}

	// Put the retrieved items to a map where an item can be addressed
	// by its key
	for {
		kv, stop := kvi.GetNext()
		if stop {
			break
		}
		key := kv.GetKey()
		if !r.Handler.IsCrdKeySuffix(key) {
			continue
		}
		item := kv.GetValue()
		dsDump[key] = item
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
func (r *KvdbReflector) markAndSweep(dsItems DsItems) error {
	for _, obj := range r.Informer.GetStore().List() {
		kvdata, err := r.Handler.CrdObjectToKVData(obj)
		if err == nil {
			for _, kv := range kvdata {
				kvBytes, err := r.marshalData(kv)
				if err != nil {
					return fmt.Errorf("marshall for key '%s' failed", kv.KeySuffix)
				}
				dsBytes, exists := dsItems[kv.KeySuffix]
				if exists {
					if !bytes.Equal(dsBytes, kvBytes) {
						// Object exists in the data store, but it changed in the
						// K8s cache; overwrite the data store
						err := r.broker.Put(kv.KeySuffix, kvBytes)
						if err != nil {
							return fmt.Errorf("update for key '%s' failed", kv.KeySuffix)
						}
					}
				} else {
					// Object does not exist in the data store, but it exists in
					// the K8s cache; create object in the data store
					err = r.broker.Put(kv.KeySuffix, kvBytes)
					if err != nil {
						return fmt.Errorf("add for key '%s' failed", kv.KeySuffix)
					}
				}
				delete(dsItems, kv.KeySuffix)
			}
		} else {
			r.Log.Warnf("Failed to cast %s item listed from K8s cache: %v",
				r.Handler.CrdName(), err)
		}
	}

	// Delete from data store all objects that no longer exist in the K8s
	// cache.
	if r.Handler.IsExclusiveKVDB() {
		for key := range dsItems {
			_, err := r.broker.Delete(key)
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
func (r *KvdbReflector) syncDataStoreWithK8sCache(dsItems DsItems) error {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()

	// don't do anything unless the K8s cache itself is synced
	if !r.Informer.HasSynced() {
		return fmt.Errorf("%s data sync: k8sController not synced",
			r.Handler.CrdName())
	}

	// Reconcile data store with k8s cache using mark-and-sweep
	err := r.markAndSweep(dsItems)
	if err != nil {
		return fmt.Errorf("%s data sync: mark-and-sweep failed, '%s'",
			r.Handler.CrdName(), err)
	}

	r.dsSynced = true
	return nil
}

// dataStoreResyncWait waits for a specified time before the data store
// resync procedure is attempted again. The wait time doubles with each
// attempt until it reaches the specified maximum wait timeout. The function
// returns true if a data sync abort signal is received, at which point
// the data store resync is terminated.
func (r *KvdbReflector) dataStoreResyncWait(timeout *time.Duration) bool {
	select {
	case <-r.syncStopCh: // Data Store resync is aborted
		r.Log.Info("Data sync aborted due to data store down")
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
func (r *KvdbReflector) startDataStoreResync() {
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
	}(r)
}
