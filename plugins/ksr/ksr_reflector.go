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

package ksr

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/logging"

	"k8s.io/apimachinery/pkg/fields"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/ksr/model/ksrapi"
)

const (
	minResyncTimeout = 100  // minimum timeout between resync attempts, in ms
	maxResyncTimeout = 1000 // maximum timeout between resync attempts, in ms
)

// Reflector holds data that is common to all KSR reflectors.
type Reflector struct {
	// Each reflector gets a separate child logger.
	Log logging.Logger
	// A K8s client gets the appropriate REST client.
	K8sClientset *kubernetes.Clientset
	// K8s List-Watch watches for Kubernetes config changes.
	K8sListWatch K8sListWatcher
	// broker is the interface to a key-val data store.
	Broker KeyProtoValBroker
	// reflector registry
	*ReflectorRegistry
	// objType defines the type of the object handled by a particular reflector
	objType string
	// ksrStopCh is used to gracefully shutdown the Reflector
	ksrStopCh <-chan struct{}
	wg        *sync.WaitGroup
	// K8s cache
	k8sStore cache.Store
	// K8s controller
	k8sController cache.Controller
	// Reflector gauges
	stats ksrapi.KsrStats

	prefix string
	pa     ProtoAllocator
	kpc    K8sToProtoConverter

	// Data store sync status and the mutex that protects access to it
	dsSynced bool
	dsMutex  sync.Mutex

	syncStopCh chan bool
}

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string]interface{}

// ProtoAllocator defines the signature for a protobuf message allocation
// function
type ProtoAllocator func() proto.Message

// K8sToProtoConverter defines the signature for a function converting k8s
// objects to KSR protobuf objects.
type K8sToProtoConverter func(interface{}) (interface{}, string, bool)

// K8sClientGetter defines the signature for a function that allocates
// a REST client for a given K8s data type
type K8sClientGetter func(*kubernetes.Clientset) rest.Interface

// ReflectorFunctions defines the function types required in the KSR reflector
type ReflectorFunctions struct {
	EventHdlrFunc cache.ResourceEventHandlerFuncs

	ProtoAllocFunc ProtoAllocator
	K8s2NodeFunc   K8sToProtoConverter
	K8sClntGetFunc K8sClientGetter
}

// GetStats returns the Service Reflector usage gauges
func (r *Reflector) GetStats() *ksrapi.KsrStats {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()

	retStats := r.stats
	return &retStats
}

// Start activates the K8s subscription.
func (r *Reflector) Start() {
	r.wg.Add(1)
	go r.ksrRun()
}

// Close deletes the reflector from the reflector registry.
func (r *Reflector) Close() error {
	return r.deleteReflector(r)
}

// HasSynced returns the KSR Reflector's sync status.
func (r *Reflector) HasSynced() bool {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()
	return r.dsSynced
}

// stopDataStoreUpdates marks the data store to be out of sync with the
// K8s cache, which will stop any updates to the data store until proper
// reconciliation is finished.
func (r *Reflector) stopDataStoreUpdates() {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()
	r.dsSynced = false
}

// ksrRun runs k8s subscription in a separate go routine.
func (r *Reflector) ksrRun() {
	defer r.wg.Done()
	r.Log.Infof("%s reflector is now synced", r.objType)
	r.k8sController.Run(r.ksrStopCh)
	r.Log.Infof("%s reflector stopped", r.objType)
}

// listDataStoreItems gets all items of a given type from Etcd
func (r *Reflector) listDataStoreItems(pfx string, iaf func() proto.Message) (DsItems, error) {
	dsDump := make(map[string]interface{})

	// Retrieve all data items for a given data type (i.e. key prefix)
	kvi, err := r.Broker.ListValues(pfx)
	if err != nil {
		return dsDump, fmt.Errorf("%s reflector can not get kv iterator, error: %s", r.objType, err)
	}

	// Put the retrieved items to a map where an item can be addressed
	// by its key
	for {
		kv, stop := kvi.GetNext()
		if stop {
			break
		}
		key := kv.GetKey()
		item := iaf()
		err := kv.GetValue(item)
		if err != nil {
			r.Log.WithField("Key", key).
				Errorf("%s reflector failed to get object from data store, error %s", r.objType, err)
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
func (r *Reflector) markAndSweep(dsItems DsItems, oc K8sToProtoConverter) error {
	for _, obj := range r.k8sStore.List() {
		k8sProtoObj, key, ok := oc(obj)
		if ok {
			dsProtoObj, exists := dsItems[key]
			if exists {
				if !reflect.DeepEqual(k8sProtoObj, dsProtoObj) {
					// Object exists in the data store, but it changed in the
					// K8s cache; overwrite the data store
					err := r.Broker.Put(key, k8sProtoObj.(proto.Message))
					if err != nil {
						r.stats.UpdErrors++
						return fmt.Errorf("update for key '%s' failed", key)
					}
					r.stats.Updates++
				}
			} else {
				// Object does not exist in the data store, but it exists in
				// the K8s cache; create object in the data store
				err := r.Broker.Put(key, k8sProtoObj.(proto.Message))
				if err != nil {
					r.stats.AddErrors++
					return fmt.Errorf("add for key '%s' failed", key)
				}
				r.stats.Adds++
			}
			delete(dsItems, key)
		}
	}

	// Delete from data store all objects that no longer exist in the K8s
	// cache.
	for key := range dsItems {
		_, err := r.Broker.Delete(key)
		if err != nil {
			r.stats.DelErrors++
			return fmt.Errorf("delete for key '%s' failed", key)
		}
		r.stats.Deletes++

		delete(dsItems, key)
	}
	return nil
}

// syncDataStoreWithK8sCache syncs data in etcd with data in KSR's
// k8s cache. Returns ok if reconciliation is successful, error otherwise.
func (r *Reflector) syncDataStoreWithK8sCache(dsItems DsItems) error {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()

	r.stats.Resyncs++

	// don't do anything unless the K8s cache itself is synced
	if !r.k8sController.HasSynced() {
		return fmt.Errorf("%s data sync: k8sController not synced", r.objType)
	}

	// Reconcile data store with k8s cache using mark-and-sweep
	err := r.markAndSweep(dsItems, r.kpc)
	if err != nil {
		return fmt.Errorf("%s data sync: mark-and-sweep failed, '%s'", r.objType, err)
	}

	r.dsSynced = true
	return nil
}

// dataStoreResyncWait waits for a specified time before the data store
// resync procedure is attempted again. The wait time doubles with each
// attempt until it reaches the specified maximum wait timeout. The function
// returns true if a data sync abort signal is received, at which point
// the data store resync is terminated.
func (r *Reflector) dataStoreResyncWait(timeout *time.Duration) bool {
	select {
	case <-r.ksrStopCh: // KSR is being terminated
		r.Log.Info("Data sync aborted due to KSR process termination")
		return true
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
// the reflector's K8s cache. The resync will only stop if it's successful,
// or until it's aborted because of a data store failure or a KSR process
// termination notification.
func (r *Reflector) startDataStoreResync() {
	go func(r *Reflector) {
		r.Log.Debug("%s: starting data sync", r.objType)
		var timeout time.Duration = minResyncTimeout

		// Keep trying to reconcile until data sync succeeds.
	Loop:
		for {
			// Try to get a snapshot of the data store.
			dsItems, err := r.listDataStoreItems(r.prefix, r.pa)
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
					err := r.syncDataStoreWithK8sCache(dsItemsCopy)
					if err == nil {
						r.Log.Infof("%s: data sync done, gauges %+v", r.objType, r.stats)
						break Loop
					}
					r.Log.Infof("%s data sync: syncDataStoreWithK8sCache failed, '%s'", r.objType, err)
					r.stats.ResErrors++ // unprotected by dsMutex, but dsSync=false

					// Wait before attempting the resync again
					if abort := r.dataStoreResyncWait(&timeout); abort == true {
						break Loop
					}
				}
			}
			r.Log.Infof("%s data sync: error listing data store items, '%s'", r.objType, err)
			r.stats.ResErrors++ // unprotected by dsMutex, but dsSync=false
			r.stats.Resyncs++   // unprotected by dsMutex, but dsSync=false

			// Wait before attempting to list data store items again
			if abort := r.dataStoreResyncWait(&timeout); abort == true {
				break Loop
			}
		}
	}(r)
}

// ksrAdd adds an item to the Etcd data store. This function must be called
// with dsMutex locked, since it manipulates the dsSynced flag.
func (r *Reflector) ksrAdd(key string, item proto.Message) {
	err := r.Broker.Put(key, item)
	if err != nil {
		r.Log.WithField("rwErr", err).Warnf("%s: failed to add item to data store", r.objType)
		r.stats.AddErrors++
		r.dsSynced = false
		r.startDataStoreResync()
		return
	}
	r.stats.Adds++
}

// ksrUpdate updates an item to the Etcd data store. This function must be
// called with dsMutex locked, since it manipulates the dsSynced flag.
func (r *Reflector) ksrUpdate(key string, itemOld, itemNew proto.Message) {
	if !reflect.DeepEqual(itemOld, itemNew) {

		r.Log.WithField("key", key).Debugf("%s: updating item in data store", r.objType)

		err := r.Broker.Put(key, itemNew)
		if err != nil {
			r.Log.WithField("rwErr", err).
				Warnf("%s: failed to update item in data store", r.objType)
			r.stats.UpdErrors++
			r.dsSynced = false
			r.startDataStoreResync()
			return
		}
		r.stats.Updates++
	}
}

// ksrDelete deletes an item from the Etcd data store. This function must be
// called with dsMutex locked, since it manipulates the dsSynced flag.
func (r *Reflector) ksrDelete(key string) {
	_, err := r.Broker.Delete(key)
	if err != nil {
		r.Log.WithField("rwErr", err).
			Warnf("%s: Failed to remove item from data store", r.objType)
		r.stats.DelErrors++
		r.dsSynced = false
		r.startDataStoreResync()
		return
	}
	r.stats.Deletes++
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (r *Reflector) ksrInit(stopCh <-chan struct{}, wg *sync.WaitGroup, prefix string,
	k8sResourceName string, k8sObjType k8sRuntime.Object, ksrFuncs ReflectorFunctions) error {

	r.syncStopCh = make(chan bool, 1)

	r.ksrStopCh = stopCh
	r.wg = wg

	r.prefix = prefix
	r.pa = ksrFuncs.ProtoAllocFunc
	r.kpc = ksrFuncs.K8s2NodeFunc

	var restClient rest.Interface
	if ksrFuncs.K8sClntGetFunc != nil {
		restClient = ksrFuncs.K8sClntGetFunc(r.K8sClientset)
	} else {
		// If API version getter not specified, use CoreV1 by default
		restClient = r.K8sClientset.CoreV1().RESTClient()
	}

	listWatch := r.K8sListWatch.NewListWatchFromClient(restClient, k8sResourceName, "", fields.Everything())
	r.k8sStore, r.k8sController = r.K8sListWatch.NewInformer(
		listWatch,
		k8sObjType,
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				r.dsMutex.Lock()
				defer r.dsMutex.Unlock()

				if !r.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.AddFunc(obj)
			},
			DeleteFunc: func(obj interface{}) {
				r.dsMutex.Lock()
				defer r.dsMutex.Unlock()

				if !r.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.DeleteFunc(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				r.dsMutex.Lock()
				defer r.dsMutex.Unlock()

				if !r.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.UpdateFunc(oldObj, newObj)
			},
		},
	)

	return r.addReflector(r)
}
