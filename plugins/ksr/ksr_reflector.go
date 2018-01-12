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

	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/logging"

	"k8s.io/apimachinery/pkg/fields"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// ReflectorStats defines the usage statistics for K8s State Reflectors
type ReflectorStats struct {
	NumAdds    int
	NumDeletes int
	NumUpdates int

	NumArgErrors int
	NumAddErrors int
	NumDelErrors int
	NumUpdErrors int
}

// Reflector holds data that is common to all KSR reflectors.
type Reflector struct {
	// Each reflector gets a separate child logger.
	Log logging.Logger
	// A K8s client gets the appropriate REST client.
	K8sClientset *kubernetes.Clientset
	// K8s List-Watch watches for Kubernetes config changes.
	K8sListWatch K8sListWatcher
	// Writer propagates changes into a data store.
	Writer KeyProtoValWriter
	// Lister lists values from a data store.
	Lister KeyProtoValLister
	// objType defines the type of the object handled by a particular reflector
	objType string
	// stopCh is used to gracefully shutdown the Reflector
	stopCh <-chan struct{}
	wg     *sync.WaitGroup
	// K8s cache
	k8sStore cache.Store
	// K8s controller
	k8sController cache.Controller
	// Reflector statistics
	stats ReflectorStats

	dsSynced bool
	dsMutex  sync.Mutex
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
	K8s2ProtoFunc  K8sToProtoConverter
	K8sClntGetFunc K8sClientGetter
}

// GetStats returns the Service Reflector usage statistics
func (r *Reflector) GetStats() *ReflectorStats {
	return &r.stats
}

// Start activates the K8s subscription.
func (r *Reflector) Start() {
	r.wg.Add(1)
	go r.ksrRun()
}

// Close does nothing for this particular reflector.
func (r *Reflector) Close() error {
	return nil
}

// HasSynced returns the KSR Reflector's sync status.
func (r *Reflector) HasSynced() bool {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()
	return r.dsSynced
}

// ksrRun runs k8s subscription in a separate go routine.
func (r *Reflector) ksrRun() {
	defer r.wg.Done()
	r.Log.Infof("%s reflector is now running", r.objType)
	r.k8sController.Run(r.stopCh)
	r.Log.Infof("%s reflector stopped", r.objType)
}

// listDataStoreItems gets all items of a given type from Etcd
func (r *Reflector) listDataStoreItems(pfx string, iaf func() proto.Message) (DsItems, error) {
	dsDump := make(map[string]interface{})

	// Retrieve all data items for a given data type (i.e. key prefix)
	kvi, err := r.Lister.ListValues(pfx)
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
// the k8s cache and data in Etcd
func (r *Reflector) markAndSweep(dsItems DsItems, oc K8sToProtoConverter) {
	r.dsMutex.Lock()
	defer r.dsMutex.Unlock()

	for _, obj := range r.k8sStore.List() {
		k8sProtoObj, key, ok := oc(obj)
		if ok {
			dsProtoObj, exists := dsItems[key]
			if exists {
				if !reflect.DeepEqual(k8sProtoObj, dsProtoObj) {
					// Object exists in the data store, but it changed in the
					// K8s cache; overwrite the data store
					err := r.Writer.Put(key, k8sProtoObj.(proto.Message))
					if err != nil {
						r.Log.WithField("err", err).
							Warnf("%s data sync: failed to update object in the data store", r.objType)
						r.stats.NumUpdErrors++
					} else {
						r.stats.NumUpdates++
					}
				}
			} else {
				// Object does not exist in the data store, but it exists in
				// the K8s cache; create object in the data store
				err := r.Writer.Put(key, k8sProtoObj.(proto.Message))
				if err != nil {
					r.Log.WithField("err", err).
						Warnf("%s data sync: failed to add object into the data store", r.objType)
					r.stats.NumAddErrors++
				} else {
					r.stats.NumAdds++
				}
			}
			delete(dsItems, key)
		}
	}

	// Delete from data store all objects that no longer exist in the K8s
	// cache.
	for key := range dsItems {
		_, err := r.Writer.Delete(key)
		if err != nil {
			r.Log.WithField("err", err).
				Warnf("%s data sync: failed to delete object from the data store", r.objType)
			r.stats.NumDelErrors++
		} else {
			r.stats.NumDeletes++
		}
		delete(dsItems, key)
	}

	r.dsSynced = true
}

// syncDataStore syncs data in etcd with data in KSR's k8s cache
func (r *Reflector) syncDataStore(dsItems DsItems, oc K8sToProtoConverter) {
	for {
		if r.k8sController.HasSynced() {
			break
		}
		time.Sleep(1 * time.Second)
	}
	r.markAndSweep(dsItems, oc)
	r.Log.Infof("%s stats: %+v", r.objType, r.stats)
}

// ksrAdd adds an item to the Etcd data store
func (r *Reflector) ksrAdd(key string, item proto.Message) {
	err := r.Writer.Put(key, item)
	if err != nil {
		r.Log.WithField("err", err).Warnf("%s: failed to add item to data store", r.objType)
		r.stats.NumAddErrors++
		return
	}
	r.stats.NumAdds++
}

// ksrUpdate updates an item to the Etcd data store
func (r *Reflector) ksrUpdate(key string, itemOld, itemNew proto.Message) {
	if !reflect.DeepEqual(itemOld, itemNew) {

		r.Log.WithField("key", key).Debugf("%s: updating item in data store", r.objType)

		err := r.Writer.Put(key, itemNew)
		if err != nil {
			r.Log.WithField("err", err).
				Warnf("%s: failed to update item in data store", r.objType)
			r.stats.NumUpdErrors++
			return
		}
		r.stats.NumUpdates++
	}
}

// ksrDelete deletes an item from the Etcd data store
func (r *Reflector) ksrDelete(key string) {
	_, err := r.Writer.Delete(key)
	if err != nil {
		r.Log.WithField("err", err).
			Warnf("%s: Failed to remove item from data store", r.objType)
		r.stats.NumDelErrors++
		return
	}
	r.stats.NumDeletes++
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (r *Reflector) ksrInit(stopCh2 <-chan struct{}, wg *sync.WaitGroup, prefix string,
	objType string, k8sObjType k8sRuntime.Object, ksrFuncs ReflectorFunctions) error {

	r.stopCh = stopCh2
	r.wg = wg

	var restClient rest.Interface
	if ksrFuncs.K8sClntGetFunc != nil {
		restClient = ksrFuncs.K8sClntGetFunc(r.K8sClientset)
	} else {
		// If API version getter not specified, use CoreV1 by default
		restClient = r.K8sClientset.CoreV1().RESTClient()
	}

	listWatch := r.K8sListWatch.NewListWatchFromClient(restClient, objType, "", fields.Everything())
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

	// Get all items currently stored in the data store
	dsSvc, err := r.listDataStoreItems(prefix, ksrFuncs.ProtoAllocFunc)
	if err != nil {
		r.Log.WithField("err", err).Errorf("%s: error listing items data store", r.objType)
	}

	// Sync up the data store with the local k8s cache *after* the cache
	// is synced with K8s.
	go r.syncDataStore(dsSvc, ksrFuncs.K8s2ProtoFunc)

	return nil
}
