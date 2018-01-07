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

// Reflector is used in all KSR reflectors to hold boiler plate data that
// is common to all reflectors. This is the base structure used in all KSR
// reflectors.
type Reflector struct {
	// Each reflector gets a separate child logger.
	Log logging.Logger
	// A K8s client is used to get the appropriate REST client.
	K8sClientset *kubernetes.Clientset
	// K8s List-Watch is used to watch for Kubernetes config changes.
	K8sListWatch K8sListWatcher
	// Writer is used to propagate changes into a datastore.
	Writer KeyProtoValWriter
	// Lister is used to list values from a datastore.
	Lister KeyProtoValLister
	// objType defines the type of the object handled by a particular reflector
	objType string
	// stopCh is used to gracefully shutdown the Reflector
	stopCh        <-chan struct{}
	wg            *sync.WaitGroup
	k8sStore      cache.Store
	k8sController cache.Controller
	// Reflector statistics
	stats ReflectorStats

	dsSynced bool
	dsMutex  sync.Mutex
}

// ProtoAllocator defines the signature for a protobuf message allocation
// function
type ProtoAllocator func() proto.Message

// K8sToProtoConverter defines the signature for a function converting k8s
// objects to KSR protobuf objects.
type K8sToProtoConverter func(interface{}) (interface{}, string, bool)

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string]interface{}

// ReflectorFunctions defines the function types required in the KSR reflector
type ReflectorFunctions struct {
	EventHdlrFunc cache.ResourceEventHandlerFuncs

	ProtoAllocFunc ProtoAllocator
	K8s2ProtoFunc  K8sToProtoConverter
}

// ksrRun runs k8s subscription in a separate go routine.
func (kr *Reflector) ksrRun() {
	defer kr.wg.Done()
	kr.Log.Infof("%s reflector is now running", kr.objType)
	kr.k8sController.Run(kr.stopCh)
	kr.Log.Infof("%s reflector stopped", kr.objType)
}

// ksrStart activates the K8s subscription.
func (kr *Reflector) ksrStart() {
	kr.wg.Add(1)
	go kr.ksrRun()
}

func (kr *Reflector) listDataStoreItems(pfx string, iaf func() proto.Message) (DsItems, error) {

	dsDump := make(map[string]interface{})
	// List everything in Etcd
	kvi, err := kr.Lister.ListValues(pfx)
	if err != nil {
		return dsDump, fmt.Errorf("can not get kv iterator, error: %s", err)
	}

	for {
		kv, stop := kvi.GetNext()
		if stop {
			break
		}

		// sr.Log.Infof("kv key: %s, rev: %d", kv.GetKey(), kv.GetRevision())
		key := kv.GetKey()
		item := iaf()
		err := kv.GetValue(item)
		if err != nil {
			kr.Log.WithField("Key", key).Error("failed to get object from data store, error", err)
		} else {
			dsDump[key] = item
		}
	}

	return dsDump, nil
}

func (kr *Reflector) markAndSweep(dsItems DsItems, oc K8sToProtoConverter) {
	kr.dsMutex.Lock()
	defer kr.dsMutex.Unlock()

	for _, obj := range kr.k8sStore.List() {
		k8sProtoObj, key, ok := oc(obj)
		if ok {
			dsProtoObj, exists := dsItems[key]
			if exists {
				if !reflect.DeepEqual(k8sProtoObj, dsProtoObj) {
					// Object exists in the data store, but it changed in K8s;
					// overwrite the data store
					err := kr.Writer.Put(key, k8sProtoObj.(proto.Message))
					if err != nil {
						kr.Log.WithField("err", err).
							Warn("Data Sync: failed to update object in the data store")
						kr.stats.NumUpdErrors++
					} else {
						kr.stats.NumUpdates++
					}
				}
				delete(dsItems, key)
			} else {
				// Object does not exist in the data store, but it exists in
				// K8s; create object in the data store
				err := kr.Writer.Put(key, k8sProtoObj.(proto.Message))
				if err != nil {
					kr.Log.WithField("err", err).
						Warn("Data Sync: failed to add object into the data store")
					kr.stats.NumAddErrors++
				} else {
					kr.stats.NumAdds++
				}
			}
		}
	}

	// Delete from data store all objects that no longer exist in K8s.
	for key := range dsItems {
		_, err := kr.Writer.Delete(key)
		if err != nil {
			kr.Log.WithField("err", err).
				Warn("Data Sync: failed to delete object from the data store")
			kr.stats.NumDelErrors++
		} else {
			kr.stats.NumDeletes++
		}
		delete(dsItems, key)
	}

	kr.dsSynced = true
}

func (kr *Reflector) syncDataStore(dsItems DsItems, oc K8sToProtoConverter) {
	for {
		if kr.k8sController.HasSynced() {
			break
		}
		time.Sleep(1 * time.Second)
	}
	kr.markAndSweep(dsItems, oc)
	kr.Log.Infof("Stats: %+v", kr.stats)
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (kr *Reflector) ksrInit(stopCh2 <-chan struct{}, wg *sync.WaitGroup,
	prefix string, objType k8sRuntime.Object, ksrFuncs ReflectorFunctions) error {

	kr.stopCh = stopCh2
	kr.wg = wg

	restClient := kr.K8sClientset.CoreV1().RESTClient()
	listWatch := kr.K8sListWatch.NewListWatchFromClient(restClient,
		"services", "", fields.Everything())
	kr.k8sStore, kr.k8sController = kr.K8sListWatch.NewInformer(
		listWatch,
		objType,
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kr.dsMutex.Lock()
				defer kr.dsMutex.Unlock()

				if !kr.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.AddFunc(obj)
			},
			DeleteFunc: func(obj interface{}) {
				kr.dsMutex.Lock()
				defer kr.dsMutex.Unlock()

				if !kr.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.DeleteFunc(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kr.dsMutex.Lock()
				defer kr.dsMutex.Unlock()

				if !kr.dsSynced {
					return
				}
				ksrFuncs.EventHdlrFunc.UpdateFunc(oldObj, newObj)
			},
		},
	)

	// Get all items currently stored in the data store
	dsSvc, err := kr.listDataStoreItems(prefix, ksrFuncs.ProtoAllocFunc)
	if err != nil {
		kr.Log.Error("Error listing services from data store: %s", err)
	}

	// Sync up the data store with the local k8s cache *after* the cache
	// is synced with K8s.
	go kr.syncDataStore(dsSvc, ksrFuncs.K8s2ProtoFunc)

	return nil
}
