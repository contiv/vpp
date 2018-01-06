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

// KsrReflector is used in all KSR reflectors to hold boiler plate data that
// is common to all reflectors.
type KsrReflector struct {
	ReflectorDeps

	stopCh        <-chan struct{}
	wg            *sync.WaitGroup
	k8sStore      cache.Store
	k8sController cache.Controller
	stats         ReflectorStats

	dsSynced bool
	dsMutex  sync.Mutex
}

// ksrRun runs k8s subscription in a separate go routine.
func (kc *KsrReflector) ksrRun(objType string) {
	defer kc.wg.Done()
	kc.Log.Infof("%s reflector is now running", objType)
	kc.k8sController.Run(kc.stopCh)
	kc.Log.Infof("%s reflector stopped", objType)
}

// ksrStart activates the K8s subscription.
func (kc *KsrReflector) ksrStart(objType string) {
	kc.wg.Add(1)
	go kc.ksrRun(objType)
}

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string]interface{}

// K8sToProtoConverter defines the function type for converting k8s objects
// to KSR protobuf objects.
type K8sToProtoConverter func(interface{}) (interface{}, string, bool)

func (kc *KsrReflector) listDataStoreItems(pfx string, iaf func() proto.Message) (DsItems, error) {

	dsDump := make(map[string]interface{})
	// List everything in Etcd
	kvi, err := kc.Lister.ListValues(pfx)
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
			kc.Log.WithField("Key", key).Error("failed to get object from data store, error", err)
		} else {
			dsDump[key] = item
		}
	}

	return dsDump, nil
}

func (kc *KsrReflector) markAndSweep(dsItems DsItems, oc K8sToProtoConverter) {
	kc.dsMutex.Lock()
	defer kc.dsMutex.Unlock()

	for _, obj := range kc.k8sStore.List() {
		k8sProtoObj, key, ok := oc(obj)
		if ok {
			dsProtoObj, exists := dsItems[key]
			if exists {
				if !reflect.DeepEqual(k8sProtoObj, dsProtoObj) {
					// Object exists in the data store, but it changed in K8s;
					// overwrite the data store
					err := kc.Writer.Put(key, k8sProtoObj.(proto.Message))
					if err != nil {
						kc.Log.WithField("err", err).
							Warn("Data Sync: failed to update object in the data store")
						kc.stats.NumUpdErrors++
					} else {
						kc.stats.NumUpdates++
					}
				}
				delete(dsItems, key)
			} else {
				// Object does not exist in the data store, but it exists in
				// K8s; create object in the data store
				err := kc.Writer.Put(key, k8sProtoObj.(proto.Message))
				if err != nil {
					kc.Log.WithField("err", err).
						Warn("Data Sync: failed to add object into the data store")
					kc.stats.NumAddErrors++
				} else {
					kc.stats.NumAdds++
				}
			}
		}
	}

	// Delete from data store all objects that no longer exist in K8s.
	for key := range dsItems {
		_, err := kc.Writer.Delete(key)
		if err != nil {
			kc.Log.WithField("err", err).
				Warn("Data Sync: failed to delete object from the data store")
			kc.stats.NumDelErrors++
		} else {
			kc.stats.NumDeletes++
		}
		delete(dsItems, key)
	}

	kc.dsSynced = true
}

func (kc *KsrReflector) syncDataStore(dsItems DsItems, oc K8sToProtoConverter) {
	for {
		if kc.k8sController.HasSynced() {
			break
		}
		time.Sleep(1 * time.Second)
	}
	kc.markAndSweep(dsItems, oc)
	kc.Log.Infof("Stats: %+v", kc.stats)
}
