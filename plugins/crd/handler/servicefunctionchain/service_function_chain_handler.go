/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/servicefunctionchain.proto

package servicefunctionchain

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"

	"reflect"
	"sync"
	"time"

	informers "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/contivppio/v1"

	"github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
)

const (
	minResyncTimeout = 100  // minimum timeout between resync attempts, in ms
	maxResyncTimeout = 1000 // maximum timeout between resync attempts, in ms
)

// Handler handler implements Handler interface,
type Handler struct {
	Deps

	// Data store sync status and the mutex that protects access to it
	dsSynced bool
	dsMutex  sync.Mutex

	broker KeyProtoValBroker
	prefix string
	kpc    K8sToProtoConverter

	syncStopCh chan bool
}

// Deps defines dependencies for NodeConfig CRD Handler.
type Deps struct {
	Log                logging.Logger
	Publish            *kvdbsync.Plugin // KeyProtoValWriter does not define Delete
	ControllerInformer informers.ServiceFunctionChainInformer
}

// KeyProtoValBroker defines handler's interface to the key-value data store. It
// defines a subset of operations from a generic cn-infra broker interface
// (keyval.ProtoBroker in cn-infra).
type KeyProtoValBroker interface {
	// Put <data> to ETCD or to any other key-value based data source.
	Put(key string, data proto.Message, opts ...datasync.PutOption) error

	// Delete data under the <key> in ETCD or in any other key-value based data
	// source.
	Delete(key string, opts ...datasync.DelOption) (existed bool, err error)

	// GetValue reads a value from etcd stored under the given key.
	GetValue(key string, reqObj proto.Message) (found bool, revision int64, err error)

	// List values stored in etcd under the given prefix.
	ListValues(prefix string) (keyval.ProtoKeyValIterator, error)
}

// K8sToProtoConverter defines the signature for a function converting k8s
// objects to service function chain protobuf objects.
type K8sToProtoConverter func(interface{}) (interface{}, string, bool)

// DsItems defines the structure holding items listed from the data store.
type DsItems map[string]interface{}

// Init initializes handler configuration
// ServiceFunctionChain Handler will be taking action on resource CRUD
func (h *Handler) Init() error {
	ksrPrefix := h.Publish.ServiceLabel.GetAgentPrefix()
	h.broker = h.Publish.Deps.KvPlugin.NewBroker(ksrPrefix)

	h.syncStopCh = make(chan bool, 1)
	h.prefix = model.KeyPrefix()

	h.kpc = func(obj interface{}) (interface{}, string, bool) {
		serviceFunctionChain, ok := obj.(*v1.ServiceFunctionChain)
		if !ok {
			h.Log.Warn("Failed to cast newly created service function chain object")
			return nil, "", false
		}
		return h.serviceFunctionChainToProto(serviceFunctionChain), model.Key(serviceFunctionChain.Name), true
	}
	return nil
}

// ObjectCreated is called when a CRD object is created
func (h *Handler) ObjectCreated(obj interface{}) {
	h.Log.Debugf("Object created with value: %v", obj)
	serviceFunctionChain, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		h.Log.Warn("Failed to cast newly created service function chain object")
		return
	}

	chainProto := h.serviceFunctionChainToProto(serviceFunctionChain)
	err := h.Publish.Put(model.Key(serviceFunctionChain.GetName()), chainProto)
	if err != nil {
		h.dsSynced = false
		h.startDataStoreResync()
	}
}

// ObjectDeleted is called when a CRD object is deleted
func (h *Handler) ObjectDeleted(obj interface{}) {
	h.Log.Debugf("Object deleted with value: %v", obj)
	serviceFunctionChain, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		h.Log.Warn("Failed to cast delete event")
		return
	}

	chainProto := h.serviceFunctionChainToProto(serviceFunctionChain)
	_, err := h.Publish.Delete(model.Key(serviceFunctionChain.GetName()))
	if err != nil {
		h.Log.WithField("rwErr", err).
			Warnf("service function chain failed to delete item from data store: %v", chainProto)
	}
}

// ObjectUpdated is called when a CRD object is updated
func (h *Handler) ObjectUpdated(oldObj, newObj interface{}) {
	h.Log.Debugf("Object updated with value: %v", newObj)
	if !reflect.DeepEqual(oldObj, newObj) {

		h.Log.Debugf("service function chain updating item in data store, %v", newObj)
		serviceFunctionChain, ok := newObj.(*v1.ServiceFunctionChain)
		if !ok {
			h.Log.Warn("Failed to cast delete event")
			return
		}

		chainProto := h.serviceFunctionChainToProto(serviceFunctionChain)
		err := h.Publish.Put(model.Key(serviceFunctionChain.GetName()), chainProto)
		if err != nil {
			h.Log.WithField("rwErr", err).
				Warnf("service function chain failed to update item in data store %v", chainProto)
			h.dsSynced = false
			h.startDataStoreResync()
			return
		}
	}
}

// serviceFunctionChainToProto converts service function chain data from the Contiv's own CRD representation
// to the corresponding protobuf-modelled data format.
func (h *Handler) serviceFunctionChainToProto(serviceFunctionChain *v1.ServiceFunctionChain) *model.ServiceFunctionChain {
	h.Log.Info("!!", serviceFunctionChain)
	chain := &model.ServiceFunctionChain{}
	chain.Name = serviceFunctionChain.Name

	for _, c := range serviceFunctionChain.Spec.Chain {
		chain.Chain = append(chain.Chain,
			h.serviceFunctionToProto(c))
	}

	return chain
}

func (h *Handler) serviceFunctionToProto(sf v1.ServiceFunction) *model.ServiceFunctionChain_ServiceFunction {
	protoVal := &model.ServiceFunctionChain_ServiceFunction{}
	protoVal.Name = sf.Name
	switch sf.Type {
	case "InterfaceInput":
		protoVal.Type = model.ServiceFunctionChain_InterfaceInput
	case "InterfaceOutput":
		protoVal.Type = model.ServiceFunctionChain_InterfaceOutput
	case "PodInput":
		protoVal.Type = model.ServiceFunctionChain_PodInput
	case "PodOutput":
		protoVal.Type = model.ServiceFunctionChain_PodOutput
	case "ServiceFunctionPod":
	default:
		protoVal.Type = model.ServiceFunctionChain_ServiceFunctionPod

	}
	protoVal.PodSelector = map[string]string{}
	for k, v := range sf.PodSelector {
		protoVal.PodSelector[k] = v
	}
	protoVal.InputInterface = sf.InputInterface
	protoVal.OutputInterface = sf.OutputInterface
	return protoVal
}

// listDataStoreItems gets all items of a given type from Etcd
func (h *Handler) listDataStoreItems() (DsItems, error) {
	dsDump := make(map[string]interface{})

	// Retrieve all data items for a given data type (i.e. key prefix)
	kvi, err := h.broker.ListValues(h.prefix)
	if err != nil {
		return dsDump, fmt.Errorf("service function chain handler can not get kv iterator, error: %s", err)
	}

	// Put the retrieved items to a map where an item can be addressed
	// by its key
	for {
		kv, stop := kvi.GetNext()
		if stop {
			break
		}
		key := kv.GetKey()
		item := &model.ServiceFunctionChain{}
		err := kv.GetValue(item)
		if err != nil {
			h.Log.WithField("Key", key).
				Errorf("service function chain handle failed to get object from data store, error %s", err)
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
func (h *Handler) markAndSweep(dsItems DsItems, oc K8sToProtoConverter) error {
	for _, obj := range h.ControllerInformer.Informer().GetStore().List() {
		k8sProtoObj, key, ok := oc(obj)
		if ok {
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
		}
	}

	// Delete from data store all objects that no longer exist in the K8s
	// cache.
	for key := range dsItems {
		_, err := h.broker.Delete(key)
		if err != nil {
			return fmt.Errorf("delete for key '%s' failed", key)
		}

		delete(dsItems, key)
	}
	return nil
}

// syncDataStoreWithK8sCache syncs data in etcd with data in service function chain crd in
// k8s cache. Returns ok if reconciliation is successful, error otherwise.
func (h *Handler) syncDataStoreWithK8sCache(dsItems DsItems) error {
	h.dsMutex.Lock()
	defer h.dsMutex.Unlock()

	// don't do anything unless the K8s cache itself is synced
	if !h.ControllerInformer.Informer().HasSynced() {
		return fmt.Errorf("service function chain data sync: k8sController not synced")
	}

	// Reconcile data store with k8s cache using mark-and-sweep
	err := h.markAndSweep(dsItems, h.kpc)
	if err != nil {
		return fmt.Errorf("service function chain data sync: mark-and-sweep failed, '%s'", err)
	}

	h.dsSynced = true
	return nil
}

// dataStoreResyncWait waits for a specified time before the data store
// resync procedure is attempted again. The wait time doubles with each
// attempt until it reaches the specified maximum wait timeout. The function
// returns true if a data sync abort signal is received, at which point
// the data store resync is terminated.
func (h *Handler) dataStoreResyncWait(timeout *time.Duration) bool {
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
func (h *Handler) startDataStoreResync() {
	go func(h *Handler) {
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
						h.Log.Info("service function chain data sync done")
						break Loop
					}
					h.Log.Infof("service function chain data sync: syncDataStoreWithK8sCache failed, '%s'", err)

					// Wait before attempting the resync again
					if abort := h.dataStoreResyncWait(&timeout); abort == true {
						break Loop
					}
				}
			}
			h.Log.Infof("service function chain data sync: error listing data store items, '%s'", err)

			// Wait before attempting to list data store items again
			if abort := h.dataStoreResyncWait(&timeout); abort == true {
				break Loop
			}
		}
	}(h)
}
