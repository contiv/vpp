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

package controller

import (
	"fmt"
	"time"

	"github.com/contiv/vpp/plugins/crd/handler"
	"github.com/ligato/cn-infra/logging"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sCache "k8s.io/client-go/tools/cache"

	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	crdResourceInformer "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/contivtelemetry/v1"
)

// ContivTelemetryController struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching) queueing, and
// handling of resource changes
type ContivTelemetryController struct {
	Deps

	K8sClient *kubernetes.Clientset
	CrdClient *crdClientSet.Clientset

	clientset    kubernetes.Interface
	queue        workqueue.RateLimitingInterface
	informer     k8sCache.SharedIndexInformer
	eventHandler handler.Handler
	//Lister     listers.ContivTelemetryLister
}

// Deps defines dependencies for the CRD plugin
type Deps struct {
	Log logging.Logger
}

// Init performs the initialization of ContivTelemetryController
func (ctc *ContivTelemetryController) Init() error {
	// Create a custom resource informer (generated from the code generator)
	// Pass the custom resource client, while looking all namespaces for listing and watching.
	ctc.informer = crdResourceInformer.NewContivTelemetryInformer(
		ctc.CrdClient,
		meta_v1.NamespaceAll,
		0,
		k8sCache.Indexers{},
	)

	// Create a new queue in that when the informer gets a resource from listing or watching,
	// adding the identifying key to the queue for the handler
	ctc.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Add event handlers to handle the three types of events for resources (add, update, delete)
	ctc.informer.AddEventHandler(k8sCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// Converting the resource object into a key
			key, err := k8sCache.MetaNamespaceKeyFunc(obj)
			ctc.Log.Infof("Add ContivTelemetry resource: %s", key)
			if err == nil {
				// Adding the key to the queue for the handler to get
				ctc.queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := k8sCache.MetaNamespaceKeyFunc(newObj)
			ctc.Log.Infof("Update ContivTelemetry resource: %s", key)
			if err == nil {
				ctc.queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := k8sCache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			ctc.Log.Infof("Delete ContivTelemetry resource: %s", key)
			if err == nil {
				ctc.queue.Add(key)
			}
		},
	})

	ctc.eventHandler = &handler.Default{}

	return nil
}

// Run this in the plugin_crd_impl, it's the controller loop
func (ctc *ContivTelemetryController) Run(ctx <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items and shutdown when done
	defer ctc.queue.ShutDown()

	ctc.Log.Info("Controller-Run: Initiating...")

	// runs the informer to list and watch on a goroutine
	// go ctc.informer.Run(ctx)

	// populate resources one after synchronization
	if !k8sCache.WaitForCacheSync(ctx, ctc.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Error syncing cache"))
		return
	}
	ctc.Log.Info("Controller.Run: cache sync complete")

	// runWorker method runs every second using a stop channel
	wait.Until(ctc.runWorker, time.Second, ctx)
}

// HasSynced indicates when the controller is synced up with the K8s.
func (ctc *ContivTelemetryController) HasSynced() bool {
	return ctc.informer.HasSynced()
}

// runWorker processes new items in the queue
func (ctc *ContivTelemetryController) runWorker() {
	ctc.Log.Info("Controller-runWorker: Starting..")

	// invoke processNextItem to fetch and consume the next change
	// to a watched or listed resource
	for ctc.processNextItem() {
		ctc.Log.Info("Controller-runWorker: processing next item...")
	}

	ctc.Log.Info("Controller-runWorker: Completed")
}

// processNextItem retrieves next queued item, acts accordingly for object CRUD
func (ctc *ContivTelemetryController) processNextItem() bool {
	ctc.Log.Info("Controller.processNextItem: start")

	// get the next item (blocking) from the queue and process or
	// quit if shutdown requested
	key, quit := ctc.queue.Get()
	if quit {
		return false
	}
	defer ctc.queue.Done(key)

	// assert the string out of the key (format `namespace/name`)
	keyRaw := key.(string)

	// Get the string key and get the object out of the indexer.
	// item is the object of the resource, it was created if exists = true
	//
	// on error retry the queue key given number of times (5 here)
	// on failure forget the queue key and throw an error
	item, exists, err := ctc.informer.GetIndexer().GetByKey(keyRaw)
	if err != nil {
		if ctc.queue.NumRequeues(key) < 5 {
			ctc.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			ctc.queue.AddRateLimited(key)
		} else {
			ctc.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			ctc.queue.Forget(key)
			utilruntime.HandleError(err)
		}
	}

	// if item exists run the ObjectCreated method (item created or updated)
	// if item does not exist run the ObjectDeleted method (item deleted)
	//
	// in every case forget the key from the queue
	if exists {
		ctc.Log.Infof("Controller.processNextItem: object created detected: %s", keyRaw)
		ctc.eventHandler.ObjectCreated(item)
		ctc.queue.Forget(key)
	} else {
		ctc.Log.Infof("Controller.processNextItem: object deleted detected: %s", keyRaw)
		ctc.eventHandler.ObjectDeleted(item)
		ctc.queue.Forget(key)
	}

	// keep the worker loop running by returning true
	return true
}
