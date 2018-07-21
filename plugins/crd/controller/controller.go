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

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/vpp/plugins/crd/handler"
	"github.com/ligato/cn-infra/logging"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Controller struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching)
// queueing, and handling of resource changes
type ContivTelemetryController struct {
	Log          logging.Logger
	Clientset    kubernetes.Interface
	Queue        workqueue.RateLimitingInterface
	Informer     cache.SharedIndexInformer
	EventHandler handler.Handler
}

// Run this in the plugin_crd_impl, it's the controller loop
func (ctc *ContivTelemetryController) Run(stopCh <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items and shutdown when done
	defer ctc.Queue.ShutDown()

	ctc.Log.Info("Controller-Run: Initiating...")

	// runs the informer to list and watch on a goroutine
	go ctc.Informer.Run(stopCh)

	// populate resources one after synchronization
	if !cache.WaitForCacheSync(stopCh, ctc.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Error syncing cache"))
		return
	}
	ctc.Log.Info("Controller.Run: cache sync complete")

	// runWorker method runs every second using a stop channel
	wait.Until(ctc.runWorker, time.Second, stopCh)
}

// When informer hasSynced, controller is synced
func (ctc *ContivTelemetryController) HasSynced() bool {
	return ctc.Informer.HasSynced()
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
	log.Info("Controller.processNextItem: start")

	// get the next item (blocking) from the queue and process or
	// quit if shutdown requested
	key, quit := ctc.Queue.Get()
	if quit {
		return false
	}
	defer ctc.Queue.Done(key)

	// assert the string out of the key (format `namespace/name`)
	keyRaw := key.(string)

	// Get the string key and get the object out of the indexer.
	// item is the object of the resource, it was created if exists = true
	//
	// on error retry the queue key given number of times (5 here)
	// on failure forget the queue key and throw an error
	item, exists, err := ctc.Informer.GetIndexer().GetByKey(keyRaw)
	if err != nil {
		if ctc.Queue.NumRequeues(key) < 5 {
			ctc.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			ctc.Queue.AddRateLimited(key)
		} else {
			ctc.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			ctc.Queue.Forget(key)
			utilruntime.HandleError(err)
		}
	}

	// if item exists run the ObjectCreated method (item created or updated)
	// if item does not exist run the ObjectDeleted method (item deleted)
	//
	// in every case forget the key from the queue
	if exists {
		ctc.Log.Infof("Controller.processNextItem: object created detected: %s", keyRaw)
		ctc.EventHandler.ObjectCreated(item)
		ctc.Queue.Forget(key)
	} else {
		ctc.Log.Infof("Controller.processNextItem: object deleted detected: %s", keyRaw)
		ctc.EventHandler.ObjectDeleted(item)
		ctc.Queue.Forget(key)
	}

	// keep the worker loop running by returning true
	return true
}
