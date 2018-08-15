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
	listers "github.com/contiv/vpp/plugins/crd/pkg/client/listers/contivtelemetry/v1"

	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"reflect"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivtelemetry/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/apimachinery/pkg/util/runtime"

	contivcache "github.com/contiv/vpp/plugins/crd/cache"
	telemetry "github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	factory "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions"

)

// ContivTelemetryController struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching) queueing, and
// handling of resource changes
type ContivTelemetryController struct {
	Deps

	K8sClient *kubernetes.Clientset
	CrdClient *crdClientSet.Clientset
	ApiClient    *apiextcs.Clientset

	ContivTelemetryCache *contivcache.ContivTelemetryCache

	clientset    kubernetes.Interface
	queue        workqueue.RateLimitingInterface
	informer     k8sCache.SharedIndexInformer
	eventHandler handler.Handler
	//Lister     listers.ContivTelemetryLister
	contivTelemetryReportLister listers.ContivTelemetryReportLister
}

// Deps defines dependencies for the CRD plugin
type Deps struct {
	Log logging.Logger
}

// Init performs the initialization of ContivTelemetryController
func (ctc *ContivTelemetryController) Init() error {

	var err error
	var crdname string

	crdname = reflect.TypeOf(v1.ContivTelemetryReport{}).Name()
	err = ctc.createCRD(v1.CRDFullContivTelemetryReportsName,
		v1.CRDGroup,
		v1.CRDGroupVersion,
		v1.CRDContivTelemetryReportPlural,
		crdname)

	if err != nil {
		ctc.Log.Error("Error initializing CRD")
		return err
	}

	// Create a custom resource informer (generated from the code generator)
	// Pass the custom resource client, while looking all namespaces for listing and watching.
	ctc.informer = crdResourceInformer.NewContivTelemetryReportInformer(
		ctc.CrdClient,
		meta_v1.NamespaceAll,
		0,
		k8sCache.Indexers{},
	)

	//ctc.contivTelemetryReportLister = listers.NewContivTelemetryReportLister(ctc.informer.GetIndexer())

	sharedFactory := factory.NewSharedInformerFactory(ctc.CrdClient, time.Second*30)
	informer := sharedFactory.Contivtelemetry().V1().ContivTelemetryReports()
	ctc.contivTelemetryReportLister = informer.Lister()

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


	ctc.genReport()

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
	go ctc.informer.Run(ctx)

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

// Create the CRD resource, ignore error if it already exists
func (ctc *ContivTelemetryController) createCRD(FullName, Group, Version, Plural, Name string) error {

	var validation *apiextv1beta1.CustomResourceValidation
	switch Name {
	case "ContivTelemetryReport":
		validation = contivTelemetryReportValidation()
	default:
		validation = &apiextv1beta1.CustomResourceValidation{}
	}
	crd := &apiextv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{Name: FullName},
		Spec: apiextv1beta1.CustomResourceDefinitionSpec{
			Group:   Group,
			Version: Version,
			Scope:   apiextv1beta1.NamespaceScoped,
			Names: apiextv1beta1.CustomResourceDefinitionNames{
				Plural: Plural,
				Kind:   Name,
			},
			Validation: validation,
		},
	}
	_, cserr := ctc.ApiClient.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
	if apierrors.IsAlreadyExists(cserr) {
		return nil
	}

	return cserr
}

// contivTelemetryReportValidation generates OpenAPIV3 validator for CrdExample CRD
func contivTelemetryReportValidation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": apiextv1beta1.JSONSchemaProps{
				},
			},
		},
	}
	return validation
}

// updates the CRD status in Kubernetes with the current status from the sfc-controller
func (ctc *ContivTelemetryController) updateContivTelemetryStatus() error {
	// Fetch crdContivTelemetry from K8s cache
	// The name in sfc is the namespace/name, which is the "namespace key". Split it out.
	key := "john"
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}
	if namespace == "" {
		namespace = "default"
	}

	//crdContivTelemetryReport, errGet := ctc.contivTelemetryReportLister.ContivTelemetryReports(namespace).Get(name)
	//if errGet != nil {
	//	ctc.Log.Errorf("Could not get '%s' with namespace '%s", name, namespace)
	//	return errGet
	//}

	crdContivTelemetryReport := &v1.ContivTelemetryReport{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
			Namespace: namespace,
		},
		TypeMeta: meta_v1.TypeMeta{
			Kind: v1.CRDContivTelemetryReport,
			APIVersion: v1.CRDGroupVersion,
		},
		Spec: v1.ContivTelemetryReportSpec {
			ReportPollingPeriodSeconds: 10,
		},
	}

	crdContivTelemetryReportCopy := crdContivTelemetryReport.DeepCopy()

	n := telemetry.Node{
		Name: "johnNode",
	}
	crdContivTelemetryReportCopy.Status.Nodes = append(crdContivTelemetryReportCopy.Status.Nodes, n)

	//for _, node := range ctc.ContivTelemetryCache.Cache.GetAllNodes() {
	//	crdContivTelemetryCopy.Status.Nodes = append(crdContivTelemetryCopy.Status.Nodes, *node)
	//}


	// Until #38113 is merged, we must use Update instead of UpdateStatus to
	// update the Status block of the NetworkNode resource. UpdateStatus will not
	// allow changes to the Spec of the resource, which is ideal for ensuring
	// nothing other than resource status has been updated.
	//_, errUpdate := ctc.CrdClient.ContivtelemetryV1().ContivTelemetryReports(namespace).Update(crdContivTelemetryReportCopy)
	_, errUpdate := ctc.CrdClient.ContivtelemetryV1().ContivTelemetryReports(namespace).Create(crdContivTelemetryReportCopy)
	if errUpdate != nil {
			ctc.Log.Errorf("Could not UPDATE '%s'  err: %v, namespace '%s, and value: %v",
				name, errUpdate, namespace, crdContivTelemetryReportCopy)
	}
	return errUpdate
	}

func (ctc *ContivTelemetryController) genReport() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for t := range ticker.C {
			ctc.Log.Infof("Tick at: %v", t)
			if ctc.HasSynced() {
				ctc.updateContivTelemetryStatus()
			}
		}
	}()
}