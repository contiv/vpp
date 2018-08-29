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

package telemetry

import (
	"fmt"
	"time"

	"github.com/ligato/cn-infra/logging"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sCache "k8s.io/client-go/tools/cache"

	handler "github.com/contiv/vpp/plugins/crd/handler/telemetry"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	factory "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions"
	telemetryInformers "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/telemetry/v1"
	telemetryListers "github.com/contiv/vpp/plugins/crd/pkg/client/listers/telemetry/v1"

	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"reflect"

	"github.com/contiv/vpp/plugins/crd/api"
)

// Controller struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching) queueing, and
// handling of resource changes
type Controller struct {
	Deps

	K8sClient *kubernetes.Clientset
	CrdClient *crdClientSet.Clientset
	APIClient *apiextcs.Clientset

	clientset kubernetes.Interface
	queue     workqueue.RateLimitingInterface
	// Telemetry CRD specifics
	telemetryInformer     telemetryInformers.TelemetryReportInformer
	telemetryReportLister telemetryListers.TelemetryReportLister
	// event handlers for Telemetry CRDs
	eventHandler handler.TelemetryHandler
}

// Deps defines dependencies for the CRD plugin
type Deps struct {
	Log logging.Logger
}

//CRDReport implements generation of reports to CRD
type CRDReport struct {
	Deps

	Ctlr     *Controller
	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

// Init performs the initialization of ContivTelemetry
func (c *Controller) Init() error {

	var err error
	var crdname string

	crdname = reflect.TypeOf(v1.TelemetryReport{}).Name()
	err = c.createCRD(v1.CRDFullContivTelemetryReportsName,
		v1.CRDGroup,
		v1.CRDGroupVersion,
		v1.CRDContivTelemetryReportPlural,
		crdname)

	if err != nil {
		c.Log.Error("Error initializing CRD")
		return err
	}

	sharedFactory := factory.NewSharedInformerFactory(c.CrdClient, time.Second*30)
	c.telemetryInformer = sharedFactory.Telemetry().V1().TelemetryReports()
	c.telemetryReportLister = c.telemetryInformer.Lister()

	// Create a new queue in that when the informer gets a resource from listing or watching,
	// adding the identifying key to the queue for the handler
	c.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Add event handlers to handle the three types of events for resources (add, update, delete)
	c.telemetryInformer.Informer().AddEventHandler(k8sCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// Converting the resource object into a key
			key, err := k8sCache.MetaNamespaceKeyFunc(obj)
			c.Log.Debug("Add ContivTelemetry resource: %s", key)
			if err == nil {
				// Adding the key to the queue for the handler to get
				c.queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := k8sCache.MetaNamespaceKeyFunc(newObj)
			c.Log.Debug("Update ContivTelemetry resource: %s", key)
			if err == nil {
				c.queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := k8sCache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			c.Log.Debug("Delete ContivTelemetry resource: %s", key)
			if err == nil {
				c.queue.Add(key)
			}
		},
	})

	c.eventHandler = handler.TelemetryHandler{}

	return nil
}

// Run this in the plugin_crd_impl, it's the controller loop
func (c *Controller) Run(ctx <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items and shutdown when done
	defer c.queue.ShutDown()

	c.Log.Info("Controller-Run: Initiating...")

	// runs the informer to list and watch on a goroutine
	go c.telemetryInformer.Informer().Run(ctx)

	// populate resources one after synchronization
	if !k8sCache.WaitForCacheSync(ctx, c.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Error syncing cache"))
		return
	}
	c.Log.Info("Controller.Run: cache sync complete")

	// runWorker method runs every second using a stop channel
	wait.Until(c.runWorker, time.Second, ctx)
}

// HasSynced indicates when the controller is synced up with the K8s.
func (c *Controller) HasSynced() bool {
	return c.telemetryInformer.Informer().HasSynced()
}

// runWorker processes new items in the queue
func (c *Controller) runWorker() {
	c.Log.Info("Controller-runWorker: Starting..")

	// invoke processNextItem to fetch and consume the next change
	// to a watched or listed resource
	for c.processNextItem() {
		c.Log.Info("Controller-runWorker: processing next item...")
	}

	c.Log.Info("Controller-runWorker: Completed")
}

// processNextItem retrieves next queued item, acts accordingly for object CRUD
func (c *Controller) processNextItem() bool {
	c.Log.Info("Controller.processNextItem: start")

	// get the next item (blocking) from the queue and process or
	// quit if shutdown requested
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	// assert the string out of the key (format `namespace/name`)
	keyRaw := key.(string)

	// Get the string key and get the object out of the indexer.
	// item is the object of the resource, it was created if exists = true
	//
	// on error retry the queue key given number of times (5 here)
	// on failure forget the queue key and throw an error
	item, exists, err := c.telemetryInformer.Informer().GetIndexer().GetByKey(keyRaw)
	if err != nil {
		if c.queue.NumRequeues(key) < 5 {
			c.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			c.queue.AddRateLimited(key)
		} else {
			c.Log.Errorf("Controller.processNextItem: Failed processing item with key: %s, error: %v, retrying...", key, err)
			c.queue.Forget(key)
			utilruntime.HandleError(err)
		}
	}

	// if item exists run the ObjectCreated method (item created or updated)
	// if item does not exist run the ObjectDeleted method (item deleted)
	//
	// in every case forget the key from the queue
	if exists {
		c.Log.Infof("Controller.processNextItem: object created detected: %s", keyRaw)
		c.eventHandler.ObjectCreated(item)
		c.queue.Forget(key)
	} else {
		c.Log.Infof("Controller.processNextItem: object deleted detected: %s", keyRaw)
		c.eventHandler.ObjectDeleted(item)
		c.queue.Forget(key)
	}

	// keep the worker loop running by returning true
	return true
}

// Create the CRD resource, ignore error if it already exists
func (c *Controller) createCRD(FullName, Group, Version, Plural, Name string) error {

	var validation *apiextv1beta1.CustomResourceValidation
	switch Name {
	case "TelemetryReport":
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
	_, err := c.APIClient.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
	if apierrors.IsAlreadyExists(err) {
		return nil
	}

	return err
}

// contivTelemetryReportValidation generates OpenAPIV3 validator for CrdExample CRD
func contivTelemetryReportValidation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {},
			},
		},
	}
	return validation
}

//GenerateCRDReport updates the CRD status in Kubernetes with the current status from the sfc-controller
func (cr *CRDReport) GenerateCRDReport() {
	// Fetch crdContivTelemetry from K8s cache
	// The name in sfc is the namespace/name, which is the "namespace key". Split it out.

	tc := cr.Ctlr

	key := "default/default-telemetry"
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return
	}

	var crdTelemetryReport *v1.TelemetryReport
	shouldCreate := false

	crdTelemetryReport, errGet := tc.telemetryReportLister.TelemetryReports(namespace).Get(name)
	if errGet != nil {
		cr.Log.Errorf("Could not get '%s' with namespace '%s', err: %v", name, namespace, errGet)

		crdTelemetryReport = &v1.TelemetryReport{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			TypeMeta: meta_v1.TypeMeta{
				Kind:       "TelemetryReport",
				APIVersion: v1.CRDGroupVersion,
			},
			Spec: v1.TelemetryReportSpec{
				ReportPollingPeriodSeconds: 10,
			},
		}

		shouldCreate = true
	}

	crdTelemetryReportCopy := crdTelemetryReport.DeepCopy()

	for _, node := range cr.VppCache.RetrieveAllNodes() {
		crdTelemetryReportCopy.Status.Nodes = append(crdTelemetryReportCopy.Status.Nodes, *node)
	}

	crdTelemetryReportCopy.Status.Reports = cr.Report.RetrieveReport().DeepCopy()

	// Until #38113 is merged, we must use Update instead of UpdateStatus to
	// update the Status block of the NetworkNode resource. UpdateStatus will not
	// allow changes to the Spec of the resource, which is ideal for ensuring
	// nothing other than resource status has been updated.

	if shouldCreate {
		cr.Log.Debug("Create '%s' namespace '%s, and value: %v", name, namespace, crdTelemetryReportCopy)
		_, err = tc.CrdClient.TelemetryV1().TelemetryReports(namespace).Create(crdTelemetryReportCopy)
		if err != nil {
			cr.Log.Errorf("Could not create '%s'  err: %v, namespace '%s', and value: %v",
				name, err, namespace, crdTelemetryReportCopy)
		}
	} else {
		cr.Log.Debug("Update '%s' namespace '%s, and value: %v", name, namespace, crdTelemetryReportCopy)
		_, err := tc.CrdClient.TelemetryV1().TelemetryReports(namespace).Update(crdTelemetryReportCopy)
		if err != nil {
			cr.Log.Errorf("Could not update '%s'  err: %v, namespace '%s', and value: %v",
				name, err, namespace, crdTelemetryReportCopy)
		}
	}
}
