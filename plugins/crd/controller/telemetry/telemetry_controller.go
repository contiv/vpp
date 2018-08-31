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
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/handler"
	"github.com/contiv/vpp/plugins/crd/handler/telemetry"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"
	"github.com/contiv/vpp/plugins/crd/utils"
	"github.com/ligato/cn-infra/logging"

	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	factory "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions"
	informers "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/telemetry/v1"
	listers "github.com/contiv/vpp/plugins/crd/pkg/client/listers/telemetry/v1"
)

const maxRetries = 5

var serverStartTime time.Time

// Controller struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching) queueing, and
// handling of resource changes
type Controller struct {
	Deps

	CrdClient *crdClientSet.Clientset
	APIClient *apiextcs.Clientset

	clientset kubernetes.Interface
	queue     workqueue.RateLimitingInterface
	// Telemetry CRD specifics
	telemetryInformer     informers.TelemetryReportInformer
	telemetryReportLister listers.TelemetryReportLister
	// event handlers for Telemetry CRDs
	eventHandler handler.Handler
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

// Event indicate the informerEvent
type Event struct {
	key         string
	eventType   string
	resource    interface{}
	oldResource interface{}
}

// Init performs the initialization of Telemetry Controller
func (c *Controller) Init() error {

	var event Event

	c.Log.Info("Telemetry-Controller: initializing...")

	crdName := reflect.TypeOf(v1.TelemetryReport{}).Name()
	err := c.createCRD(v1.CRDFullContivTelemetryReportsName,
		v1.CRDGroup,
		v1.CRDGroupVersion,
		v1.CRDContivTelemetryReportPlural,
		crdName)

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
			event.key, err = k8sCache.MetaNamespaceKeyFunc(obj)
			event.eventType = "create"
			c.Log.Infof("Add Telemetry resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			event.key, err = k8sCache.MetaNamespaceKeyFunc(newObj)
			event.resource = newObj
			event.oldResource = oldObj
			event.eventType = "update"
			c.Log.Infof("Update Telemetry resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
		DeleteFunc: func(obj interface{}) {
			event.key, err = k8sCache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			event.eventType = "delete"
			c.Log.Infof("Delete Telemetry resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
	})

	c.eventHandler = &telemetry.Handler{}

	return nil
}

// Run this in the plugin_crd_impl, it's the controller loop
func (c *Controller) Run(ctx <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items and shutdown when done
	defer c.queue.ShutDown()

	c.Log.Info("Telemetry-Controller: starting...")

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
	c.Log.Info("Telemetry-Controller: running...")

	// invoke processNextItem to fetch and consume the next change
	// to a watched or listed resource
	for c.processNextItem() {
		c.Log.Info("Telemetry-Controller-runWorker: processing next item...")
	}

	c.Log.Info("Telemetry-Controller-runWorker: Completed")
}

// processNextItem retrieves next queued item, acts accordingly for object CRUD
func (c *Controller) processNextItem() bool {
	// get the next item (blocking) from the queue and process or
	// quit if shutdown requested
	event, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(event)

	err := c.processItem(event.(Event))
	if err == nil {
		// If there is no error reset the rate limit counters
		c.queue.Forget(event)
	} else if c.queue.NumRequeues(event) < maxRetries {
		c.Log.Errorf("Error processing %s (will retry): %v", event.(Event).key, err)
		c.queue.AddRateLimited(event)
	} else {
		// err != nil and too many retries
		c.Log.Errorf("Error processing %s (giving up): %v", event.(Event).key, err)
		c.queue.Forget(event)
		utilruntime.HandleError(err)
	}

	// keep the worker loop running by returning true
	return true
}

// processItem processes the next item from the queue and send the event update
// to the telemetry event handler
func (c *Controller) processItem(event Event) error {

	// process events based on its type
	switch event.eventType {
	case "create":
		// get object's metadata
		objectMeta := utils.GetObjectMetaData(event.resource)
		// compare CreationTimestamp and serverStartTime and alert only on latest events
		if objectMeta.CreationTimestamp.Sub(serverStartTime).Seconds() > 0 {
			c.eventHandler.ObjectCreated(event.resource)
			return nil
		}
	case "update":
		c.eventHandler.ObjectUpdated(event.oldResource, event.resource)
		return nil
	case "delete":
		c.eventHandler.ObjectDeleted(event.resource)
		return nil
	}
	return nil
}

// Create the CRD resource, ignore error if it already exists
func (c *Controller) createCRD(FullName, Group, Version, Plural, Name string) error {
	c.Log.Info("Creating Telemetry CRD")

	var validation *apiextv1beta1.CustomResourceValidation
	switch Name {
	case "TelemetryReport":
		validation = telemetryReportValidation()
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

// telemetryReportValidation generates OpenAPIV3 validator for Telemetry CRD
func telemetryReportValidation() *apiextv1beta1.CustomResourceValidation {
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
	namespace, name, err := k8sCache.SplitMetaNamespaceKey(key)
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
			ObjectMeta: meta.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			TypeMeta: meta.TypeMeta{
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
