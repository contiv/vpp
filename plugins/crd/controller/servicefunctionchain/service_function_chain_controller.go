// Copyright (c) 2019 Cisco and/or its affiliates.
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

package servicefunctionchain

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/handler"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	"github.com/contiv/vpp/plugins/crd/utils"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/logging"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sCache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"time"

	sf "github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	factory "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions"
	informers "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/contivppio/v1"
	listers "github.com/contiv/vpp/plugins/crd/pkg/client/listers/contivppio/v1"
	"reflect"
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

	queue workqueue.RateLimitingInterface
	// ServiceFunctionChain CRD specifics
	serviceFunctionChainInformer informers.ServiceFunctionChainInformer
	serviceFunctionChainLister   listers.ServiceFunctionChainLister
	// event handlers for CustomNetwork CRDs
	eventHandler handler.Handler
}

// Deps defines dependencies for the CRD plugin
type Deps struct {
	Log     logging.Logger
	Publish *kvdbsync.Plugin // KeyProtoValWriter does not define Delete
}

// Event indicate the informerEvent
type Event struct {
	key         string
	eventType   string
	resource    interface{}
	oldResource interface{}
}

// Init performs the initialization of NodeConfig Controller
func (c *Controller) Init() error {

	var (
		event Event
		err   error
	)

	c.Log.Info("ServiceFunctionChain-Controller: initializing...")

	crdName := reflect.TypeOf(v1.ServiceFunctionChain{}).Name()
	err = c.createCRD("servicefunctionchains"+"."+contivppio.GroupName,
		contivppio.GroupName,
		"v1",
		"servicefunctionchains",
		crdName)

	if err != nil {
		c.Log.Errorf("Error initializing CRD: %v", err)
		return err
	}

	sharedFactory := factory.NewSharedInformerFactory(c.CrdClient, time.Second*30)
	c.serviceFunctionChainInformer = sharedFactory.Contivpp().V1().ServiceFunctionChains()
	c.serviceFunctionChainLister = c.serviceFunctionChainInformer.Lister()

	// Create a new queue in that when the informer gets a resource from listing or watching,
	// adding the identifying key to the queue for the handler
	c.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Add event handlers to handle the three types of events for resources (add, update, delete)
	c.serviceFunctionChainInformer.Informer().AddEventHandler(k8sCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event.key, err = k8sCache.MetaNamespaceKeyFunc(obj)
			event.eventType = "create"
			event.resource = obj
			c.Log.Infof("Add ServiceFunctionChain resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			event.key, err = k8sCache.MetaNamespaceKeyFunc(newObj)
			event.resource = newObj
			event.oldResource = oldObj
			event.eventType = "update"
			c.Log.Infof("Update ServiceFunctionChain resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
		DeleteFunc: func(obj interface{}) {
			event.key, err = k8sCache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			event.eventType = "delete"
			event.resource = obj
			c.Log.Infof("Delete ServiceFunctionChain resource with key: %s", event.key)
			if err == nil {
				c.queue.Add(event)
			}
		},
	})
	c.eventHandler = &sf.Handler{
		Deps: sf.Deps{
			Log:                c.Log,
			Publish:            c.Publish,
			ControllerInformer: c.serviceFunctionChainInformer,
		},
	}

	return nil
}

// Run this in the plugin_crd_impl, it's the controller loop
func (c *Controller) Run(ctx <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items and shutdown when done
	defer c.queue.ShutDown()

	c.Log.Info("ServiceFunctionChain-Controller: Starting...")

	// runs the informer to list and watch on a goroutine
	go c.serviceFunctionChainInformer.Informer().Run(ctx)

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
	return c.serviceFunctionChainInformer.Informer().HasSynced()
}

// runWorker processes new items in the queue
func (c *Controller) runWorker() {
	c.Log.Info("ServiceFunctionChain-Controller: Running..")

	// invoke processNextItem to fetch and consume the next change
	// to a watched or listed resource
	for c.processNextItem() {
		c.Log.Info("ServiceFunctionChain-Controller-runWorker: processing next item...")
	}

	c.Log.Info("ServiceFunctionChain-Controller-runWorker: Completed")
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
// to the serviceFunctionChain event handler
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
	default:
		c.Log.Warn("Unknown event type")
	}
	return nil
}

// Create the CRD resource, ignore error if it already exists
func (c *Controller) createCRD(FullName, Group, Version, Plural, Name string) error {
	c.Log.Info("Creating ServiceFunctionChain CRD")

	var validation *apiextv1beta1.CustomResourceValidation
	switch Name {
	case "ServiceFunctionChain":
		validation = serviceFunctionChainValidation()
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

// serviceFunctionChainValidation generates OpenAPIV3 validator for ServiceFunctionChain CRD
func serviceFunctionChainValidation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {},
			},
		},
	}
	return validation
}
