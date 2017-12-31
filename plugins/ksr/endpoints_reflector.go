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
	"sync"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	// proto "github.com/contiv/vpp/plugins/ksr/model/service"
)

// EndpointsReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s service endpoints.
// Protobuf-modelled changes are published into the selected key-value store.
type EndpointsReflector struct {
	ReflectorDeps

	stopCh <-chan struct{}
	wg     *sync.WaitGroup

	k8sEndpointsStore      cache.Store
	k8sEndpointsController cache.Controller
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (epr *EndpointsReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	epr.Log.Info("EndpointsReflector Init()")
	epr.stopCh = stopCh2
	epr.wg = wg

	restClient := epr.K8sClientset.CoreV1().RESTClient()
	listWatch := epr.K8sListWatch.NewListWatchFromClient(restClient, "endpoints", "", fields.Everything())
	epr.k8sEndpointsStore, epr.k8sEndpointsController = epr.K8sListWatch.NewInformer(
		listWatch,
		&coreV1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eps, ok := obj.(*coreV1.Endpoints)
				if !ok {
					epr.Log.Warn("Failed to cast newly created endpoints object")
				} else {
					epr.addEndpoints(eps)
				}
			},
			DeleteFunc: func(obj interface{}) {
				eps, ok := obj.(*coreV1.Endpoints)
				if !ok {
					epr.Log.Warn("Failed to cast removed endpoints object")
				} else {
					epr.deleteEndpoints(eps)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				epsOld, ok1 := oldObj.(*coreV1.Endpoints)
				epsNew, ok2 := newObj.(*coreV1.Endpoints)
				if !ok1 || !ok2 {
					epr.Log.Warn("Failed to cast changed endpoints object")
				} else {
					epr.updateEndpoints(epsNew, epsOld)
				}
			},
		},
	)
	return nil
}

// addEndpoints adds state data of a newly created K8s endpoints into the data store.
func (epr *EndpointsReflector) addEndpoints(eps *coreV1.Endpoints) {
	epr.Log.WithField("endpoints", eps).Info("Endpoints added")
	// endpointsProto := epr.endpointsToProto(eps)
	// key := proto.Key(endpoints.GetName(), endpoints.GetNamespace())
	// err := epr.Publish.Put(key, endpointsProto)
	// if err != nil {
	//	epr.Log.WithField("err", err).Warn("Failed to add endpoints state data into the data store")
	//}
}

// deleteEndpoints deletes state data of a removed K8s service from the data store.
func (epr *EndpointsReflector) deleteEndpoints(eps *coreV1.Endpoints) {
	epr.Log.WithField("endpoints", eps).Info("Endpoints removed")
	// key := proto.Key(eps.GetName(), eps.GetNamespace())
	// _, err := epr.Publish.Delete(key)
	// if err != nil {
	//	epr.Log.WithField("err", err).Warn("Failed to remove endpoints state data from the data store")
	// }
}

// updateEndpoints updates state data of a changes K8s endpoints in the data store.
func (epr *EndpointsReflector) updateEndpoints(epsNew, epsOld *coreV1.Endpoints) {
	epr.Log.WithFields(map[string]interface{}{"endpoints-old": epsOld, "endpoints-new": epsNew}).Info("Endpoints updated")
	// endpointsProto := epr.endpointsToProto(epsNew)
	// key := proto.Key(epsNew.GetName(), epsNew.GetNamespace())
	// err := epr.Publish.Put(key, endpointsProto)
	// if err != nil {
	//	epr.Log.WithField("err", err).Warn("Failed to update endpoints state data in the data store")
	// }
}

// Start activates the K8s subscription.
func (epr *EndpointsReflector) Start() {
	epr.wg.Add(1)
	go epr.run()
}

// run runs k8s subscription in a separate go routine.
func (epr *EndpointsReflector) run() {
	defer epr.wg.Done()
	epr.Log.Info("Endpoints reflector is now running")
	epr.k8sEndpointsController.Run(epr.stopCh)
	epr.Log.Info("Stopping Endpoints reflector")
}

// Close does nothing for this particular reflector.
func (epr *EndpointsReflector) Close() error {
	return nil
}



