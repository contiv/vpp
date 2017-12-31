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
	"reflect"
	"sync"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/ksr/model/endpoints"
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
	endpointsProto := epr.endpointsToProto(eps)
	epr.Log.WithField("endpointsProto", endpointsProto).Info("Endpoints converted")
	key := proto.Key(eps.GetName(), eps.GetNamespace())
	err := epr.Publish.Put(key, endpointsProto)
	if err != nil {
		epr.Log.WithField("err", err).Warn("Failed to add endpoints state data into the data store")
	}
}

// deleteEndpoints deletes state data of a removed K8s service from the data store.
func (epr *EndpointsReflector) deleteEndpoints(eps *coreV1.Endpoints) {
	epr.Log.WithField("endpoints", eps).Info("Endpoints removed")
	key := proto.Key(eps.GetName(), eps.GetNamespace())
	_, err := epr.Publish.Delete(key)
	if err != nil {
		epr.Log.WithField("err", err).Warn("Failed to remove endpoints state data from the data store")
	}
}

// updateEndpoints updates state data of a changes K8s endpoints in the data store.
func (epr *EndpointsReflector) updateEndpoints(epsNew, epsOld *coreV1.Endpoints) {
	epr.Log.WithFields(map[string]interface{}{"endpoints-old": epsOld, "endpoints-new": epsNew}).Info("Endpoints updated")
	epsProtoNew := epr.endpointsToProto(epsNew)
	epsProtoOld := epr.endpointsToProto(epsOld)

	if !reflect.DeepEqual(epsProtoNew, epsProtoOld) {
		epr.Log.WithFields(map[string]interface{}{"namespace": epsNew.Namespace, "name": epsNew.Name}).
			Info("Endpoints changed, updating in Etcd")
		key := proto.Key(epsNew.GetName(), epsNew.GetNamespace())
		err := epr.Publish.Put(key, epsProtoNew)
		if err != nil {
			epr.Log.WithField("err", err).Warn("Failed to update endpoints state data in the data store")
		}
	}
}

// endpointsToProto converts endpoints data from the k8s representation into
// our protobuf-modelled data structure.
func (epr *EndpointsReflector) endpointsToProto(eps *coreV1.Endpoints) *proto.Endpoints {
	epsProto := &proto.Endpoints{}
	epsProto.Name = eps.GetName()
	epsProto.Namespace = eps.GetNamespace()

	var subsets []*proto.EndpointSubset
	for _, ss := range eps.Subsets {
		pss := &proto.EndpointSubset{}

		var addresses []*proto.EndpointSubset_EndpointAddress
		for _, addr := range ss.Addresses {
			addresses = append(addresses, addressToProto(&addr))
		}
		pss.Addresses = addresses

		var notReadyAddresses []*proto.EndpointSubset_EndpointAddress
		for _, addr := range ss.NotReadyAddresses {
			notReadyAddresses = append(notReadyAddresses, addressToProto(&addr))
		}
		pss.NotReadyAddresses = notReadyAddresses

		var ports []*proto.EndpointSubset_EndpointPort
		for _, port := range ss.Ports {
			ports = append(ports, &proto.EndpointSubset_EndpointPort{
				Name:     port.Name,
				Port:     port.Port,
				Protocol: string(port.Protocol),
			})
		}
		pss.Ports = ports

		subsets = append(subsets, pss)
	}

	epsProto.EndpointSubsets = subsets

	return epsProto
}

// addressToProto converts an endpoint address from the k8s representation
// into our protobuf-modelled data structure.
func addressToProto(addr *coreV1.EndpointAddress) *proto.EndpointSubset_EndpointAddress {
	protoAddr := &proto.EndpointSubset_EndpointAddress{}
	protoAddr.Ip = addr.IP
	protoAddr.HostName = addr.Hostname

	if addr.NodeName != nil {
		protoAddr.NodeName = *addr.NodeName
	}

	if addr.TargetRef != nil {
		protoAddr.TargetRef = &proto.ObjectReference{
			Kind:            addr.TargetRef.Kind,
			Namespace:       addr.TargetRef.Namespace,
			Name:            addr.TargetRef.Name,
			Uid:             string(addr.TargetRef.UID),
			ApiVersion:      addr.TargetRef.APIVersion,
			ResourceVersion: addr.TargetRef.ResourceVersion,
		}
	}

	return protoAddr
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
