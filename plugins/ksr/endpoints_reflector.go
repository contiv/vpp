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
	"k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/ksr/model/endpoints"
	"github.com/gogo/protobuf/proto"
)

// EndpointsReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s service endpoints.
// Protobuf-modelled changes are published into the selected key-value store.
type EndpointsReflector struct {
	Reflector
}

// Ignored endpoints.
const (
	epKubeCtlMgr = "kube-controller-manager"
	epKubeSched  = "kube-scheduler"
)

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (epr *EndpointsReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	epsReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				epr.addEndpoints(obj)
			},
			DeleteFunc: func(obj interface{}) {
				epr.deleteEndpoints(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				epr.updateEndpoints(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &endpoints.Endpoints{}
		},
		K8s2NodeFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sEps, ok := k8sObj.(*coreV1.Endpoints)
			if !ok {
				epr.Log.Errorf("endpoints syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return epr.endpointsToProto(k8sEps), endpoints.Key(k8sEps.Name, k8sEps.Namespace), true
		},
	}

	return epr.ksrInit(stopCh2, wg, endpoints.KeyPrefix(), "endpoints", &coreV1.Endpoints{}, epsReflectorFuncs)
}

// addEndpoints adds state data of a newly created K8s endpoints into the data store.
func (epr *EndpointsReflector) addEndpoints(obj interface{}) {
	eps, ok := obj.(*coreV1.Endpoints)
	if !ok {
		epr.Log.Warn("Failed to cast newly created endpoints object")
		epr.stats.ArgErrors++
		return
	}

	if eps.GetName() == epKubeCtlMgr || eps.GetName() == epKubeSched {
		// Ignore notification.
		return
	}

	epr.Log.WithField("endpoints", obj).Info("addEndpoints")
	endpointsProto := epr.endpointsToProto(eps)
	key := endpoints.Key(eps.GetName(), eps.GetNamespace())
	epr.ksrAdd(key, endpointsProto)
}

// deleteEndpoints deletes state data of a removed K8s service from the data store.
func (epr *EndpointsReflector) deleteEndpoints(obj interface{}) {
	eps, ok := obj.(*coreV1.Endpoints)
	if !ok {
		epr.Log.Warn("Failed to cast newly created endpoints object")
		epr.stats.ArgErrors++
		return
	}

	if eps.GetName() == epKubeCtlMgr || eps.GetName() == epKubeSched {
		// Ignore notification.
		return
	}

	epr.Log.WithField("endpoints", obj).Info("deleteEndpoints")
	key := endpoints.Key(eps.GetName(), eps.GetNamespace())
	epr.ksrDelete(key)
}

// updateEndpoints updates state data of a changed K8s endpoints in the data store.
func (epr *EndpointsReflector) updateEndpoints(oldObj, newObj interface{}) {
	epsOld, ok1 := oldObj.(*coreV1.Endpoints)
	epsNew, ok2 := newObj.(*coreV1.Endpoints)
	if !ok1 || !ok2 {
		epr.Log.Warn("Failed to cast changed service object")
		epr.stats.ArgErrors++
		return
	}

	if epsOld.GetName() == epKubeCtlMgr || epsOld.GetName() == epKubeSched {
		// Ignore notification.
		return
	}

	epr.Log.WithFields(map[string]interface{}{"endpoints-old": epsOld, "endpoints-new": epsNew}).
		Info("Endpoints updated")

	epsProtoNew := epr.endpointsToProto(epsNew)
	epsProtoOld := epr.endpointsToProto(epsOld)
	key := endpoints.Key(epsNew.GetName(), epsNew.GetNamespace())

	epr.ksrUpdate(key, epsProtoOld, epsProtoNew)
}

// endpointsToProto converts endpoints data from the k8s representation into
// our protobuf-modelled data structure.
func (epr *EndpointsReflector) endpointsToProto(eps *coreV1.Endpoints) *endpoints.Endpoints {
	epsProto := &endpoints.Endpoints{}
	epsProto.Name = eps.GetName()
	epsProto.Namespace = eps.GetNamespace()

	var subsets []*endpoints.EndpointSubset
	for _, ss := range eps.Subsets {
		pss := &endpoints.EndpointSubset{}

		var addresses []*endpoints.EndpointSubset_EndpointAddress
		for _, addr := range ss.Addresses {
			addresses = append(addresses, addressToProto(&addr))
		}
		pss.Addresses = addresses

		var notReadyAddresses []*endpoints.EndpointSubset_EndpointAddress
		for _, addr := range ss.NotReadyAddresses {
			notReadyAddresses = append(notReadyAddresses, addressToProto(&addr))
		}
		pss.NotReadyAddresses = notReadyAddresses

		var ports []*endpoints.EndpointSubset_EndpointPort
		for _, port := range ss.Ports {
			ports = append(ports, &endpoints.EndpointSubset_EndpointPort{
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
func addressToProto(addr *coreV1.EndpointAddress) *endpoints.EndpointSubset_EndpointAddress {
	protoAddr := &endpoints.EndpointSubset_EndpointAddress{}
	protoAddr.Ip = addr.IP
	protoAddr.HostName = addr.Hostname

	if addr.NodeName != nil {
		protoAddr.NodeName = *addr.NodeName
	}

	if addr.TargetRef != nil {
		protoAddr.TargetRef = &endpoints.ObjectReference{
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
