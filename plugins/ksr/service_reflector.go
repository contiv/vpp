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

	"github.com/golang/protobuf/proto"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/ksr/model/service"
)

// ServiceReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s services.
// Protobuf-modelled changes are published into the selected key-value store.
type ServiceReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (sr *ServiceReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {

	serviceReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				sr.addService(obj)
			},
			DeleteFunc: func(obj interface{}) {
				sr.deleteService(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				sr.updateService(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &service.Service{}
		},
		K8s2ProtoFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sSvc, ok := k8sObj.(*coreV1.Service)
			if !ok {
				sr.Log.Errorf("service syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return sr.serviceToProto(k8sSvc), service.Key(k8sSvc.Name, k8sSvc.Namespace), true
		},
	}

	return sr.ksrInit(stopCh2, wg, service.KeyPrefix(), "services", &coreV1.Service{}, serviceReflectorFuncs)
}

// addService adds state data of a newly created K8s service into the data store.
func (sr *ServiceReflector) addService(obj interface{}) {
	sr.Log.WithField("service", obj).Info("addService")

	svc, ok := obj.(*coreV1.Service)
	if !ok {
		sr.Log.Warn("Failed to cast newly created service object")
		sr.stats.ArgErrors++
		return
	}

	serviceProto := sr.serviceToProto(svc)
	key := service.Key(svc.GetName(), svc.GetNamespace())
	sr.ksrAdd(key, serviceProto)
}

// deleteService deletes state data of a removed K8s service from the data store.
func (sr *ServiceReflector) deleteService(obj interface{}) {
	sr.Log.WithField("service", obj).Info("deleteService")

	svc, ok := obj.(*coreV1.Service)
	if !ok {
		sr.Log.Warn("Failed to cast removed service object")
		sr.stats.ArgErrors++
		return
	}

	key := service.Key(svc.GetName(), svc.GetNamespace())
	sr.ksrDelete(key)
}

// updateService updates state data of a changes K8s service in the data store.
func (sr *ServiceReflector) updateService(oldObj, newObj interface{}) {
	svcOld, ok1 := oldObj.(*coreV1.Service)
	svcNew, ok2 := newObj.(*coreV1.Service)
	if !ok1 || !ok2 {
		sr.Log.Warn("Failed to cast changed service object")
		sr.stats.ArgErrors++
		return
	}
	sr.Log.WithFields(map[string]interface{}{"service-old": svcOld, "service-new": svcNew}).
		Info("Service updated")

	svcProtoOld := sr.serviceToProto(svcOld)
	svcProtoNew := sr.serviceToProto(svcNew)
	key := service.Key(svcNew.GetName(), svcNew.GetNamespace())

	sr.ksrUpdate(key, svcProtoOld, svcProtoNew)
}

// serviceToProto converts service state data from the k8s representation into
// our protobuf-modelled data structure.
func (sr *ServiceReflector) serviceToProto(svc *coreV1.Service) *service.Service {
	svcProto := &service.Service{}
	svcProto.Name = svc.GetName()
	svcProto.Namespace = svc.GetNamespace()

	var svcPorts []*service.Service_ServicePort
loop:
	for _, port := range svc.Spec.Ports {
		svcp := &service.Service_ServicePort{}
		svcp.Name = port.Name
		svcp.NodePort = port.NodePort
		svcp.Port = port.Port
		svcp.Protocol = string(port.Protocol)

		svcp.TargetPort = &service.Service_ServicePort_IntOrString{}
		switch port.TargetPort.Type {
		case intstr.Int:
			svcp.TargetPort.Type = service.Service_ServicePort_IntOrString_NUMBER
			svcp.TargetPort.IntVal = port.TargetPort.IntVal
		case intstr.String:
			svcp.TargetPort.Type = service.Service_ServicePort_IntOrString_STRING
			svcp.TargetPort.StringVal = port.TargetPort.StrVal
		default:
			sr.Log.WithField("target port", port.TargetPort.Type).Error("Unknown target port type")
			continue loop
		}

		svcPorts = append(svcPorts, svcp)
	}
	svcProto.Port = svcPorts

	svcProto.Selector = svc.Spec.Selector
	svcProto.ClusterIp = svc.Spec.ClusterIP
	svcProto.ServiceType = string(svc.Spec.Type)
	svcProto.ExternalIps = svc.Spec.ExternalIPs
	svcProto.SessionAffinity = string(svc.Spec.SessionAffinity)
	svcProto.LoadbalancerIp = svc.Spec.LoadBalancerIP
	svcProto.LoadbalancerSourceRanges = svc.Spec.LoadBalancerSourceRanges
	svcProto.ExternalTrafficPolicy = string(svc.Spec.ExternalTrafficPolicy)
	svcProto.HealthCheckNodePort = svc.Spec.HealthCheckNodePort

	return svcProto
}
