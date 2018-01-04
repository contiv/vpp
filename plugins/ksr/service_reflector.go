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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ServiceReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s services.
// Protobuf-modelled changes are published into the selected key-value store.
type ServiceReflector struct {
	ReflectorDeps

	stopCh               <-chan struct{}
	wg                   *sync.WaitGroup
	k8sServiceStore      cache.Store
	k8sServiceController cache.Controller
	stats                ReflectorStats
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s services. The subscription does not become active until Start()
// is called.
func (sr *ServiceReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	sr.stopCh = stopCh2
	sr.wg = wg

	restClient := sr.K8sClientset.CoreV1().RESTClient()
	listWatch := sr.K8sListWatch.NewListWatchFromClient(restClient, "services", "", fields.Everything())
	sr.k8sServiceStore, sr.k8sServiceController = sr.K8sListWatch.NewInformer(
		listWatch,
		&coreV1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				svc, ok := obj.(*coreV1.Service)
				if !ok {
					sr.Log.Warn("Failed to cast newly created service object")
					sr.stats.NumArgErrors++
				} else {
					sr.addService(svc)
				}
			},
			DeleteFunc: func(obj interface{}) {
				svc, ok := obj.(*coreV1.Service)
				if !ok {
					sr.Log.Warn("Failed to cast removed service object")
					sr.stats.NumArgErrors++
				} else {
					sr.deleteService(svc)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				svcOld, ok1 := oldObj.(*coreV1.Service)
				svcNew, ok2 := newObj.(*coreV1.Service)
				if !ok1 || !ok2 {
					sr.Log.Warn("Failed to cast changed service object")
					sr.stats.NumArgErrors++
				} else {
					sr.updateService(svcNew, svcOld)
				}
			},
		},
	)
	return nil
}

// GetStats returns the Service Reflector usage statistics
func (sr *ServiceReflector) GetStats() *ReflectorStats {
	return &sr.stats
}

// addService adds state data of a newly created K8s service into the data store.
func (sr *ServiceReflector) addService(svc *coreV1.Service) {
	sr.Log.WithField("service", svc).Info("Service added")
	serviceProto := sr.serviceToProto(svc)
	sr.Log.WithField("serviceProto", serviceProto).Info("Service converted")
	key := proto.Key(svc.GetName(), svc.GetNamespace())
	err := sr.Publish.Put(key, serviceProto)

	if err != nil {
		sr.Log.WithField("err", err).Warn("Failed to add service state data into the data store")
		sr.stats.NumAddErrors++
		return
	}

	sr.stats.NumAdds++
}

// deleteService deletes state data of a removed K8s service from the data store.
func (sr *ServiceReflector) deleteService(svc *coreV1.Service) {
	sr.Log.WithField("service", svc).Info("Service removed")
	key := proto.Key(svc.GetName(), svc.GetNamespace())
	_, err := sr.Publish.Delete(key)
	if err != nil {
		sr.Log.WithField("err", err).Warn("Failed to remove service state data from the data store")
		sr.stats.NumDelErrors++
		return
	}

	sr.stats.NumDeletes++
}

// updateService updates state data of a changes K8s service in the data store.
func (sr *ServiceReflector) updateService(svcNew, svcOld *coreV1.Service) {
	sr.Log.WithFields(map[string]interface{}{"service-old": svcOld, "service-new": svcNew}).Info("Service updated")
	svcProtoOld := sr.serviceToProto(svcOld)
	svcProtoNew := sr.serviceToProto(svcNew)

	if !reflect.DeepEqual(svcProtoNew, svcProtoOld) {
		sr.Log.WithFields(map[string]interface{}{"namespace": svcNew.Namespace, "name": svcNew.Name}).
			Debug("Service changed, updating in Etcd")
		key := proto.Key(svcNew.GetName(), svcNew.GetNamespace())
		err := sr.Publish.Put(key, svcProtoNew)

		if err != nil {
			sr.Log.WithField("err", err).Warn("Failed to update service state data in the data store")
			sr.stats.NumUpdErrors++
			return
		}

		sr.stats.NumUpdates++
	}
}

// serviceToProto converts service state data from the k8s representation into
// our protobuf-modelled data structure.
func (sr *ServiceReflector) serviceToProto(svc *coreV1.Service) *proto.Service {
	svcProto := &proto.Service{}
	svcProto.Name = svc.GetName()
	svcProto.Namespace = svc.GetNamespace()

	var svcPorts []*proto.Service_ServicePort
loop:
	for _, port := range svc.Spec.Ports {
		svcp := &proto.Service_ServicePort{}
		svcp.Name = port.Name
		svcp.NodePort = port.NodePort
		svcp.Port = port.Port
		svcp.Protocol = string(port.Protocol)

		svcp.TargetPort = &proto.Service_ServicePort_IntOrString{}
		switch port.TargetPort.Type {
		case intstr.Int:
			svcp.TargetPort.Type = proto.Service_ServicePort_IntOrString_NUMBER
			svcp.TargetPort.IntVal = port.TargetPort.IntVal
		case intstr.String:
			svcp.TargetPort.Type = proto.Service_ServicePort_IntOrString_STRING
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

// Start activates the K8s subscription.
func (sr *ServiceReflector) Start() {
	sr.wg.Add(1)
	go sr.run()
}

// run runs k8s subscription in a separate go routine.
func (sr *ServiceReflector) run() {
	defer sr.wg.Done()
	sr.Log.Info("Service reflector is now running")
	sr.k8sServiceController.Run(sr.stopCh)
	sr.Log.Info("Stopping Service reflector")
}

// Close does nothing for this particular reflector.
func (sr *ServiceReflector) Close() error {
	return nil
}
