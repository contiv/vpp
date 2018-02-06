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
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/ligato/cn-infra/flavors/local"
)

type ServiceTestVars struct {
	k8sListWatch *mockK8sListWatch
	mockKvBroker *mockKeyProtoVaBroker
	svcReflector *ServiceReflector
	svc          *coreV1.Service
	svcTestData  []coreV1.Service
}

var serviceTestVars ServiceTestVars

func TestServiceReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	serviceTestVars.k8sListWatch = &mockK8sListWatch{}
	serviceTestVars.mockKvBroker = newMockKeyProtoValBroker()

	serviceTestVars.svcReflector = &ServiceReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("service-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: serviceTestVars.k8sListWatch,
			Broker:       serviceTestVars.mockKvBroker,
			dsSynced:     false,
			objType:      serviceObjType,
		},
	}

	serviceTestVars.svcTestData = []coreV1.Service{
		{
			// Test data 0: mocks a new object to be added or a "pre-existing"
			// object that is updated during sync
			ObjectMeta: metav1.ObjectMeta{
				Name:            "kubernetes",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/services/kubernetes",
				UID:             "8ca8bfdc-ec4c-11e7-9959-0800271d72be",
				ResourceVersion: "16",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"component: apiserver": "provider: kubernetes"},
			},
			Spec: coreV1.ServiceSpec{
				Ports: []coreV1.ServicePort{
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
						TargetPort: intstr.IntOrString{
							Type:   0,
							IntVal: 6443,
						},
					},
				},
				Selector:  map[string]string{},
				ClusterIP: "10.96.0.1",
				Type:      "ClusterIP",
			},
		},
		// Test data 1: mocks an object that updates a "pre-existing" object
		// during sync
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "kubernetes",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/services/kubernetes",
				UID:             "8ca8bfdc-ec4c-11e7-9959-0800271d72be",
				ResourceVersion: "16",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"component: apiserver": "provider: kubernetes"},
			},
			Spec: coreV1.ServiceSpec{
				Ports: []coreV1.ServicePort{
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
						TargetPort: intstr.IntOrString{
							Type:   0,
							IntVal: 6443,
						},
					},
				},
				Selector:  map[string]string{},
				ClusterIP: "10.96.0.2", // <-- Updated IP address
				Type:      "ClusterIP",
			},
		},
		// Test data 2: mocks a new object that is to be added during sync
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "calico-etcd",
				Namespace:       "kube-system",
				SelfLink:        "/api/v1/namespaces/kube-system/services/calico-etcd",
				UID:             "11401d89-ec4d-11e7-9959-0800271d72be",
				ResourceVersion: "579",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"k8s-app": "calico-etcd"},
			},
			Spec: coreV1.ServiceSpec{
				Ports: []coreV1.ServicePort{
					{
						Protocol: "TCP",
						Port:     6666,
						TargetPort: intstr.IntOrString{
							Type:   0,
							IntVal: 6666,
						},
					},
				},
				Selector: map[string]string{
					"k8s-app": "calico-etcd",
				},
				ClusterIP: "10.96.232.136",
				Type:      "ClusterIP",
			},
		},
		// Test data 3: mocks a "stale" object that is to be deleted during
		// sync
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "kube-dns",
				Namespace:       "kube-system",
				SelfLink:        "/api/v1/namespaces/kube-system/services/kube-dns",
				UID:             "8ed7c31b-ec4c-11e7-9959-0800271d72be",
				ResourceVersion: "184",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"k8s-app": "kube-dns"},
			},
			Spec: coreV1.ServiceSpec{
				Ports: []coreV1.ServicePort{
					{
						Name:     "dns",
						Protocol: "UDP",
						Port:     53,
						TargetPort: intstr.IntOrString{
							Type:   0,
							IntVal: 53,
						},
					},
					{
						Name:     "dns-tcp",
						Protocol: "TCP",
						Port:     53,
						TargetPort: intstr.IntOrString{
							Type:   0,
							IntVal: 53,
						},
					},
				},
				Selector: map[string]string{
					"k8s-app": "kube-dns",
				},
				ClusterIP: "10.96.0.10",
				Type:      "ClusterIP",
			},
		},
	}

	// The mock function returns two K8s mock service instances:
	// - a new service instance to be added to the data store
	// - a modified service instance, where and existing service in the
	//   data store is to be updated
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			// Updated value mock
			&serviceTestVars.svcTestData[1],
			// New value mock
			&serviceTestVars.svcTestData[2],
		}
	}

	// Pre-populate the mock data store with pre-existing data that is supposed
	// to be updated during the test.
	svc1 := &serviceTestVars.svcTestData[0]
	serviceTestVars.mockKvBroker.
		Put(service.Key(svc1.GetName(), svc1.GetNamespace()), serviceTestVars.svcReflector.serviceToProto(svc1))
	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during the test.
	svc2 := &serviceTestVars.svcTestData[3]
	serviceTestVars.mockKvBroker.
		Put(service.Key(svc2.GetName(), svc2.GetNamespace()), serviceTestVars.svcReflector.serviceToProto(svc2))

	statsBefore := *serviceTestVars.svcReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := serviceTestVars.svcReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	serviceTestVars.svcReflector.startDataStoreResync()

	// Wait for the initial sync to finish
	for {
		if serviceTestVars.svcReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *serviceTestVars.svcReflector.GetStats()

	gomega.Expect(serviceTestVars.mockKvBroker.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.Adds + 1).To(gomega.Equal(statsAfter.Adds))
	gomega.Expect(statsBefore.Updates + 1).Should(gomega.BeNumerically("==", statsAfter.Updates))
	gomega.Expect(statsBefore.Deletes + 1).Should(gomega.BeNumerically("==", statsAfter.Deletes))

	serviceTestVars.mockKvBroker.ClearDs()

	serviceTestVars.svc = &serviceTestVars.svcTestData[0]

	t.Run("addDeleteService", testAddDeleteService)

	serviceTestVars.mockKvBroker.ClearDs()
	t.Run("updateService", testUpdateService)

	MockK8sCache.ListFunc = nil
}

func testUpdateService(t *testing.T) {
	svcOld := serviceTestVars.svcTestData[0]
	svcNew := serviceTestVars.svcTestData[1]

	// Take a snapshot of counters
	argErrs := serviceTestVars.svcReflector.GetStats().ArgErrors
	upd := serviceTestVars.svcReflector.GetStats().Updates

	// Test update with wrong argument type
	serviceTestVars.k8sListWatch.Update(svcOld, svcNew)

	// There should be no update if we pass bad data types into update function
	gomega.Expect(argErrs + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().ArgErrors))
	gomega.Expect(upd).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Updates))

	// Test add where everything should be good
	serviceTestVars.k8sListWatch.Update(&svcOld, &svcOld)

	// There should be no update if old and new updates are the same
	gomega.Expect(upd).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Updates))

	svcNew.Spec.ClusterIP = "1.2.3.4"
	gomega.Expect(svcOld).ShouldNot(gomega.BeEquivalentTo(svcNew))
	serviceTestVars.k8sListWatch.Update(&svcOld, &svcNew)

	// There should be exactly one update because old and new data are different
	gomega.Expect(upd + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Updates))

	// Check that new data was written properly
	svcProto := &service.Service{}
	_, _, err := serviceTestVars.mockKvBroker.GetValue(service.Key(svcNew.GetName(), svcNew.GetNamespace()), svcProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(svcProto.ClusterIp).To(gomega.Equal(svcNew.Spec.ClusterIP))

}

func testAddDeleteService(t *testing.T) {
	svc := serviceTestVars.svc

	// Take a snapshot of counters
	adds := serviceTestVars.svcReflector.GetStats().Adds
	argErrs := serviceTestVars.svcReflector.GetStats().ArgErrors

	// Test add with wrong argument type
	serviceTestVars.k8sListWatch.Add(&svc)

	gomega.Expect(argErrs + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().ArgErrors))
	gomega.Expect(adds).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Adds))

	// Test add where everything should be good
	serviceTestVars.k8sListWatch.Add(svc)

	svcProto := &service.Service{}
	found, _, err := serviceTestVars.mockKvBroker.GetValue(service.Key(svc.GetName(), svc.GetNamespace()), svcProto)

	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(adds + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Adds))
	gomega.Expect(svcProto).NotTo(gomega.BeNil())
	gomega.Expect(svcProto.Name).To(gomega.Equal(svc.GetName()))
	gomega.Expect(svcProto.Namespace).To(gomega.Equal(svc.GetNamespace()))
	gomega.Expect(svcProto.ClusterIp).To(gomega.Equal(svc.Spec.ClusterIP))
	gomega.Expect(len(svcProto.Selector)).To(gomega.Equal(len(svc.Spec.Selector)))
	gomega.Expect(svcProto.ServiceType).Should(gomega.BeEquivalentTo(svc.Spec.Type))
	gomega.Expect(svcProto.LoadbalancerIp).To(gomega.Equal(svc.Spec.LoadBalancerIP))
	gomega.Expect(len(svcProto.Port)).Should(gomega.BeNumerically("==", 1))
	gomega.Expect(svcProto.Port[0].Name).To(gomega.Equal(svc.Spec.Ports[0].Name))
	gomega.Expect(svcProto.Port[0].Port).To(gomega.Equal(svc.Spec.Ports[0].Port))
	gomega.Expect(svcProto.Port[0].Protocol).Should(gomega.BeEquivalentTo(svc.Spec.Ports[0].Protocol))
	gomega.Expect(svcProto.Port[0].TargetPort.Type).To(gomega.BeEquivalentTo(svc.Spec.Ports[0].TargetPort.Type))
	gomega.Expect(svcProto.Port[0].TargetPort.IntVal).Should(gomega.BeEquivalentTo(svc.Spec.Ports[0].TargetPort.IntVal))

	// Take a snapshot of counters
	dels := serviceTestVars.svcReflector.GetStats().Deletes
	argErrs = serviceTestVars.svcReflector.GetStats().ArgErrors

	// Test delete with wrong argument type
	serviceTestVars.k8sListWatch.Delete(&svc)

	gomega.Expect(argErrs + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().ArgErrors))
	gomega.Expect(dels).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Deletes))

	// Test delete where everything should be good
	serviceTestVars.k8sListWatch.Delete(svc)
	gomega.Expect(dels + 1).To(gomega.Equal(serviceTestVars.svcReflector.GetStats().Deletes))

	svcProto = &service.Service{}
	key := service.Key(svc.GetName(), svc.GetNamespace())
	found, _, err = serviceTestVars.mockKvBroker.GetValue(key, svcProto)

	gomega.Expect(found).To(gomega.BeFalse())
	gomega.Ω(err).Should(gomega.Succeed())
}
