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
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/endpoints"
	"github.com/ligato/cn-infra/flavors/local"
)

type EndpointsTestVars struct {
	k8sListWatch *mockK8sListWatch
	mockKvWriter *mockKeyProtoValWriter
	mockKvLister *mockKeyProtoValLister
	epsReflector *EndpointsReflector
	epsTestData  []coreV1.Endpoints
}

var epTestVars EndpointsTestVars

func TestEndpointsReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	epTestVars.k8sListWatch = &mockK8sListWatch{}
	epTestVars.mockKvWriter = newMockKeyProtoValWriter()
	epTestVars.mockKvLister = newMockKeyProtoValLister(epTestVars.mockKvWriter.ds)

	epTestVars.epsReflector = &EndpointsReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("endpoints-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: epTestVars.k8sListWatch,
			Writer:       epTestVars.mockKvWriter,
			Lister:       epTestVars.mockKvLister,
			dsSynced:     false,
			objType:      "Endpoints",
		},
	}

	nodeName := "cvpp"
	epTestVars.epsTestData = []coreV1.Endpoints{
		{
			// Test data 0: mocks a new object to be added
			ObjectMeta: metav1.ObjectMeta{
				Name:            "my-nginx",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx",
				UID:             "cace7a27-eddf-11e7-9959-0800271d72be",
				ResourceVersion: "85353",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"ksrRun": "my-nginx"},
			},
			Subsets: []coreV1.EndpointSubset{
				{
					Addresses: []coreV1.EndpointAddress{
						{
							IP:       "192.168.49.80",
							NodeName: &nodeName,
							TargetRef: &coreV1.ObjectReference{
								Kind:            "Pod",
								Namespace:       "default",
								Name:            "my-nginx-9d5677d94-bmq98",
								UID:             "a49c6175-edde-11e7-9959-0800271d72be",
								ResourceVersion: "84938",
							},
						},
						{
							IP:       "192.168.49.81",
							NodeName: &nodeName,
							TargetRef: &coreV1.ObjectReference{
								Kind:            "Pod",
								Namespace:       "default",
								Name:            "my-nginx-9d5677d94-4wvfb",
								UID:             "a49da607-edde-11e7-9959-0800271d72be",
								ResourceVersion: "84948",
							},
						},
					},
					Ports: []coreV1.EndpointPort{
						{
							Port:     80,
							Protocol: "TCP",
						},
					},
				},
			},
		},
		// Test data 1: mocks an object that updates a "pre-existing" object
		// during sync
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "calico-etcd",
				Namespace:       "kube-system",
				SelfLink:        "/api/v1/namespaces/default/endpoints/calico-etcd",
				UID:             "1143b9ec-ec4d-11e7-9959-0800271d72be",
				ResourceVersion: "85353",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"k8s-app": "calico-etcd"},
			},
			Subsets: []coreV1.EndpointSubset{
				{
					Addresses: []coreV1.EndpointAddress{
						{
							IP:       "10.0.2.15",
							NodeName: &nodeName,
							TargetRef: &coreV1.ObjectReference{
								Kind:            "Pod",
								Namespace:       "kube-system",
								Name:            "calico-etcd-xkkvc",
								UID:             "531e26a7-f028-11e7-9eee-0800271d72be",
								ResourceVersion: "288097",
							},
						},
					},
					Ports: []coreV1.EndpointPort{
						{
							Port:     6666,
							Protocol: "TCP",
						},
					},
				},
			},
		},
		// Test data 2: mocks a "stale" object that is to be deleted during
		// sync
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "kube-dns",
				Namespace:       "kube-system",
				SelfLink:        "/api/v1/namespaces/default/endpoints/kube-dns",
				UID:             "978d039b-ec4c-11e7-9959-0800271d72be",
				ResourceVersion: "288168",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"k8s-app": "calico-etcd"},
			},
			Subsets: []coreV1.EndpointSubset{
				{
					Addresses: []coreV1.EndpointAddress{
						{
							IP:       "192.168.49.91",
							NodeName: &nodeName,
							TargetRef: &coreV1.ObjectReference{
								Kind:            "Pod",
								Namespace:       "kube-system",
								Name:            "kube-dns-6f4fd4bdf-lkpjr",
								UID:             "978e098f-ec4c-11e7-9959-0800271d72be",
								ResourceVersion: "288167",
							},
						},
					},
					Ports: []coreV1.EndpointPort{
						{
							Name:     "dns",
							Port:     53,
							Protocol: "UDP",
						},
						{
							Name:     "dns-tcp",
							Port:     53,
							Protocol: "TCP",
						},
					},
				},
			},
		},
	}

	// The mock function returns two K8s mock endpoints instances:
	// - a new endpoints instance to be added to the data store
	// - a modified endpoints instance, where and existing instance in the
	//   data store is to be updated
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			// Updated value mock
			&epTestVars.epsTestData[0],
			// New value mock
			&epTestVars.epsTestData[1],
		}
	}

	// Pre-populate the mock data store with pre-existing data that is supposed
	// to be updated during the test.
	k8sEps1 := &epTestVars.epsTestData[1]
	protoEps1 := epTestVars.epsReflector.endpointsToProto(k8sEps1)
	protoEps1.EndpointSubsets[0].Addresses[0].Ip = "1.2.3.4"
	epTestVars.mockKvWriter.Put(endpoints.Key(k8sEps1.GetName(), k8sEps1.GetNamespace()), protoEps1)

	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during the test.
	eps2 := &epTestVars.epsTestData[2]
	epTestVars.mockKvWriter.Put(endpoints.Key(eps2.GetName(),
		eps2.GetNamespace()), epTestVars.epsReflector.endpointsToProto(eps2))

	statsBefore := *epTestVars.epsReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := epTestVars.epsReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	// Wait for the initial sync to finish
	for {
		if epTestVars.epsReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *epTestVars.epsReflector.GetStats()

	gomega.Expect(epTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.NumAdds + 1).Should(gomega.BeNumerically("==", statsAfter.NumAdds))
	gomega.Expect(statsBefore.NumUpdates + 1).Should(gomega.BeNumerically("==", statsAfter.NumUpdates))
	gomega.Expect(statsBefore.NumDeletes + 1).Should(gomega.BeNumerically("==", statsAfter.NumDeletes))

	epTestVars.mockKvWriter.ClearDs()

	t.Run("addDeleteEndpoints", testAddDeleteEndpoints)

	epTestVars.mockKvWriter.ClearDs()
	t.Run("updateEndpoints", testUpdateEndpoints)
}

func testAddDeleteEndpoints(t *testing.T) {
	eps := &epTestVars.epsTestData[0]

	// Check if we can add an endpoint
	add := epTestVars.epsReflector.GetStats().NumAdds
	epTestVars.k8sListWatch.Add(eps)
	epsProto := &endpoints.Endpoints{}
	err := epTestVars.mockKvWriter.GetValue(endpoints.Key(eps.GetName(), eps.GetNamespace()), epsProto)

	gomega.Expect(add + 1).To(gomega.Equal(epTestVars.epsReflector.GetStats().NumAdds))

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(epsProto).NotTo(gomega.BeNil())
	gomega.Expect(epsProto.Name).To(gomega.Equal(eps.GetName()))
	gomega.Expect(epsProto.Namespace).To(gomega.Equal(eps.GetNamespace()))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].Ip).To(gomega.Equal(eps.Subsets[0].Addresses[0].IP))

	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].TargetRef.Namespace).
		To(gomega.Equal(eps.Subsets[0].Addresses[0].TargetRef.Namespace))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].TargetRef.Name).
		To(gomega.Equal(eps.Subsets[0].Addresses[0].TargetRef.Name))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].TargetRef.Kind).
		To(gomega.Equal(eps.Subsets[0].Addresses[0].TargetRef.Kind))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].TargetRef.Uid).
		Should(gomega.BeEquivalentTo(eps.Subsets[0].Addresses[0].TargetRef.UID))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].TargetRef.ResourceVersion).
		To(gomega.Equal(eps.Subsets[0].Addresses[0].TargetRef.ResourceVersion))

	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[1].TargetRef.Namespace).
		To(gomega.Equal(eps.Subsets[0].Addresses[1].TargetRef.Namespace))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[1].TargetRef.Name).
		To(gomega.Equal(eps.Subsets[0].Addresses[1].TargetRef.Name))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[1].TargetRef.Kind).
		To(gomega.Equal(eps.Subsets[0].Addresses[1].TargetRef.Kind))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[1].TargetRef.Uid).
		Should(gomega.BeEquivalentTo(eps.Subsets[0].Addresses[1].TargetRef.UID))
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[1].TargetRef.ResourceVersion).
		To(gomega.Equal(eps.Subsets[0].Addresses[1].TargetRef.ResourceVersion))

	gomega.Expect(epsProto.EndpointSubsets[0].Ports[0].Port).To(gomega.Equal(eps.Subsets[0].Ports[0].Port))
	gomega.Expect(epsProto.EndpointSubsets[0].Ports[0].Protocol).
		Should(gomega.BeEquivalentTo(eps.Subsets[0].Ports[0].Protocol))

	// Now check if we can delete the newly added service
	del := epTestVars.epsReflector.GetStats().NumDeletes
	epTestVars.k8sListWatch.Delete(eps)
	gomega.Expect(del + 1).To(gomega.Equal(epTestVars.epsReflector.GetStats().NumDeletes))

	epsProto = &endpoints.Endpoints{}
	key := endpoints.Key(eps.GetName(), eps.GetNamespace())
	err = epTestVars.mockKvWriter.GetValue(key, epsProto)
	gomega.Ω(err).ShouldNot(gomega.Succeed())
}

func testUpdateEndpoints(t *testing.T) {
	nodeName := "cvpp"

	epsOld := &epTestVars.epsTestData[0]
	epsNew := &coreV1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "my-nginx",
			Namespace:       "default",
			SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx",
			UID:             "cace7a27-eddf-11e7-9959-0800271d72be",
			ResourceVersion: "85353",
			Generation:      0,
			CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
				time.FixedZone("PST", -800)),
			Labels: map[string]string{"ksrRun": "my-nginx"},
		},
		Subsets: []coreV1.EndpointSubset{
			{
				Addresses: []coreV1.EndpointAddress{
					{
						IP:       "192.168.49.80",
						NodeName: &nodeName,
						TargetRef: &coreV1.ObjectReference{
							Kind:            "Pod",
							Namespace:       "default",
							Name:            "my-nginx-9d5677d94-bmq98",
							UID:             "a49c6175-edde-11e7-9959-0800271d72be",
							ResourceVersion: "84938",
						},
					},
				},
				Ports: []coreV1.EndpointPort{
					{
						Port:     80,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	upd := epTestVars.epsReflector.GetStats().NumUpdates

	epTestVars.k8sListWatch.Update(*epsOld, *epsNew)
	// There should be no update if we pass bad data types into update function
	gomega.Expect(upd).To(gomega.Equal(epTestVars.epsReflector.GetStats().NumUpdates))

	epTestVars.k8sListWatch.Update(&epsOld, &epsNew)
	// There should be no update if old and new updates are the same
	gomega.Expect(upd).To(gomega.Equal(epTestVars.epsReflector.GetStats().NumUpdates))

	gomega.Expect(epsOld).ShouldNot(gomega.BeEquivalentTo(epsNew))
	epTestVars.k8sListWatch.Update(epsOld, epsNew)
	// There should be exactly one update because old and new data are different
	gomega.Expect(upd + 1).To(gomega.Equal(epTestVars.epsReflector.GetStats().NumUpdates))

	// Check that new data was written properly
	epsProto := &endpoints.Endpoints{}
	err := epTestVars.mockKvWriter.GetValue(endpoints.Key(epsNew.GetName(), epsNew.GetNamespace()), epsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].Ip).
		To(gomega.Equal(epsNew.Subsets[0].Addresses[0].IP))
	gomega.Expect(len(epsProto.EndpointSubsets[0].Addresses)).Should(gomega.BeNumerically("==", 1))

}
