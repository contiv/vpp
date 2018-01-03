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

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	proto "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	"github.com/ligato/cn-infra/flavors/local"
	"time"
)

type EndpointsTestVars struct {
	k8sListWatch *mockK8sListWatch
	mockKvWriter *mockKeyProtoValWriter
	epsReflector *EndpointsReflector
	endpoints    *coreV1.Endpoints
}

var epTestVars EndpointsTestVars

func TestEndpointsReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	epTestVars.k8sListWatch = &mockK8sListWatch{}
	epTestVars.mockKvWriter = newMockKeyProtoValWriter()

	epTestVars.epsReflector = &EndpointsReflector{
		ReflectorDeps: ReflectorDeps{
			Log:          flavorLocal.LoggerFor("endpoints-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: epTestVars.k8sListWatch,
			Publish:      epTestVars.mockKvWriter,
		},
	}

	nodeName := "cvpp"
	epTestVars.endpoints = &coreV1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "my-nginx",
			Namespace:       "default",
			SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx",
			UID:             "cace7a27-eddf-11e7-9959-0800271d72be",
			ResourceVersion: "85353",
			Generation:      0,
			CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
				time.FixedZone("PST", -800)),
			Labels: map[string]string{"run": "my-nginx"},
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
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := epTestVars.epsReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	t.Run("addDeleteEndpoints", testAddDeleteEndpoints)
	epTestVars.mockKvWriter.ClearDs()
	t.Run("updateEndpoints", testUpdateEndpoints)
	// TODO: add more
}

func testAddDeleteEndpoints(t *testing.T) {
	eps := epTestVars.endpoints

	// Check if we can add a service
	add := epTestVars.epsReflector.GetStats().NumAdds
	epTestVars.k8sListWatch.Add(eps)
	epsProto := &proto.Endpoints{}
	err := epTestVars.mockKvWriter.GetValue(proto.Key(eps.GetName(), eps.GetNamespace()), epsProto)

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

	epsProto = &proto.Endpoints{}
	key := proto.Key(eps.GetName(), eps.GetNamespace())
	err = epTestVars.mockKvWriter.GetValue(key, epsProto)
	gomega.Ω(err).ShouldNot(gomega.Succeed())
}

func testUpdateEndpoints(t *testing.T) {
	nodeName := "cvpp"

	epsOld := epTestVars.endpoints
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
			Labels: map[string]string{"run": "my-nginx"},
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
	epsProto := &proto.Endpoints{}
	err := epTestVars.mockKvWriter.GetValue(proto.Key(epsNew.GetName(), epsNew.GetNamespace()), epsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(epsProto.EndpointSubsets[0].Addresses[0].Ip).
		To(gomega.Equal(epsNew.Subsets[0].Addresses[0].IP))
	gomega.Expect(len(epsProto.EndpointSubsets[0].Addresses)).Should(gomega.BeNumerically("==", 1))

}
