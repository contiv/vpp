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

package ksr

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/flavors/local"
)

type PodTestVars struct {
	k8sListWatch *mockK8sListWatch
	mockKvWriter *mockKeyProtoValWriter
	mockKvLister *mockKeyProtoValLister
	podReflector *PodReflector
	podTestData  []coreV1.Pod
}

var podTestVars PodTestVars

func TestPodReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	podTestVars.k8sListWatch = &mockK8sListWatch{}
	podTestVars.mockKvWriter = newMockKeyProtoValWriter()
	podTestVars.mockKvLister = newMockKeyProtoValLister(podTestVars.mockKvWriter.ds)

	podTestVars.podReflector = &PodReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("pod-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: podTestVars.k8sListWatch,
			Writer:       podTestVars.mockKvWriter,
			Lister:       podTestVars.mockKvLister,
			dsSynced:     false,
			objType:      "Pod",
		},
	}

	timeout := int64(30)
	podTestVars.podTestData = []coreV1.Pod{
		// Test data 0: mocks a new object to be added to the data store add
		// tests (mark-and-sweep synchronization test, add test)
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "my-nginx-9d5677d94-ng9xg",
				GenerateName:    "my-nginx-9d5677d94-,",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx-9d5677d94-ng9xg",
				UID:             "bb6b2a49-ee73-11e7-9959-0800271d72be",
				ResourceVersion: "288178",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"ksrRun": "my-nginx"},
			},
			Spec: coreV1.PodSpec{
				Containers: []coreV1.Container{
					{
						Name:  "my-nginx",
						Image: "nginx",
						Ports: []coreV1.ContainerPort{
							{
								HostPort: 80,
								Protocol: "TCP",
							},
						},
						VolumeMounts: []coreV1.VolumeMount{
							{
								Name:      "default-token-cbhmr",
								ReadOnly:  true,
								MountPath: " /var/run/secrets/kubernetes.io/serviceaccount",
							},
						},
						TerminationMessagePath:   "/dev/termination-log",
						TerminationMessagePolicy: "File",
						ImagePullPolicy:          "Always",
					},
				},
				DNSPolicy:                     "ClusterFirst",
				RestartPolicy:                 "Always",
				TerminationGracePeriodSeconds: &timeout,
				NodeName:                      "cvpp",
				Tolerations: []coreV1.Toleration{
					{
						Key:      "default-token-cbhmr",
						Operator: "true",
						Value:    " /var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
			},
			Status: coreV1.PodStatus{
				HostIP: "10.0.2.15",
				PodIP:  "192.168.49.92",
			},
		},
		// Test data 1: mocks a pre-existing object in the data store that is
		// updated during the mark-and-sweep synchronization test because its
		// counterpart in the K8s cache has changed.
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "kube-dns-6f4fd4bdf-lkpjr",
				GenerateName:    "kube-dns-6f4fd4bdf-,",
				Namespace:       "kube-system",
				SelfLink:        "/api/v1/namespaces/default/endpoints/kube-dns-6f4fd4bdf-lkpjr",
				UID:             "978e098f-ec4c-11e7-9959-0800271d72be",
				ResourceVersion: "288167",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "extensions/v1beta1",
						Kind:       "ReplicaSet",
						Name:       "kube-dns-6f4fd4bdf 978926cc-ec4c-11e7-9959-0800271d72be",
					},
				},
				Labels: map[string]string{
					"k8s-app":           "kube-dns",
					"pod-template-hash": "290980689",
				},
			},
			Spec: coreV1.PodSpec{
				Containers: []coreV1.Container{
					{
						Name:  "kubedns",
						Image: "gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.7",
						Ports: []coreV1.ContainerPort{
							{
								Name:          "dns-local",
								ContainerPort: 0,
								HostPort:      10053,
								Protocol:      "UDP",
							},
							{
								Name:          "dns-tcp-local",
								ContainerPort: 0,
								HostPort:      10053,
								Protocol:      "TCP",
							},
							{
								Name:          "metrics",
								ContainerPort: 0,
								HostPort:      10055,
								Protocol:      "TCP",
								HostIP:        "1.2.3.4",
							},
						},
						VolumeMounts: []coreV1.VolumeMount{
							{
								Name:      "default-token-cbhmr",
								ReadOnly:  true,
								MountPath: " /var/run/secrets/kubernetes.io/serviceaccount",
							},
						},
						TerminationMessagePath:   "/dev/termination-log",
						TerminationMessagePolicy: "File",
						ImagePullPolicy:          "Always",
					},
				},
				DNSPolicy:                     "ClusterFirst",
				RestartPolicy:                 "Always",
				TerminationGracePeriodSeconds: &timeout,
				NodeName:                      "cvpp",
				Tolerations: []coreV1.Toleration{
					{
						Key:      "default-token-cbhmr",
						Operator: "true",
						Value:    " /var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
			},
			Status: coreV1.PodStatus{
				HostIP: "10.0.2.15",
				PodIP:  "192.168.49.91",
			},
		},
		// Test data 2: mocks a pre-existing "stale" object in the data store
		// that is deleted during the mark-and-sweep synchronization test
		// because its counterpart no longer exists in the K8s cache.
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "my-nginx-9d5677d94-kjmjw",
				GenerateName:    "my-nginx-9d5677d94-,",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx-9d5677d94-kjmjw",
				UID:             "bb6c3414-ee73-11e7-9959-0800271d72be",
				ResourceVersion: "288178",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{"ksrRun": "my-nginx"},
			},
			Spec: coreV1.PodSpec{
				Containers: []coreV1.Container{
					{
						Name:  "my-nginx",
						Image: "nginx",
						Ports: []coreV1.ContainerPort{
							{
								HostPort: 80,
								Protocol: "TCP",
							},
						},
						VolumeMounts: []coreV1.VolumeMount{
							{
								Name:      "default-token-cbhmr",
								ReadOnly:  true,
								MountPath: " /var/run/secrets/kubernetes.io/serviceaccount",
							},
						},
						TerminationMessagePath:   "/dev/termination-log",
						TerminationMessagePolicy: "File",
						ImagePullPolicy:          "Always",
					},
				},
				DNSPolicy:                     "ClusterFirst",
				RestartPolicy:                 "Always",
				TerminationGracePeriodSeconds: &timeout,
				NodeName:                      "cvpp",
				Tolerations: []coreV1.Toleration{
					{
						Key:      "default-token-cbhmr",
						Operator: "true",
						Value:    " /var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
			},
			Status: coreV1.PodStatus{
				HostIP: "10.0.2.15",
				PodIP:  "192.168.49.90",
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
			&podTestVars.podTestData[0],
			// New value mock
			&podTestVars.podTestData[1],
		}
	}

	// Pre-populate the mock data store with pre-existing data that is supposed
	// to be updated during the test.
	k8sPod1 := &podTestVars.podTestData[1]
	protoPod1 := podTestVars.podReflector.podToProto(k8sPod1)
	protoPod1.IpAddress = "1.2.3.4"
	podTestVars.mockKvWriter.Put(pod.Key(k8sPod1.GetName(), k8sPod1.GetNamespace()), protoPod1)

	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during the test.
	k8sPod2 := &podTestVars.podTestData[2]
	podTestVars.mockKvWriter.Put(pod.Key(k8sPod2.GetName(),
		k8sPod2.GetNamespace()), podTestVars.podReflector.podToProto(k8sPod2))

	statsBefore := *podTestVars.podReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := podTestVars.podReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	// Wait for the initial sync to finish
	for {
		if podTestVars.podReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *podTestVars.podReflector.GetStats()

	gomega.Expect(podTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.NumAdds + 1).Should(gomega.BeNumerically("==", statsAfter.NumAdds))
	gomega.Expect(statsBefore.NumUpdates + 1).Should(gomega.BeNumerically("==", statsAfter.NumUpdates))
	gomega.Expect(statsBefore.NumDeletes + 1).Should(gomega.BeNumerically("==", statsAfter.NumDeletes))

	podTestVars.mockKvWriter.ClearDs()

	t.Run("addDeleteEndpoints", testAddDeletePod)

	podTestVars.mockKvWriter.ClearDs()
	t.Run("updateEndpoints", testUpdatePod)
}

func testAddDeletePod(t *testing.T) {
	k8sPod := &podTestVars.podTestData[0]

	// Take a snapshot of counters
	adds := podTestVars.podReflector.GetStats().NumAdds
	argErrs := podTestVars.podReflector.GetStats().NumArgErrors

	// Test add with wrong argument type
	podTestVars.k8sListWatch.Add(&k8sPod)

	gomega.Expect(argErrs + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumArgErrors))
	gomega.Expect(adds).To(gomega.Equal(podTestVars.podReflector.GetStats().NumAdds))

	// Test add where everything should be good
	podTestVars.k8sListWatch.Add(k8sPod)

	key := pod.Key(k8sPod.GetName(), k8sPod.GetNamespace())
	protoPod := &pod.Pod{}
	err := podTestVars.mockKvWriter.GetValue(key, protoPod)

	gomega.Expect(adds + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumAdds))
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(protoPod).NotTo(gomega.BeNil())
	gomega.Expect(protoPod.Name).To(gomega.Equal(k8sPod.GetName()))
	gomega.Expect(protoPod.Namespace).To(gomega.Equal(k8sPod.GetNamespace()))
	gomega.Expect(protoPod.Namespace).To(gomega.Equal(k8sPod.GetNamespace()))

	gomega.Expect(protoPod.HostIpAddress).To(gomega.Equal(k8sPod.Status.HostIP))
	gomega.Expect(protoPod.IpAddress).To(gomega.Equal(k8sPod.Status.PodIP))

	gomega.Expect(protoPod.Container[0].Name).To(gomega.Equal(k8sPod.Spec.Containers[0].Name))
	gomega.Expect(protoPod.Container[0].Port[0].Name).
		To(gomega.Equal(k8sPod.Spec.Containers[0].Ports[0].Name))
	gomega.Expect(protoPod.Container[0].Port[0].Protocol).
		Should(gomega.BeNumerically("==", pod.Pod_Container_Port_TCP))
	gomega.Expect(k8sPod.Spec.Containers[0].Ports[0].Protocol).To(gomega.BeEquivalentTo("TCP"))
	gomega.Expect(protoPod.Container[0].Port[0].HostPort).
		To(gomega.Equal(k8sPod.Spec.Containers[0].Ports[0].HostPort))
	gomega.Expect(protoPod.Container[0].Port[0].ContainerPort).
		To(gomega.Equal(k8sPod.Spec.Containers[0].Ports[0].ContainerPort))
	gomega.Expect(protoPod.Container[0].Port[0].HostIpAddress).
		To(gomega.Equal(k8sPod.Spec.Containers[0].Ports[0].HostIP))

	// Take a snapshot of counters
	dels := podTestVars.podReflector.GetStats().NumDeletes
	argErrs = podTestVars.podReflector.GetStats().NumArgErrors

	// Test delete with wrong argument type
	podTestVars.k8sListWatch.Delete(&k8sPod)

	gomega.Expect(argErrs + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumArgErrors))
	gomega.Expect(dels).To(gomega.Equal(podTestVars.podReflector.GetStats().NumDeletes))

	// Test delete where everything should be good
	podTestVars.k8sListWatch.Delete(k8sPod)
	gomega.Expect(dels + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumDeletes))

	protoPod = &pod.Pod{}
	err = podTestVars.mockKvWriter.GetValue(key, protoPod)
	gomega.Ω(err).ShouldNot(gomega.Succeed())
}

func testUpdatePod(t *testing.T) {
	// Prepare test data
	k8sPodOld := &podTestVars.podTestData[0]
	tmpBuf, err := json.Marshal(k8sPodOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPodNew := &coreV1.Pod{}
	err = json.Unmarshal(tmpBuf, k8sPodNew)
	gomega.Ω(err).Should(gomega.Succeed())

	// Take a snapshot of counters
	upds := podTestVars.podReflector.GetStats().NumUpdates
	argErrs := podTestVars.podReflector.GetStats().NumArgErrors

	// Test update with wrong argument type
	podTestVars.k8sListWatch.Update(*k8sPodOld, *k8sPodNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumArgErrors))
	gomega.Expect(upds).To(gomega.Equal(podTestVars.podReflector.GetStats().NumUpdates))

	// Ensure that there is no update if old and new values are the same
	podTestVars.k8sListWatch.Update(k8sPodOld, k8sPodNew)
	gomega.Expect(upds).To(gomega.Equal(podTestVars.podReflector.GetStats().NumUpdates))

	// Test update where everything should be good
	k8sPodNew.Status.HostIP = "1.2.3.4"
	podTestVars.k8sListWatch.Update(k8sPodOld, k8sPodNew)
	gomega.Expect(upds + 1).To(gomega.Equal(podTestVars.podReflector.GetStats().NumUpdates))

	key := pod.Key(k8sPodOld.GetName(), k8sPodOld.GetNamespace())
	protoPodNew := &pod.Pod{}
	err = podTestVars.mockKvWriter.GetValue(key, protoPodNew)
	gomega.Ω(err).Should(gomega.Succeed())
	gomega.Expect(protoPodNew.HostIpAddress).To(gomega.Equal(k8sPodNew.Status.HostIP))
}
