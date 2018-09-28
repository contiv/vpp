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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/sfc"

	"github.com/ligato/cn-infra/logging"
)

type SfcPodTestVars struct {
	k8sListWatch      *mockK8sListWatch
	mockKvBroker      *mockKeyProtoValBroker
	sfcPodReflector   *SfcPodReflector
	sfcPodTestData    []coreV1.Pod
	reflectorRegistry ReflectorRegistry
}

var sfcPodTestVars SfcPodTestVars

func TestSfcPodReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	sfcPodTestVars.k8sListWatch = &mockK8sListWatch{}
	sfcPodTestVars.mockKvBroker = newMockKeyProtoValBroker()

	sfcPodTestVars.reflectorRegistry = ReflectorRegistry{
		reflectors: make(map[string]*Reflector),
		lock:       sync.RWMutex{},
	}

	sfcPodTestVars.sfcPodReflector = &SfcPodReflector{
		Reflector: Reflector{
			Log:               logging.ForPlugin("pod-reflector"),
			K8sClientset:      &kubernetes.Clientset{},
			K8sListWatch:      sfcPodTestVars.k8sListWatch,
			Broker:            sfcPodTestVars.mockKvBroker,
			dsSynced:          false,
			objType:           sfcPodObjType,
			ReflectorRegistry: &sfcPodTestVars.reflectorRegistry,
		},
	}

	timeout := int64(30)
	sfcPodTestVars.sfcPodTestData = []coreV1.Pod{
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
				Labels: map[string]string{
					"ksrRun": "my-nginx",
					"sfc":    "true",
				},
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
				NodeName:                      "k8s-master",
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
					"sfc":               "true",
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
								Name:          "gauges",
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
				NodeName:                      "k8s-master",
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
				Labels: map[string]string{
					"ksrRun": "my-nginx",
					"sfc":    "true",
				},
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
				NodeName:                      "k8s-master",
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
		// Test data 3: mocks a k8s data store pod that won't be added
		// under the sfc-controller tree since the labels don't match
		// "sfc"="true"
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "my-nginx-9d5677d94-kjsdmjw",
				GenerateName:    "my-nginx-9d56asd77d94-,",
				Namespace:       "default",
				SelfLink:        "/api/v1/namespaces/default/endpoints/my-nginx-9d5677asdd94-kjmjw",
				UID:             "bb6c3414-ee73-sd11e7-9959-0800271d72be",
				ResourceVersion: "288178",
				Generation:      0,
				CreationTimestamp: metav1.Date(2017, 12, 28, 19, 58, 37, 0,
					time.FixedZone("PST", -800)),
				Labels: map[string]string{
					"ksrRun": "my-nginx",
				},
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
				NodeName:                      "k8s-master",
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
	// - a new endpoint instance to be added to the data store
	// - a modified endpoint instance, where an existing instance in the
	//   data store is to be updated
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			// Updated value mock
			&sfcPodTestVars.sfcPodTestData[0],
			// New value mock
			&sfcPodTestVars.sfcPodTestData[1],
			// Unused mock value
			&sfcPodTestVars.sfcPodTestData[3],
		}
	}

	// Pre-populate the mock data store with pre-existing data that is supposed
	// to be updated during the test.
	k8sPod1 := &sfcPodTestVars.sfcPodTestData[1]
	protoPod1 := sfcPodTestVars.sfcPodReflector.valueToProto(k8sPod1.Name, k8sPod1.Spec.NodeName)
	protoPod1.Pod = "kube-dns-2"
	sfcPodTestVars.mockKvBroker.Put(sfc.Key(k8sPod1.Name, k8sPod1.Namespace), protoPod1)

	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during the test.
	k8sPod2 := &sfcPodTestVars.sfcPodTestData[2]
	sfcPodTestVars.mockKvBroker.Put(pod.Key(k8sPod2.Name,
		k8sPod2.Namespace), sfcPodTestVars.sfcPodReflector.valueToProto(k8sPod2.Name, k8sPod2.Spec.NodeName))

	statsBefore := *sfcPodTestVars.sfcPodReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := sfcPodTestVars.sfcPodReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	sfcPodTestVars.sfcPodReflector.startDataStoreResync()

	// Wait for the initial sync to finish
	for {
		if sfcPodTestVars.sfcPodReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *sfcPodTestVars.sfcPodReflector.GetStats()

	gomega.Expect(sfcPodTestVars.mockKvBroker.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.Adds + 1).Should(gomega.BeNumerically("==", statsAfter.Adds))
	gomega.Expect(statsBefore.Updates + 1).Should(gomega.BeNumerically("==", statsAfter.Updates))
	gomega.Expect(statsBefore.Deletes + 1).Should(gomega.BeNumerically("==", statsAfter.Deletes))

	sfcPodTestVars.mockKvBroker.ClearDs()

	t.Run("addDeleteEndpoints", testAddDeleteSfcPod)

	sfcPodTestVars.mockKvBroker.ClearDs()
	t.Run("updateEndpoints", testUpdateSfcPod)
}

func testAddDeleteSfcPod(t *testing.T) {
	k8sPod := &sfcPodTestVars.sfcPodTestData[0]

	// Take a snapshot of counters
	adds := sfcPodTestVars.sfcPodReflector.GetStats().Adds
	argErrs := sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors

	// Test add with wrong argument type
	sfcPodTestVars.k8sListWatch.Add(&k8sPod)

	gomega.Expect(argErrs + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors))
	gomega.Expect(adds).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Adds))

	// Test add where everything should be good
	sfcPodTestVars.k8sListWatch.Add(k8sPod)

	key := sfc.Key(k8sPod.Name, k8sPod.Namespace)
	protoPod := &sfc.Sfc{}
	found, _, err := sfcPodTestVars.mockKvBroker.GetValue(key, protoPod)

	gomega.Expect(adds + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Adds))
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(protoPod).NotTo(gomega.BeNil())
	gomega.Expect(protoPod.Pod).To(gomega.Equal(k8sPod.Name))
	gomega.Expect(protoPod.Node).To(gomega.Equal(k8sPod.Spec.NodeName))

	// Take a snapshot of counters
	dels := sfcPodTestVars.sfcPodReflector.GetStats().Deletes
	argErrs = sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors

	// Test delete with wrong argument type
	sfcPodTestVars.k8sListWatch.Delete(&k8sPod)

	gomega.Expect(argErrs + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors))
	gomega.Expect(dels).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Deletes))

	// Test delete where everything should be good
	sfcPodTestVars.k8sListWatch.Delete(k8sPod)
	gomega.Expect(dels + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Deletes))

	protoPod = &sfc.Sfc{}
	found, _, _ = sfcPodTestVars.mockKvBroker.GetValue(key, protoPod)
	gomega.Ω(found).ShouldNot(gomega.BeTrue())
}

func testUpdateSfcPod(t *testing.T) {
	// Prepare test data
	k8sPodOld := &sfcPodTestVars.sfcPodTestData[0]
	tmpBuf, err := json.Marshal(k8sPodOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPodNew := &coreV1.Pod{}
	err = json.Unmarshal(tmpBuf, k8sPodNew)
	gomega.Ω(err).Should(gomega.Succeed())

	// Take a snapshot of counters
	upds := sfcPodTestVars.sfcPodReflector.GetStats().Updates
	argErrs := sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors

	// Test update with wrong argument type
	sfcPodTestVars.k8sListWatch.Update(*k8sPodOld, *k8sPodNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().ArgErrors))
	gomega.Expect(upds).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Updates))

	// Ensure that there is no update if old and new values are the same
	sfcPodTestVars.k8sListWatch.Update(k8sPodOld, k8sPodNew)
	gomega.Expect(upds).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Updates))

	// Test update where everything should be good
	k8sPodNew.Spec.NodeName = "k8s-worker2"
	sfcPodTestVars.k8sListWatch.Update(k8sPodOld, k8sPodNew)
	gomega.Expect(upds + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Updates))

	key := sfc.Key(k8sPodOld.Name, k8sPodOld.Namespace)
	protoPodNew := &sfc.Sfc{}
	found, _, err := sfcPodTestVars.mockKvBroker.GetValue(key, protoPodNew)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Ω(err).Should(gomega.BeNil())

	// Take a snapshot of counters
	dels := sfcPodTestVars.sfcPodReflector.GetStats().Deletes

	// test what happens when we remove the label "sfc"="true" from the pod
	tmpBuf, err = json.Marshal(k8sPodOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPodNew2 := &coreV1.Pod{}
	err = json.Unmarshal(tmpBuf, k8sPodNew2)
	gomega.Ω(err).Should(gomega.Succeed())

	fmt.Println(k8sPodNew2.GetLabels())

	// Test update where everything should be good
	delete(k8sPodNew2.Labels, "sfc")
	sfcPodTestVars.k8sListWatch.Update(k8sPodNew, k8sPodNew2)
	gomega.Expect(dels + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Deletes))

	// Take a snapshot of counters
	adds := sfcPodTestVars.sfcPodReflector.GetStats().Adds

	// test what happens when we add the label "sfc"="true" to the pod
	tmpBuf, err = json.Marshal(k8sPodNew2)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPodNew3 := &coreV1.Pod{}
	err = json.Unmarshal(tmpBuf, k8sPodNew3)
	gomega.Ω(err).Should(gomega.Succeed())

	// Test update where everything should be good
	k8sPodNew3.Labels["sfc"] = "true"
	sfcPodTestVars.k8sListWatch.Update(k8sPodNew2, k8sPodNew3)
	gomega.Expect(adds + 1).To(gomega.Equal(sfcPodTestVars.sfcPodReflector.GetStats().Adds))

}
