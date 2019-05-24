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
	"reflect"
	"strings"
	"sync"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	contivAnnotationPrefix = "contivpp.io"
)

// PodReflector subscribes to K8s cluster to watch for changes in the
// configuration of k8s pods. Protobuf-modelled changes are published
// into the selected key-value store.
type PodReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s pods. The subscription does not become active until Start()
// is called.
func (pr *PodReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {

	podReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pr.addPod(obj)
			},
			DeleteFunc: func(obj interface{}) {
				pr.deletePod(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				pr.updatePod(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &pod.Pod{}
		},
		K8s2NodeFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sPod, ok := k8sObj.(*coreV1.Pod)
			if !ok {
				pr.Log.Errorf("pod syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return pr.podToProto(k8sPod), pod.Key(k8sPod.Name, k8sPod.Namespace), true
		},
	}

	return pr.ksrInit(stopCh2, wg, pod.KeyPrefix(), "pods", &coreV1.Pod{}, podReflectorFuncs)
}

// addPod adds state data of a newly created K8s pod into the data store.
func (pr *PodReflector) addPod(obj interface{}) {
	pr.Log.WithField("pod", obj).Info("addPod")
	k8sPod, ok := obj.(*coreV1.Pod)
	if !ok {
		pr.Log.Warn("Failed to cast newly created pod object")
		pr.stats.ArgErrors++
		return
	}

	podProto := pr.podToProto(k8sPod)
	key := pod.Key(k8sPod.GetName(), k8sPod.GetNamespace())
	pr.ksrAdd(key, podProto)
}

// deletePod deletes state data of a removed K8s pod from the data store.
func (pr *PodReflector) deletePod(obj interface{}) {
	pr.Log.WithField("pod", obj).Info("deletePod")
	k8sPod, ok := obj.(*coreV1.Pod)
	if !ok {
		pr.Log.Warn("Failed to cast newly created pod object")
		pr.stats.ArgErrors++
		return
	}

	key := pod.Key(k8sPod.GetName(), k8sPod.GetNamespace())
	pr.ksrDelete(key)
}

// updatePod updates state data of a changed K8s pod in the data store.
func (pr *PodReflector) updatePod(oldObj, newObj interface{}) {
	oldK8sPod, ok1 := oldObj.(*coreV1.Pod)
	newK8sPod, ok2 := newObj.(*coreV1.Pod)
	if !ok1 || !ok2 {
		pr.Log.Warn("Failed to cast changed pod object")
		pr.stats.ArgErrors++
		return
	}

	pr.Log.WithFields(map[string]interface{}{"name": newK8sPod.Name, "namespace": newK8sPod.Namespace}).
		Info("Pod updated")

	key := pod.Key(newK8sPod.GetName(), newK8sPod.GetNamespace())
	oldPodProto := pr.podToProto(oldK8sPod)
	newPodProto := pr.podToProto(newK8sPod)
	pr.ksrUpdate(key, oldPodProto, newPodProto)
}

// podToProto converts pod state data from the k8s representation into our
// protobuf-modelled data structure.
func (pr *PodReflector) podToProto(k8sPod *coreV1.Pod) *pod.Pod {
	podProto := &pod.Pod{}
	podProto.Name = k8sPod.GetName()
	podProto.Namespace = k8sPod.GetNamespace()
	labels := k8sPod.GetLabels()
	if labels != nil {
		for key, val := range labels {
			podProto.Label = append(podProto.Label, &pod.Pod_Label{Key: key, Value: val})

		}
	}
	podProto.IpAddress = k8sPod.Status.PodIP
	podProto.HostIpAddress = k8sPod.Status.HostIP
	for _, container := range k8sPod.Spec.Containers {
		podProto.Container = append(podProto.Container, pr.containerToProto(&container))
	}
	podProto.Annotations = make(map[string]string)
	for k, v := range k8sPod.Annotations {
		if strings.HasPrefix(k, contivAnnotationPrefix) {
			podProto.Annotations[k] = v
		}
	}

	return podProto
}

// containerToProto converts container state data from the k8s representation
// into our protobuf-modelled data structure.
func (pr *PodReflector) containerToProto(container *coreV1.Container) *pod.Pod_Container {
	containerProto := &pod.Pod_Container{}
	containerProto.Name = container.Name
	for _, port := range container.Ports {
		portProto := &pod.Pod_Container_Port{}
		portProto.Name = port.Name
		portProto.HostPort = port.HostPort
		portProto.ContainerPort = port.ContainerPort
		switch port.Protocol {
		case coreV1.ProtocolTCP:
			portProto.Protocol = pod.Pod_Container_Port_TCP
		case coreV1.ProtocolUDP:
			portProto.Protocol = pod.Pod_Container_Port_UDP
		}
		portProto.HostIpAddress = port.HostIP
		containerProto.Port = append(containerProto.Port, portProto)
	}
	return containerProto
}
