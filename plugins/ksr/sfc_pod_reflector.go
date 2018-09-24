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
	"sync"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/golang/protobuf/proto"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/sfc"
)

// SfcPodReflector subscribes to K8s cluster to watch for changes in the
// configuration of k8s pods. Protobuf-modelled changes are published
// into the selected key-value store.
type SfcPodReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s pods. The subscription does not become active until Start()
// is called.
func (spr *SfcPodReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	sfcPodReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				spr.addPod(obj)
			},
			DeleteFunc: func(obj interface{}) {
				spr.deletePod(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				spr.updatePod(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &sfc.Sfc{}
		},
		K8s2NodeFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sPod, ok := k8sObj.(*coreV1.Pod)
			if !ok {
				spr.Log.Errorf("sfc pod syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			labels := k8sPod.GetLabels()
			if labels != nil {
				for key, val := range labels {
					if key == "sfc" && val == "true" {
						return spr.valueToProto(k8sPod.Name, k8sPod.Spec.NodeName), sfc.Key(k8sPod.Name, k8sPod.Namespace), true
					}
				}
			}
			return nil, "", false
		},
	}

	return spr.ksrInit(stopCh2, wg, pod.KeyPrefix(), "pods", &coreV1.Pod{}, sfcPodReflectorFuncs)
}

// addPod adds state data of a newly created K8s pod into the data store.
func (spr *SfcPodReflector) addPod(obj interface{}) {
	k8sPod, ok := obj.(*coreV1.Pod)
	if !ok {
		spr.Log.Warn("Failed to cast newly created pod object")
		spr.stats.ArgErrors++
		return
	}
	labels := k8sPod.GetLabels()
	if labels != nil {
		for key, val := range labels {
			if key == "sfc" && val == "true" {
				sfcKey := sfc.Key(k8sPod.Name, k8sPod.Namespace)
				sfcValue := spr.valueToProto(k8sPod.Name, k8sPod.Spec.NodeName)
				spr.Log.WithField("sfc-pod", obj).Info("Adding sfc-pod")
				spr.ksrAdd(sfcKey, sfcValue)
			}
		}
	}
}

// deletePod deletes state data of a removed K8s pod from the data store.
func (spr *SfcPodReflector) deletePod(obj interface{}) {
	k8sPod, ok := obj.(*coreV1.Pod)
	if !ok {
		spr.Log.Warn("Failed to cast newly created pod object")
		spr.stats.ArgErrors++
		return
	}
	labels := k8sPod.GetLabels()
	if labels != nil {
		for key, val := range labels {
			if key == "sfc" && val == "true" {
				sfcKey := sfc.Key(k8sPod.Name, k8sPod.Namespace)
				spr.Log.WithField("sfc-pod", obj).Info("Deleting sfc-pod")
				spr.ksrDelete(sfcKey)
			}
		}
	}
}

// updatePod updates state data of a changed K8s pod in the data store.
func (spr *SfcPodReflector) updatePod(oldObj, newObj interface{}) {
	oldK8sPod, ok1 := oldObj.(*coreV1.Pod)
	newK8sPod, ok2 := newObj.(*coreV1.Pod)
	if !ok1 || !ok2 {
		spr.Log.Warn("Failed to cast changed pod object")
		spr.stats.ArgErrors++
		return
	}

	oldLabels := oldK8sPod.GetLabels()
	newLabels := newK8sPod.GetLabels()
	oldSfcLabelExist := false
	newSfcLabelExist := false

	if oldLabels != nil {
		for key, val := range oldLabels {
			if key == "sfc" && val == "true" {
				oldSfcLabelExist = true
			}
		}
	}
	if newLabels != nil {
		for key, val := range newLabels {
			if key == "sfc" && val == "true" {
				newSfcLabelExist = true
			}
		}
	}

	if oldSfcLabelExist && newSfcLabelExist {
		sfcKey := sfc.Key(newK8sPod.GetName(), newK8sPod.GetNamespace())
		oldSfcValue := spr.valueToProto(oldK8sPod.Name, oldK8sPod.Spec.NodeName)
		newSfcValue := spr.valueToProto(newK8sPod.Name, newK8sPod.Spec.NodeName)
		spr.Log.WithField("new-sfc-pod", newSfcValue).Info("Updating new sfc-pod")
		spr.ksrUpdate(sfcKey, oldSfcValue, newSfcValue)
	} else if !oldSfcLabelExist && newSfcLabelExist {
		sfcKey := sfc.Key(newK8sPod.Name, newK8sPod.GetNamespace())
		sfcValue := spr.valueToProto(newK8sPod.Name, newK8sPod.Spec.NodeName)
		spr.Log.WithField("new-sfc-pod", sfcValue).Info("Updating new sfc-pod")
		spr.ksrAdd(sfcKey, sfcValue)
	} else if oldSfcLabelExist && !newSfcLabelExist {
		sfcKey := sfc.Key(oldK8sPod.Name, oldK8sPod.GetNamespace())
		spr.ksrDelete(sfcKey)
	}
}

// valueToProto returns the value of the sfc tree a given K8s pod is stored in the
// data store.
func (spr *SfcPodReflector) valueToProto(name string, nodeName string) *sfc.Sfc {
	valueProto := &sfc.Sfc{}
	valueProto.Vnf = name
	valueProto.Node = nodeName

	return valueProto
}
