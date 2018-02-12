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

	"github.com/golang/protobuf/proto"

	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// NamespaceReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s namespaces.
// Protobuf-modelled changes are published into the selected key-value store.
type NamespaceReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s namespaces. The subscription does not become active until Start()
// is called.
func (nr *NamespaceReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	namespaceReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				nr.addNamespace(obj)
			},
			DeleteFunc: func(obj interface{}) {
				nr.deleteNamespace(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				nr.updateNamespace(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &namespace.Namespace{}
		},
		K8s2NodeFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sNsp, ok := k8sObj.(*coreV1.Namespace)
			if !ok {
				nr.Log.Errorf("service syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return nr.namespaceToProto(k8sNsp), namespace.Key(k8sNsp.Name), true
		},
	}

	return nr.ksrInit(stopCh2, wg, namespace.KeyPrefix(), "namespaces",
		&coreV1.Namespace{}, namespaceReflectorFuncs)
}

// addNamespace adds state data of a newly created K8s namespace into the data
// store.
func (nr *NamespaceReflector) addNamespace(obj interface{}) {
	nr.Log.WithField("k8sNs", obj).Info("K8s namespace added")

	k8sNs, ok := obj.(*coreV1.Namespace)
	if !ok {
		nr.Log.Warn("Failed to cast to be deleted namespace object")
		nr.stats.ArgErrors++
		return
	}
	nr.ksrAdd(namespace.Key(k8sNs.GetName()), nr.namespaceToProto(k8sNs))
}

// deleteNamespace deletes state data of a removed K8s namespace from the data
// store.
func (nr *NamespaceReflector) deleteNamespace(obj interface{}) {
	nr.Log.WithField("k8sNs", obj).Info("K8s namespace removed")

	k8sNs, ok := obj.(*coreV1.Namespace)
	if !ok {
		nr.Log.Warn("Failed to cast to be deleted namespace object")
		nr.stats.ArgErrors++
		return
	}
	nr.ksrDelete(namespace.Key(k8sNs.GetName()))
}

// updateNamespace updates state data of a changes K8s namespace in the data
// store.
func (nr *NamespaceReflector) updateNamespace(oldObj, newObj interface{}) {
	nr.Log.WithFields(map[string]interface{}{"ns-old": oldObj, "ns-new": newObj}).
		Info("Namespace updated")

	oldK8sNs, ok1 := oldObj.(*coreV1.Namespace)
	newK8sNs, ok2 := newObj.(*coreV1.Namespace)
	if !ok1 || !ok2 {
		nr.Log.Warn("Failed to cast changed namespace object")
		nr.stats.ArgErrors++
		return
	}
	nr.ksrUpdate(namespace.Key(newK8sNs.GetName()),
		nr.namespaceToProto(oldK8sNs), nr.namespaceToProto(newK8sNs))
}

// namespaceToProto converts namespace state data from the k8s representation
// into our protobuf-modelled data structure.
func (nr *NamespaceReflector) namespaceToProto(ns *coreV1.Namespace) *namespace.Namespace {
	nsProto := &namespace.Namespace{}
	nsProto.Name = ns.GetName()
	labels := ns.GetLabels()
	if labels != nil {
		for key, val := range labels {
			nsProto.Label = append(nsProto.Label, &namespace.Namespace_Label{Key: key, Value: val})
		}
	}
	return nsProto
}
