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

	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/golang/protobuf/proto"
)

// NodeReflector subscribes to K8s cluster to watch for changes in the
// configuration of k8s nodes. Protobuf-modelled changes are published
// into the selected key-value store.
type NodeReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s nodes. The subscription does not become active until Start()
// is called.
func (nr *NodeReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {

	nodeReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				nr.addNode(obj)
			},
			DeleteFunc: func(obj interface{}) {
				nr.deleteNode(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				nr.updateNode(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &node.Node{}
		},
		K8s2NodeFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sNode, ok := k8sObj.(*coreV1.Node)
			if !ok {
				nr.Log.Errorf("node syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return nr.nodeToProto(k8sNode), node.Key(k8sNode.Name), true
		},
	}

	return nr.ksrInit(stopCh2, wg, node.KeyPrefix(), "nodes", &coreV1.Node{}, nodeReflectorFuncs)
}

// addPod adds state data of a newly created K8s pod into the data store.
func (nr *NodeReflector) addNode(obj interface{}) {
	nr.Log.WithField("node", obj).Info("addNode")
	k8sNode, ok := obj.(*coreV1.Node)
	if !ok {
		nr.Log.Warn("Failed to cast newly created node object")
		nr.stats.ArgErrors++
		return
	}

	nodeProto := nr.nodeToProto(k8sNode)
	key := node.Key(k8sNode.GetName())
	nr.ksrAdd(key, nodeProto)
}

// deleteNode deletes data of a removed K8s node from the data store.
func (nr *NodeReflector) deleteNode(obj interface{}) {
	nr.Log.WithField("node", obj).Info("deleteNode")
	k8sNode, ok := obj.(*coreV1.Node)
	if !ok {
		nr.Log.Warn("Failed to cast newly created node object")
		nr.stats.ArgErrors++
		return
	}

	key := node.Key(k8sNode.GetName())
	nr.ksrDelete(key)
}

// updateNode updates  data of a changed K8s node from the data store.
func (nr *NodeReflector) updateNode(oldObj, newObj interface{}) {
	oldK8sNode, ok1 := oldObj.(*coreV1.Node)
	newK8sNode, ok2 := newObj.(*coreV1.Node)
	if !ok1 || !ok2 {
		nr.Log.Warn("Failed to cast changed node object")
		nr.stats.ArgErrors++
		return
	}

	nr.Log.WithFields(map[string]interface{}{"pod-old": oldK8sNode, "pod-new": newK8sNode}).
		Info("Node updated")

	key := node.Key(newK8sNode.GetName())
	oldNodeProto := nr.nodeToProto(oldK8sNode)
	newNodeProto := nr.nodeToProto(newK8sNode)
	nr.ksrUpdate(key, oldNodeProto, newNodeProto)
}

// nodeToProto converts node data from the k8s representation into contiv
// protobuf-modelled data structure.
func (nr *NodeReflector) nodeToProto(k8sNode *coreV1.Node) *node.Node {
	nr.Log.Infof("k8sNode: %+v", k8sNode)
	nodeProto := &node.Node{}
	nodeProto.Name = k8sNode.Name
	return nodeProto
}
