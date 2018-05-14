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

	nodeID "github.com/contiv/vpp/plugins/contiv/model/node"
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
	nr.Log.WithField("node", obj).Debug("addNode")
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
	nr.Log.WithField("node", obj).Debug("deleteNode")
	k8sNode, ok := obj.(*coreV1.Node)
	if !ok {
		nr.Log.Warn("Failed to cast newly created node object")
		nr.stats.ArgErrors++
		return
	}

	key := node.Key(k8sNode.GetName())
	nr.ksrDelete(key)

	nr.deleteNodeIDForName(k8sNode.Name)
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

	nr.Log.WithFields(map[string]interface{}{"node-old": oldK8sNode, "node-new": newK8sNode}).
		Debug("Node updated")

	key := node.Key(newK8sNode.GetName())
	oldNodeProto := nr.nodeToProto(oldK8sNode)
	newNodeProto := nr.nodeToProto(newK8sNode)
	nr.ksrUpdate(key, oldNodeProto, newNodeProto)
}

// nodeToProto converts node data from the k8s representation into the
// corresponding contiv protobuf-modelled data format.
func (nr *NodeReflector) nodeToProto(k8sNode *coreV1.Node) *node.Node {
	nodeProto := &node.Node{}
	nodeProto.Name = k8sNode.Name

	nodeProto.Pod_CIDR = k8sNode.Spec.PodCIDR
	nodeProto.Provider_ID = k8sNode.Spec.ProviderID
	nodeProto.Addresses = getNodeAddresses(k8sNode.Status.Addresses)
	nodeProto.NodeInfo = getNodeInfo(k8sNode.Status.NodeInfo)

	return nodeProto
}

// getNodeAddresses converts node addresses from the k8s representation
// into the corresponding contiv protobuf-modelled data format.
func getNodeAddresses(k8sAddrs []coreV1.NodeAddress) []*node.NodeAddress {
	var protoAddrs []*node.NodeAddress

Loop:
	for _, ka := range k8sAddrs {
		pa := &node.NodeAddress{}
		switch ka.Type {
		case coreV1.NodeHostName:
			pa.Type = node.NodeAddress_NodeHostName
		case coreV1.NodeExternalIP:
			pa.Type = node.NodeAddress_NodeExternalIP
		case coreV1.NodeInternalIP:
			pa.Type = node.NodeAddress_NodeInternalIP
		case coreV1.NodeExternalDNS:
			pa.Type = node.NodeAddress_NodeExternalDNS
		case coreV1.NodeInternalDNS:
			pa.Type = node.NodeAddress_NodeInternalDNS
		default:
			continue Loop
		}

		pa.Address = ka.Address
		protoAddrs = append(protoAddrs, pa)
	}

	return protoAddrs
}

// getNodeAddresses converts node system node info from the k8s representation
// into the corresponding contiv protobuf-modelled data format.
func getNodeInfo(kni coreV1.NodeSystemInfo) *node.NodeSystemInfo {
	pni := &node.NodeSystemInfo{}

	pni.Architecture = kni.Architecture
	pni.Boot_ID = kni.BootID
	pni.ContainerRuntimeVersion = kni.ContainerRuntimeVersion
	pni.KernelVersion = kni.KernelVersion
	pni.KubeletVersion = kni.KubeletVersion
	pni.KubeProxyVersion = kni.KubeProxyVersion
	pni.Machine_ID = kni.MachineID
	pni.OperatingSystem = kni.OperatingSystem
	pni.OsImage = kni.OSImage
	pni.System_UUID = kni.SystemUUID

	return pni
}

// deleteNodeIDForName removes nodeID allocated for defined name. The aim of the function is to
// cleanup nodeID when a node is removed for a cluster.
func (nr *NodeReflector) deleteNodeIDForName(name string) error {
	it, err := nr.Broker.ListValues(nodeID.AllocatedIDsKeyPrefix)
	if err != nil {
		return err
	}

	for {

		kv, stop := it.GetNext()

		if stop {
			break
		}

		val := &nodeID.NodeInfo{}
		err := kv.GetValue(val)
		if err != nil {
			return err
		}
		if val.Name == name {
			nr.Broker.Delete(kv.GetKey())
			nr.Log.Infof("Node ID %v was removed", kv.GetKey())
			break
		}
	}
	return nil
}
