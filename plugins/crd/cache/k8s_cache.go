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

package cache

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ksr/model/node"
	pod2 "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
	"github.com/pkg/errors"
	"sync"
	"sort"
)

// K8sCache defines the operations on the K8s data store / cache.
type K8sCache interface {
	CreateK8sNode(name string, podCIDR string, providerID string,
		Addresses []*node.NodeAddress, nodeInfo *node.NodeSystemInfo) error
	RetrieveK8sNode(nodeName string) (*node.Node, error)
	UpdateK8sNode(name string, podCIDR string, providerID string,
		Addresses []*node.NodeAddress, nodeInfo *node.NodeSystemInfo) error
	DeleteK8sNode(nodeName string) error

	RetrieveAllK8sNodes() []*node.Node

	CreatePod(name string, namespace string, label []*pod2.Pod_Label, IPAddress,
		hostIPAdd string, container []*pod2.Pod_Container) error
	RetrievePod(name string) (*telemetrymodel.Pod, error)
	UpdatePod(name string, namespace string, label []*telemetrymodel.PodLabel,
		IPAddress, hostIPAddress string, container []*pod2.Pod_Container) error
	DeletePod(name string) error

	RetrieveAllPods() []*telemetrymodel.Pod

	ClearCache()
	ReinitializeCache()
}

//K8sDataStore holds k8s related information separate from vpp related information
type K8sDataStore struct {
	lock       *sync.Mutex
	k8sNodeMap map[string]*node.Node
	podMap     map[string]*telemetrymodel.Pod
}

//NewK8sCache will return a pointer to a new cache which holds various types of k8s related information.
func NewK8sCache(logger logging.Logger) *K8sDataStore {
	return &K8sDataStore{
		&sync.Mutex{},
		make(map[string]*node.Node),
		make(map[string]*telemetrymodel.Pod),
	}
}

//CreateK8sNode will add a k8s type node to the Contiv Telemtry cache,
// making sure there are no duplicates.
func (k *K8sDataStore) CreateK8sNode(name string, PodCIDR string, ProviderID string,
	Addresses []*node.NodeAddress, NodeInfo *node.NodeSystemInfo) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	newNode := node.Node{Name: name, Pod_CIDR: PodCIDR, Provider_ID: ProviderID, Addresses: Addresses, NodeInfo: NodeInfo}
	_, ok := k.k8sNodeMap[name]
	if ok {
		return errors.Errorf("Duplicate k8s node with name %+v found", name)
	}
	k.k8sNodeMap[name] = &newNode

	return nil
}

// RetrieveK8sNode will retrieve a k8s node from the cache with the given name
// or return an error if it is not found.gi
func (k *K8sDataStore) RetrieveK8sNode(name string) (*node.Node, error) {
	k.lock.Lock()
	defer k.lock.Unlock()

	return k.retrieveK8sNode(name)
}

func (k *K8sDataStore) UpdateK8sNode(name string, PodCIDR string, ProviderID string,
	Addresses []*node.NodeAddress, NodeInfo *node.NodeSystemInfo) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	k8snode, err := k.retrieveK8sNode(name)
	if err != nil {
		return errors.Errorf("Cannot find k8s node %+v in k8s cache node map", name)
	}
	k8snode.Addresses = Addresses
	k8snode.NodeInfo = NodeInfo
	k8snode.Provider_ID = ProviderID
	k8snode.Pod_CIDR = PodCIDR
	return nil
}

func (k *K8sDataStore) DeleteK8sNode(name string) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	_, err := k.retrieveK8sNode(name)
	if err != nil {
		return errors.Errorf("k8s node with name %+v not found", name)
	}
	delete(k.k8sNodeMap, name)
	return nil
}

func (k *K8sDataStore) RetrieveAllK8sNodes() []*node.Node {
	k.lock.Lock()
	defer k.lock.Unlock()

	var str []string
	for k := range k.k8sNodeMap {
		str = append(str, k)
	}
	var nList []*node.Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := k.retrieveK8sNode(v)
		nList = append(nList, n)
	}
	return nList
}

// CreatePod adds a pod with the given parameters to the contiv telemetry cache
func (k *K8sDataStore) CreatePod(name, Namespace string, label []*pod2.Pod_Label, IPAddress,
hostIPAddress string, container []*pod2.Pod_Container) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	labels := make([]*telemetrymodel.PodLabel, 0)
	for _, l := range label {
		labels = append(labels, &telemetrymodel.PodLabel{Key: l.Key, Value: l.Value})
	}
	newPod := telemetrymodel.Pod{
		Name:          name,
		Namespace:     Namespace,
		Label:         labels,
		IPAddress:     IPAddress,
		HostIPAddress: hostIPAddress,
	}
	_, ok := k.podMap[name]
	if ok {
		return errors.Errorf("Duplicate pod with name %+v found", name)
	}
	k.podMap[name] = &newPod
	return nil
}

// RetrievePod will retrieve a pod from the cache with the given name or
// return an error if it is not found.
func (k *K8sDataStore) RetrievePod(name string) (*telemetrymodel.Pod, error) {
	k.lock.Lock()
	defer k.lock.Unlock()

	return k.retrievePod(name)
}

func (k *K8sDataStore) UpdatePod(name string, namespace string, label []*telemetrymodel.PodLabel,
	IPAddress, hostIPAddress string, container []*pod2.Pod_Container) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	pod, err := k.retrievePod(name)
	if err != nil {
		return errors.Errorf("Cannot find pod %+v in k8s cache pod map", name)
	}
	pod.Label = label
	pod.Namespace = namespace
	pod.IPAddress = IPAddress
	pod.HostIPAddress = hostIPAddress
	return nil
}

func (k *K8sDataStore) DeletePod(name string) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	_, err := k.retrievePod(name)
	if err != nil {
		return errors.Errorf("pod with name %+v not found", name)
	}
	delete(k.podMap, name)
	return nil
}

func (k *K8sDataStore) RetrieveAllPods() []*telemetrymodel.Pod {
	k.lock.Lock()
	defer k.lock.Unlock()

	var str []string
	for k := range k.podMap {
		str = append(str, k)
	}
	var nList []*telemetrymodel.Pod
	sort.Strings(str)
	for _, v := range str {
		p, _ := k.retrievePod(v)
		nList = append(nList, p)
	}
	return nList
}

func (k *K8sDataStore) ClearCache() {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.podMap = make(map[string]*telemetrymodel.Pod)
	k.k8sNodeMap = make(map[string]*node.Node)
}

func (k *K8sDataStore) ReinitializeCache() {
	k.ClearCache()
}

// retrieveK8sNode is an internal function (no locks) used to retrieve
// a node from the data store map. It should be called with the global
// cache lock locked
func (k *K8sDataStore) retrieveK8sNode(name string) (*node.Node, error) {
	node, ok := k.k8sNodeMap[name]
	if !ok {
		return node, errors.Errorf("k8s node with name %+v not found", name)
	}
	return node, nil
}

// retrievePod is an internal function (no locks) used to retrieve
// a node from the data store map. It should be called with the global
// cache lock locked.
func (k *K8sDataStore) retrievePod(name string) (*telemetrymodel.Pod, error) {
	pod, ok := k.podMap[name]
	if !ok {
		return nil, errors.Errorf("Pod with name %+v not found", name)
	}
	return pod, nil
}
