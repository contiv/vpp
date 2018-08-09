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
	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/pkg/errors"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	pod2 "github.com/contiv/vpp/plugins/ksr/model/pod"
)

//AddK8sNode will add a k8s type node to the Contiv Telemtry cache, making sure there are no duplicates.
func (ctc *ContivTelemetryCache) AddK8sNode(name string, PodCIDR string, ProviderID string,
	Addresses []*node.NodeAddress, NodeInfo *node.NodeSystemInfo) error {
	newNode := node.Node{Name: name, Pod_CIDR: PodCIDR, Provider_ID: ProviderID, Addresses: Addresses, NodeInfo: NodeInfo}
	_, ok := ctc.Cache.k8sNodeMap[name]
	if ok {
		return errors.Errorf("Duplicate k8s node with name %+v found", name)
	}
	ctc.Cache.k8sNodeMap[name] = &newNode


	return nil
}

//AddPod adds a pod with the given parameters to the contiv telemetry cache
func (ctc *ContivTelemetryCache) AddPod(Name, Namespace string, Label []*pod2.Pod_Label, IPAddress, HostIPAddress string,
	Container []*pod2.Pod_Container) error {
	// TODO: add container to telemetry pod struct
	labels := make([]*telemetrymodel.PodLabel, 0)
	for _, l := range Label {
		labels = append(labels, &telemetrymodel.PodLabel{Key: l.Key, Value: l.Value})
	}
	newPod := telemetrymodel.Pod{Name: Name, Namespace: Namespace, Label: labels, IPAddress: IPAddress, HostIPAddress: HostIPAddress}
	_, ok := ctc.Cache.podMap[Name]
	if ok {
		return errors.Errorf("Duplicate pod with name %+v found", Name)
	}
	ctc.Cache.podMap[Name] = &newPod
	node, ok := ctc.Cache.hostIPMap[HostIPAddress]
	if ok {
		node.PodMap[Name] = &newPod
	}
	return nil
}


func (c *Cache) RetrievePod(name string) (*telemetrymodel.Pod, error) {
	pod, ok := c.podMap[name]
	if !ok {
		return nil, errors.Errorf("Pod with name %+v not found", name)
	}
	return pod, nil
}

func (c *Cache) RetrieveK8sNode(name string) (*node.Node, error) {
	node, ok := c.k8sNodeMap[name]
	if !ok {
		return node, errors.Errorf("k8s node with name %+v not found", name)
	}
	return node, nil
}

