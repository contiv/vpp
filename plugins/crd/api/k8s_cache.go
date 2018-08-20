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

package api

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ksr/model/node"
	pod2 "github.com/contiv/vpp/plugins/ksr/model/pod"
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

	ReinitializeCache()
}
