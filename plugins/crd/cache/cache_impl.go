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
//

package cache

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging"
)

const subnetmask = "/24"
const vppVNI = 10

// ContivTelemetryCache is used for a in-memory storage of K8s State data
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
type ContivTelemetryCache struct {
	Deps
	Synced bool
	// todo - here add the maps you have in your db implementation
	VppCache  *VppCache
	K8sCache  *K8sCache
	Processor Processor
	report    []string
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	// todo - here initialize your maps
	ctc.VppCache = NewVppCache(ctc.Log)
	ctc.K8sCache = NewK8sCache(ctc.Log)
	ctc.Log.Infof("ContivTelemetryCache has been initialized")
	return nil
}

// ListAllNodes returns node data for all nodes in the cache.
func (ctc *ContivTelemetryCache) ListAllNodes() []*telemetrymodel.Node {
	nodeList := ctc.VppCache.RetrieveAllNodes()
	return nodeList
}

// LookupNode return node data for nodes that match a node name passed
// to the function in the node names slice.
func (ctc *ContivTelemetryCache) LookupNode(nodenames []string) []*telemetrymodel.Node {
	nodeslice := make([]*telemetrymodel.Node, 0)
	for _, name := range nodenames {
		node, ok := ctc.VppCache.nMap[name]
		if !ok {
			continue
		}
		nodeslice = append(nodeslice, node)
	}
	return nodeslice
}

// DeleteNode deletes from the cache those nodes that match a node name passed
// to the function in the node names slice.
func (ctc *ContivTelemetryCache) DeleteNode(nodenames []string) {
	for _, str := range nodenames {
		node, err := ctc.VppCache.RetrieveNode(str)
		if err != nil {
			ctc.Log.Error(err)
			return
		}
		ctc.VppCache.deleteNode(node.Name)

	}

}

//AddNode will add a node to the Contiv Telemetry cache with the given parameters.
func (ctc *ContivTelemetryCache) AddNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	err := ctc.VppCache.addNode(ID, nodeName, IPAdr, ManIPAdr)
	if err != nil {
		return err
	}
	return nil
}
