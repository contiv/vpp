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
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"

	"sort"
)

// NodeTelemetryCache is used for a in-memory storage of K8s State data
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
type ContivTelemetryCache struct {
	Deps
	Synced bool
	// todo - here add the maps you have in your db implementation
	nameMap map[string]*Node
	loopIPMap map[string]*Node
	gigEIPMap map[string]*Node
	loopMACMap map[string]*Node
	k8sNodeMap map[string]*nodemodel.Node
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	// todo - here initialize your maps
	ctc.loopMACMap = make(map[string]*Node)
	ctc.loopIPMap = make(map[string]*Node)
	ctc.gigEIPMap = make(map[string]*Node)
	ctc.nameMap = make(map[string]*Node)
	ctc.k8sNodeMap = make(map[string]*nodemodel.Node)
	return nil
}

// Update processes a datasync change event associated with K8s State data.
// The change is applied into the cache and all subscribed watchers are
// notified.
// The function will forward any error returned by a watcher.
func (ctc *ContivTelemetryCache) Update(dataChngEv datasync.ChangeEvent) error {
	err := ctc.changePropagateEvent(dataChngEv)
	if err != nil {
		return err
	}

	return nil
}

// Resync processes a datasync resync event associated with K8s State data.
// The cache content is full replaced with the received data.
func (ctc *ContivTelemetryCache) Resync(resyncEv datasync.ResyncEvent) error {
	return ctc.processResyncEvent(resyncEv)
}


func (ctc *ContivTelemetryCache) ListAllNodes() []Node{
	var str []string
	for k := range ctc.nameMap{
		str = append(str, k)
	}
	var nodeList []Node
	sort.Strings(str)
	for _,name := range str  {
		nodeList = append(nodeList,*ctc.nameMap[name])
	}
	return nodeList
}

func (ctc *ContivTelemetryCache)LookupNode(nodenames []string) []Node{
nodeslice := make([]Node,0)
	for _, name := range nodenames{
		node := ctc.nameMap[name]
		nodeslice = append(nodeslice,*node)
	}
	return nodeslice
}

func (ctc *ContivTelemetryCache)DeleteNode(nodenames []string){


}