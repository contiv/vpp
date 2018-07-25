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

package processor

import (
	"github.com/contiv/vpp/plugins/crd/cache"
	"github.com/ligato/cn-infra/logging"
)

// ContivTelemetryProcessor defines the processor's data structures and
// dependencies
type ContivTelemetryProcessor struct {
	Deps

	dbChannel chan interface{}
	nodesDB   cache.Nodes
}

// Deps define processor dependencies
type Deps struct {
	Log logging.Logger
}

// Init initializes the processor
func (p *ContivTelemetryProcessor) Init() error {

	p.nodesDB = cache.NewNodesDB(p.Log)
	p.dbChannel = make(chan interface{})
	return nil
}

// CollectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (p *ContivTelemetryProcessor) CollectNodeInfo(node *cache.Node) {

	p.collectAgentInfo(node)

	p.ProcessNodeData()

	p.nodesDB.PopulateNodeMaps(node)

}

// ValidateNodeInfo checks the consistency of the node data in the cache. It
// checks the ARP tables, ... . Data inconsistencies may cause loss of
// connectivity between nodes or pods. All sata inconsistencies found during
// validation are reported to the CRD.
func (p *ContivTelemetryProcessor) ValidateNodeInfo(nodelist []*cache.Node) {

	p.nodesDB.ValidateLoopIFAddresses(nodelist)

}
