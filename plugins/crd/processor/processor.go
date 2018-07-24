/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */
package processor

import (
	"github.com/contiv/vpp/plugins/crd/cache"
	"github.com/ligato/cn-infra/logging"
)


type ContivTelemetryProcessor struct {
Deps

dbChannel chan interface{}
nodesDB cache.Nodes


}
type Deps struct {

	Log logging.Logger
}


func (p *ContivTelemetryProcessor) Init() error {

	p.nodesDB = cache.NewNodesDB(p.Log)
	p.dbChannel = make(chan interface{})
	 return nil
}

func (p *ContivTelemetryProcessor)CollectNodeInfo(node *cache.Node){

	p.collectAgentInfo(node)

	p.ProcessNodeData()

	p.nodesDB.PopulateNodeMaps(node)

}

func (p *ContivTelemetryProcessor)ValidateNodeInfo(nodelist []*cache.Node){

	p.nodesDB.ValidateLoopIFAddresses(nodelist)

}