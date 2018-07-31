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

//ProcessNodeResponses will read the nodeDTO map and make sure that each node has
//enough DTOS to fully process information. It then clears the node DTO map after it
//is finished with it.
func (p *ContivTelemetryProcessor) ProcessNodeResponses() {
	for data := range p.nodeResponseChannel {
		p.dtoList = append(p.dtoList, data)
		if len(p.dtoList) == numDTOs*len(p.Cache.GetAllNodes()) {
			p.SetNodeData()
			p.ValidateNodeInfo()
			p.dtoList = p.dtoList[0:0]
		}
	}
}

// SetNodeData will iterate through the dtoList, read the type of dto, and assign the dto info to the name
// associated with the DTO.
func (p *ContivTelemetryProcessor) SetNodeData() {
	for _, data := range p.dtoList {
		switch data.(type) {
		case NodeLivenessDTO:
			nlDto := data.(NodeLivenessDTO)
			if nlDto.err != nil {
				p.Cache.report = append(p.Cache.report, nlDto.err.Error())
			}
			p.Cache.SetNodeLiveness(nlDto.NodeName, nlDto.NodeInfo)
		case NodeInterfacesDTO:
			niDto := data.(NodeInterfacesDTO)
			if niDto.err != nil {
				p.Cache.report = append(p.Cache.report, niDto.err.Error())
			}
			p.Cache.SetNodeInterfaces(niDto.NodeName, niDto.NodeInfo)
		case NodeBridgeDomainsDTO:
			nbdDto := data.(NodeBridgeDomainsDTO)
			if nbdDto.err != nil {
				p.Cache.report = append(p.Cache.report, nbdDto.err.Error())
			}
			p.Cache.SetNodeBridgeDomain(nbdDto.NodeName, nbdDto.NodeInfo)
		case NodeL2FibsDTO:
			nl2fDto := data.(NodeL2FibsDTO)
			if nl2fDto.err != nil {
				p.Cache.report = append(p.Cache.report, nl2fDto.err.Error())
			}
			p.Cache.SetNodeL2Fibs(nl2fDto.NodeName, nl2fDto.NodeInfo)
		case NodeTelemetryDTO:
			ntDto := data.(NodeTelemetryDTO)
			if ntDto.err != nil {
				p.Cache.report = append(p.Cache.report, ntDto.err.Error())
			}
			p.Cache.SetNodeTelemetry(ntDto.NodeName, ntDto.NodeInfo)
		case NodeIPArpDTO:
			nipaDto := data.(NodeIPArpDTO)
			if nipaDto.err != nil {
				p.Cache.report = append(p.Cache.report, nipaDto.err.Error())
			}
			p.Cache.SetNodeIPARPs(nipaDto.NodeName, nipaDto.NodeInfo)
		default:
			p.Log.Error("Unknown data type")
		}

	}

}
