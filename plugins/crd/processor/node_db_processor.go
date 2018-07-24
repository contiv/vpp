package processor

import "github.com/contiv/vpp/plugins/crd/cache"

//ProcessNodeData reads data sent by agent_client.go to the plugins Node Database channel.
//It decides how to process the data received based on the type of Data Transfer Object.
//Then it updates the node with the name from the DTO with the specific data from the DTO.
func (p *ContivTelemetryProcessor) ProcessNodeData() {
	for  {
		data := <-p.dbChannel
		switch data.(type) {
		case cache.NodeLivenessDTO:
			nlDto := data.(cache.NodeLivenessDTO)
			p.nodesDB.SetNodeLiveness(nlDto.NodeName, nlDto.NodeInfo)
		case cache.NodeInterfacesDTO:
			niDto := data.(cache.NodeInterfacesDTO)
			p.nodesDB.SetNodeInterfaces(niDto.NodeName, niDto.NodeInfo)
		case cache.NodeBridgeDomainsDTO:
			nbdDto := data.(cache.NodeBridgeDomainsDTO)
			p.nodesDB.SetNodeBridgeDomain(nbdDto.NodeName, nbdDto.NodeInfo)
		case cache.NodeL2FibsDTO:
			nl2fDto := data.(cache.NodeL2FibsDTO)
			p.nodesDB.SetNodeL2Fibs(nl2fDto.NodeName, nl2fDto.NodeInfo)
		case cache.NodeTelemetryDTO:
			ntDto := data.(cache.NodeTelemetryDTO)
			p.nodesDB.SetNodeTelemetry(ntDto.NodeName, ntDto.NodeInfo)
		case cache.NodeIPArpDTO:
			nipaDto := data.(cache.NodeIPArpDTO)
			p.nodesDB.SetNodeIPARPs(nipaDto.NodeName, nipaDto.NodeInfo)
		default:
			p.Log.Error("Unknown data type")
		}
	}
}
