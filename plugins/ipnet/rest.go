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

package ipnet

import (
	"github.com/contiv/vpp/plugins/ipnet/restapi"
	"github.com/unrolled/render"
	"net/http"
)

func (n *IPNet) registerRESTHandlers() {
	if n.HTTPHandlers == nil {
		n.Log.Warnf("No http handler provided or getNodeIP callback, skipping registration of IPAM REST handlers")
		return
	}

	n.HTTPHandlers.RegisterHTTPHandler(restapi.RestURLNodeIPAM, n.ipamGetHandler, "GET")
	n.Log.Infof("IPAM REST handler registered: GET %v", restapi.RestURLNodeIPAM)
}

func (n *IPNet) ipamGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		n.Log.Debug("Getting IPAM data")
		nodeIP, _ := n.GetNodeIP()
		if nodeIP == nil {
			n.Log.Error("Error getting node IP")
			formatter.JSON(w, http.StatusInternalServerError, "Error getting node IP")
			return
		}

		formatter.JSON(w, http.StatusOK, restapi.NodeIPAMInfo{
			NodeID:            n.NodeSync.GetNodeID(),
			NodeName:          n.ServiceLabel.GetAgentLabel(),
			NodeIP:            nodeIP.String(),
			PodSubnetThisNode: n.IPAM.PodSubnetThisNode(DefaultPodNetworkName).String(),
			VppHostNetwork:    n.IPAM.HostInterconnectSubnetThisNode().String(),
			Config:            n.IPAM.GetIPAMConfigForJSON(),
		})
	}
}
