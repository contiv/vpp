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

package ipam

import (
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/unrolled/render"
	"net/http"
)

type ipamData struct {
	NodeID         uint32 `json:"nodeId"`
	NodeName       string `json:"nodeName"`
	NodeIP         string `json:"nodeIP"`
	PodNetwork     string `json:"podNetwork"`
	VppHostNetwork string `json:"vppHostNetwork"`
}

func (i *IPAM) registerHandlers(http rest.HTTPHandlers) {
	if http == nil {
		i.logger.Warnf("No http handler provided, skipping registration of IPAM REST handlers")
		return
	}
	http.RegisterHTTPHandler("/ipam", i.ipamGetHandler, "GET")
	i.logger.Infof("IPAM REST handler registered: GET /ipam")
}

func (i *IPAM) ipamGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		i.logger.Debug("Getting IPAM data")
		nodeID := i.NodeID()
		nodeIP, err := i.NodeIPAddress(nodeID)
		if err != nil {
			i.logger.Errorf("Error getting node IP: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		formatter.JSON(w, http.StatusOK, ipamData{
			NodeID:         nodeID,
			NodeName:       i.nodeName,
			NodeIP:         nodeIP.String(),
			PodNetwork:     i.PodNetwork().String(),
			VppHostNetwork: i.VPPHostNetwork().String(),
		})
	}
}
