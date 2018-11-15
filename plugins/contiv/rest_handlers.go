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

package contiv

import (
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/unrolled/render"
	"net/http"
)

const (
	// Prefix is versioned prefix for REST urls
	Prefix = "/contiv/v1/"
	// PluginURL is versioned URL (using prefix) for IPAM REST endpoint
	PluginURL = Prefix + "ipam"
)

type ipamData struct {
	NodeID            uint32       `json:"nodeId"`
	NodeName          string       `json:"nodeName"`
	NodeIP            string       `json:"nodeIP"`
	PodSubnetThisNode string       `json:"podNetwork"`
	VppHostNetwork    string       `json:"vppHostNetwork"`
	Config            *ipam.Config `json:"config"`
}

func (s *remoteCNIserver) registerHandlers() {
	if s.http == nil {
		s.Logger.Warnf("No http handler provided or getNodeIP callback, skipping registration of IPAM REST handlers")
		return
	}

	s.http.RegisterHTTPHandler(PluginURL, s.ipamGetHandler, "GET")
	s.Logger.Infof("IPAM REST handler registered: GET %v", PluginURL)
}

func (s *remoteCNIserver) ipamGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		s.Logger.Debug("Getting IPAM data")
		nodeIP, _ := s.GetNodeIP()
		if nodeIP == nil {
			s.Logger.Error("Error getting node IP")
			formatter.JSON(w, http.StatusInternalServerError, "Error getting node IP")
			return
		}

		formatter.JSON(w, http.StatusOK, ipamData{
			NodeID:            s.nodeID,
			NodeName:          s.agentLabel,
			NodeIP:            nodeIP.String(),
			PodSubnetThisNode: s.ipam.PodSubnetThisNode().String(),
			VppHostNetwork:    s.ipam.HostInterconnectSubnetThisNode().String(),
			Config:            &s.config.IPAMConfig,
		})
	}
}
