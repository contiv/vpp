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

const (
	// Prefix is versioned prefix for REST urls
	Prefix = "/contiv/v1/"
	// PluginURL is versioned URL (using prefix) for IPAM REST endpoint
	PluginURL = Prefix + "ipam"
)

type config struct {
	PodIfIPCIDR             string `json:"podIfIPCIDR"`
	PodSubnetCIDR           string `json:"podSubnetCIRDR"`
	PodNetworkPrefixLen     uint8  `json:"podNetworkPrefixLen"`
	VPPHostSubnetCIDR       string `json:"vppHostSubnetCIDR"`
	VPPHostNetworkPrefixLen uint8  `json:"vppHostNetworkPrefixLen"`
	NodeInterconnectCIDR    string `json:"nodeInterconnectCIDR"`
	NodeInterconnectDHCP    bool   `json:"nodeInterconnectDHCP"`
	VxlanCIDR               string `json:"vxlanCIDR"`
	ServiceCIDR             string `json:"serviceCIDR"`
}

type ipamData struct {
	NodeID         uint32  `json:"nodeId"`
	NodeName       string  `json:"nodeName"`
	NodeIP         string  `json:"nodeIP"`
	PodNetwork     string  `json:"podNetwork"`
	VppHostNetwork string  `json:"vppHostNetwork"`
	Config         *config `json:"config"`
}

func (i *IPAM) registerHandlers(http rest.HTTPHandlers) {
	if http == nil {
		i.logger.Warnf("No http handler provided, skipping registration of IPAM REST handlers")
		return
	}
	http.RegisterHTTPHandler(PluginURL, i.ipamGetHandler, "GET")
	i.logger.Infof("IPAM REST handler registered: GET %v", PluginURL)
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
			Config: &config{
				PodIfIPCIDR:             i.config.PodIfIPCIDR,
				PodSubnetCIDR:           i.config.PodSubnetCIDR,
				PodNetworkPrefixLen:     i.config.PodNetworkPrefixLen,
				VPPHostSubnetCIDR:       i.config.VPPHostSubnetCIDR,
				VPPHostNetworkPrefixLen: i.config.VPPHostNetworkPrefixLen,
				NodeInterconnectCIDR:    i.config.NodeInterconnectCIDR,
				NodeInterconnectDHCP:    i.config.NodeInterconnectDHCP,
				VxlanCIDR:               i.config.VxlanCIDR,
				ServiceCIDR:             i.config.ServiceCIDR,
			},
		})
	}
}
