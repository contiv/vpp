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
	"github.com/contiv/vpp/plugins/ipam/restapi"
	"github.com/unrolled/render"
	"net/http"
)

func (i *IPAM) registerRESTHandlers() {
	if i.HTTPHandlers == nil {
		i.Log.Warnf("No http handler provided, skipping registration of IP alocation REST handlers")
		return
	}

	i.HTTPHandlers.RegisterHTTPHandler(restapi.RestURLNodeIPAllocations, i.ipamGetHandler, "GET")
	i.Log.Infof("IP Allocation REST handler registered: GET %v", restapi.RestURLNodeIPAllocations)
}

func (i *IPAM) ipamGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		i.mutex.RLock()
		defer i.mutex.RUnlock()

		i.Log.Debug("Getting IP allocation data")

		allocations := restapi.NodeIPAllocations{}
		for k, v := range i.podToIP {
			allocations.Pods = append(allocations.Pods, restapi.PodIPAllocation{
				PodID:       k,
				MainIP:      v.mainIP,
				CustomIfIPs: v.customIfIPs,
			})
		}

		formatter.JSON(w, http.StatusOK, allocations)
	}
}
