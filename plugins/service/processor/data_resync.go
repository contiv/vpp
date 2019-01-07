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
	"fmt"

	controller "github.com/contiv/vpp/plugins/controller/api"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ResyncEventData wraps an entire state of K8s services that should be reflected
// into VPP.
type ResyncEventData struct {
	Pods      []podmodel.ID
	Endpoints []*epmodel.Endpoints
	Services  []*svcmodel.Service
}

// NewResyncEventData creates an empty instance of ResyncEventData.
func NewResyncEventData() *ResyncEventData {
	return &ResyncEventData{
		Pods:      []podmodel.ID{},
		Endpoints: []*epmodel.Endpoints{},
		Services:  []*svcmodel.Service{},
	}
}

// String converts ResyncEventData into a human-readable string.
func (red ResyncEventData) String() string {
	pods := ""
	for idx, podID := range red.Pods {
		pods += podID.String()
		if idx < len(red.Pods)-1 {
			pods += ", "
		}
	}
	endpoints := ""
	for idx, endpoint := range red.Endpoints {
		endpoints += endpoint.String()
		if idx < len(red.Endpoints)-1 {
			endpoints += ", "
		}
	}
	services := ""
	for idx, service := range red.Services {
		services += service.String()
		if idx < len(red.Services)-1 {
			services += ", "
		}
	}
	return fmt.Sprintf("ResyncEventData <Pods:[%s] Endpoint:[%s] Services:[%s]>",
		pods, endpoints, services)
}

func (sc *ServiceProcessor) parseResyncEv(kubeStateData controller.KubeStateData) *ResyncEventData {
	event := NewResyncEventData()

	// collect pods
	for podID := range sc.PodManager.GetLocalPods() {
		event.Pods = append(event.Pods, podID)
	}

	// collect endpoints
	for _, epProto := range kubeStateData[epmodel.EndpointsKeyword] {
		endpoints := epProto.(*epmodel.Endpoints)
		event.Endpoints = append(event.Endpoints, endpoints)
	}

	// collect services
	for _, svcProto := range kubeStateData[svcmodel.ServiceKeyword] {
		service := svcProto.(*svcmodel.Service)
		event.Services = append(event.Services, service)
	}
	return event
}
