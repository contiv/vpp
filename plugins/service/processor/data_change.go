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
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// propagateDataChangeEv propagates CHANGE in the K8s configuration into the Processor.
func (sp *ServiceProcessor) propagateDataChangeEv(event *controller.KubeStateChange) error {
	switch event.Resource {
	case epmodel.EndpointsKeyword:
		if event.NewValue != nil {
			endpoints := event.NewValue.(*epmodel.Endpoints)
			if event.PrevValue == nil {
				return sp.processNewEndpoints(endpoints)
			}
			return sp.processUpdatedEndpoints(endpoints)
		}
		endpoints := event.PrevValue.(*epmodel.Endpoints)
		return sp.processDeletedEndpoints(epmodel.GetID(endpoints))

	case svcmodel.ServiceKeyword:
		if event.NewValue != nil {
			service := event.NewValue.(*svcmodel.Service)
			if event.PrevValue == nil {
				return sp.processNewService(service)
			}
			return sp.processUpdatedService(service)
		}
		service := event.PrevValue.(*svcmodel.Service)
		return sp.processDeletedService(svcmodel.GetID(service))
	case ipalloc.Keyword:
		if event.NewValue != nil {
			alloc := event.NewValue.(*ipalloc.CustomIPAllocation)
			return sp.processCustomIPAlloc(alloc)
		}
		// no-op for delete, handled in ProcessDeletingPod
	}
	return nil
}
