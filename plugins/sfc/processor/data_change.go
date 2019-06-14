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
	sfcmodel "github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// propagateDataChangeEv propagates CHANGE in the K8s configuration into the Processor.
func (sp *SFCProcessor) propagateDataChangeEv(event *controller.KubeStateChange) error {
	switch event.Resource {

	case sfcmodel.Keyword:
		if event.NewValue != nil {
			sfc := event.NewValue.(*sfcmodel.ServiceFunctionChain)
			if event.PrevValue == nil {
				return sp.processNewSFC(sfc)
			}
			return sp.processUpdatedSFC(sfc)
		}
		sfc := event.PrevValue.(*sfcmodel.ServiceFunctionChain)
		return sp.processDeletedSFC(sfc)

	case podmodel.PodKeyword:
		if event.NewValue != nil {
			pod := event.NewValue.(*podmodel.Pod)
			if event.PrevValue == nil {
				return sp.processNewPod(pod)
			}
			return sp.processUpdatedPod(pod)
		}
		pod := event.PrevValue.(*podmodel.Pod)
		return sp.processDeletedPod(pod)
	}
	return nil
}
