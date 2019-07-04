/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
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

// ResyncEventData wraps an entire state of K8s resources that should be reflected into VPP.
type ResyncEventData struct {
	SFCs []*sfcmodel.ServiceFunctionChain
	Pods []*podmodel.Pod
}

func (sp *SFCProcessor) parseResyncEv(kubeStateData controller.KubeStateData) *ResyncEventData {

	event := &ResyncEventData{}

	// collect SFCs
	for _, svcProto := range kubeStateData[sfcmodel.Keyword] {
		sfc := svcProto.(*sfcmodel.ServiceFunctionChain)
		event.SFCs = append(event.SFCs, sfc)
	}

	// collect pods
	for _, epProto := range kubeStateData[podmodel.PodKeyword] {
		pod := epProto.(*podmodel.Pod)
		event.Pods = append(event.Pods, pod)
	}

	return event
}
