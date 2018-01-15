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
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ResyncEventData wraps an entire state of K8s services that should be reflected
// into VPP.
type ResyncEventData struct {
	Pods      []*podmodel.Pod
	Endpoints []*epmodel.Endpoints
	Services  []*svcmodel.Service
}

// NewResyncEventData creates an empty instance of ResyncEventData.
func NewResyncEventData() *ResyncEventData {
	return &ResyncEventData{
		Pods:      []*podmodel.Pod{},
		Endpoints: []*epmodel.Endpoints{},
		Services:  []*svcmodel.Service{},
	}
}

func (sc *ServiceProcessor) parseResyncEv(resyncEv datasync.ResyncEvent) *ResyncEventData {
	var (
		numPod int
		numEps int
		numSvc int
		err    error
	)

	event := NewResyncEventData()

	for key, resyncData := range resyncEv.GetValues() {
		sc.Log.Debug("Received RESYNC key ", key)

		for {
			evData, stop := resyncData.GetNext()

			if stop {
				break
			}
			key := evData.GetKey()
			sc.Log.Debug("Received RESYNC key ", key)

			// Parse pod RESYNC event
			_, _, err = podmodel.ParsePodFromKey(key)
			if err == nil {
				value := &podmodel.Pod{}
				err := evData.GetValue(value)
				if err == nil {
					event.Pods = append(event.Pods, value)
					numPod++
				}
				continue
			}

			// Parse endpoints RESYNC event
			_, _, err = epmodel.ParseEndpointsFromKey(key)
			if err == nil {
				value := &epmodel.Endpoints{}
				err := evData.GetValue(value)
				if err == nil {
					event.Endpoints = append(event.Endpoints, value)
					numEps++
				}
				continue
			}

			// Parse service RESYNC event
			_, _, err = svcmodel.ParseServiceFromKey(key)
			if err == nil {
				value := &svcmodel.Service{}
				err := evData.GetValue(value)
				if err == nil {
					event.Services = append(event.Services, value)
					numSvc++
				}
				continue
			}
		}
	}

	sc.Log.WithFields(logging.Fields{
		"num-pods":      numPod,
		"num-endpoints": numEps,
		"num-services":  numSvc,
	}).Debug("Parsed RESYNC event")

	return event
}
