/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
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

package cache

import (
	"strings"

	"github.com/ligato/cn-infra/datasync"

	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"github.com/ligato/cn-infra/logging"
)

// DataResyncEvent wraps an entire state of K8s that should be reflected into VPP.
type DataResyncEvent struct {
	Namespaces []*namespacemodel.Namespace
	Pods       []*podmodel.Pod
	Policies   []*policymodel.Policy
}

// NewDataResyncEvent creates an empty instance of DataResyncEvent.
func NewDataResyncEvent() *DataResyncEvent {
	return &DataResyncEvent{
		Namespaces: []*namespacemodel.Namespace{},
		Pods:       []*podmodel.Pod{},
		Policies:   []*policymodel.Policy{},
	}
}

// resyncParseEvent parses K8s configuration RESYNC event for use by the Config Processor.
func (pc *PolicyCache) resyncParseEvent(resyncEv datasync.ResyncEvent) *DataResyncEvent {
	var numNs int
	var numPolicy int
	var numPod int

	event := NewDataResyncEvent()

	for key := range resyncEv.GetValues() {
		pc.Log.Debug("Received RESYNC key ", key)
	}

	for key, resyncData := range resyncEv.GetValues() {

		if strings.HasPrefix(key, namespacemodel.KeyPrefix()) {

			for {
				evData, stop := resyncData.GetNext()

				if stop {
					break
				}
				key := evData.GetKey()

				// Parse policy RESYNC event
				_, _, err := policymodel.ParsePolicyFromKey(key)
				if err == nil {
					value := &policymodel.Policy{}
					err := evData.GetValue(value)
					if err == nil {
						event.Policies = append(event.Policies, value)
						numPolicy++
					}
					continue
				}

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

				// Parse namespace RESYNC event
				value := &namespacemodel.Namespace{}
				err = evData.GetValue(value)
				if err == nil {
					event.Namespaces = append(event.Namespaces, value)
					numNs++
				}
			}

			pc.Log.WithFields(logging.Fields{
				"num-policies": numPolicy,
				"num-pods":     numPod,
				"num-ns":       numNs,
			}).Debug("Parsed RESYNC event")
		} else {
			pc.Log.WithField("event", resyncEv).Warn("Ignoring RESYNC event")
		}
	}

	return event

}
