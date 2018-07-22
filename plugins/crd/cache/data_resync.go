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

package cache

import (
	"github.com/ligato/cn-infra/datasync"

	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"

	"github.com/ligato/cn-infra/logging"
)

// DataResyncEvent wraps an entire state of K8s that should be reflected into VPP.
type DataResyncEvent struct {
	Pods  []*podmodel.Pod
	Nodes []*nodemodel.Node
	// add more types here
}

// NewDataResyncEvent creates an empty instance of DataResyncEvent.
func NewDataResyncEvent() *DataResyncEvent {
	return &DataResyncEvent{
		Pods:  []*podmodel.Pod{},
		Nodes: []*nodemodel.Node{},
		// init more types here
	}
}

// resyncParseEvent parses K8s configuration RESYNC event for use by the Config Processor.
func (ctc *ContivTelemetryCache) resyncParseEvent(resyncEv datasync.ResyncEvent) error {
	var numPod, numNode int

	event := NewDataResyncEvent()
	ctc.Log.Debug("Received RESYNC Event ", resyncEv)

	for key, resyncData := range resyncEv.GetValues() {
		ctc.Log.Debug("Received RESYNC key ", key)

		for {
			evData, stop := resyncData.GetNext()

			if stop {
				break
			}
			key := evData.GetKey()

			// Parse pod RESYNC event
			_, _, err := podmodel.ParsePodFromKey(key)
			if err != nil {
				return err
			}
			podValue := &podmodel.Pod{}
			err = evData.GetValue(podValue)
			if err != nil {
				return err
			}

			event.Pods = append(event.Pods, podValue)
			//podID := podmodel.GetID(value).String()
			// todo register pod in cache
			numPod++
			continue

			// Parse node RESYNC event
			_, err = nodemodel.ParseNodeFromKey(key)
			if err != nil {
				return err
			}
			nodeValue := &nodemodel.Node{}
			err = evData.GetValue(nodeValue)
			if err != nil {
				return err
			}
			event.Nodes = append(event.Nodes, nodeValue)
			// nodeID := nodemodel.GetID(value).String()
			// todo register node in cache
			numNode++
			continue
		}
	}

	ctc.Log.WithFields(logging.Fields{
		"num-pods":  numPod,
		"num-nodes": numNode,
	}).Debug("Parsed RESYNC event")

	return nil

}
