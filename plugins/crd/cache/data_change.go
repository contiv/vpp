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
	"github.com/ligato/cn-infra/datasync"

	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
)

// changePropagateEvent propagates CHANGE in the K8s configuration into the Cache.
func (ctc *ContivTelemetryCache) changePropagateEvent(dataChngEv datasync.ChangeEvent) error {
	var err error
	var diff bool
	key := dataChngEv.GetKey()
	ctc.Log.SetLevel(logging.DebugLevel)
	ctc.Log.Debug("Received CHANGE key ", key)

	// Propagate Pod CHANGE event
	// use this to get pod name and pod namespace
	// podName, podNs, err := podmodel.ParsePodFromKey(key)
	if err == nil {
		var value, prevValue podmodel.Pod
		// use this to create a podID and use it to store/delete/update in pod Cache
		// podID := podmodel.ID{Name: podName, Namespace: podNs}

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			// podID used here
			// todo - remove

		} else if diff {
			// podID used here to remove and then update
			// key remains the same
			// todo - remove old pod in cache
			// todo - add updated pod in cache

		} else {
			ctc.Log.Infof("Pod added with value: %v", value)
			// podID used here
			// todo - add pod to cache
		}
		return nil
	}

	// Propagate Pod CHANGE event
	// use this to get node name
	// nodeName, err := nodemodel.ParseNodeFromKey(key)
	// Propagate Namespace CHANGE event
	_, err = nodemodel.ParseNodeFromKey(key)
	if err == nil {
		var value, prevValue nodemodel.Node

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			//nodeID := nodemodel.GetID(&prevValue).String()

		} else if diff {
			//newNodeID := nodemodel.GetID(&prevValue).String()
			//oldNodeID := nodemodel.GetID(&prevValue).String()

		} else {
			//nodeID := nodemodel.GetID(&prevValue).String()
		}
	}

	return nil
}
