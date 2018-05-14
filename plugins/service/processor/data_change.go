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
	"strconv"
	"strings"

	nodemodel "github.com/contiv/vpp/plugins/contiv/model/node"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

func (sc *ServiceProcessor) propagateDataChangeEv(dataChngEv datasync.ChangeEvent) error {
	var diff bool
	var err error
	key := dataChngEv.GetKey()
	sc.Log.Debug("Received CHANGE key ", key)

	// Process Node CHANGE event
	if strings.HasPrefix(key, nodemodel.AllocatedIDsKeyPrefix) {
		var value, prevValue nodemodel.NodeInfo

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			nodeIDStr := strings.TrimPrefix(key, nodemodel.AllocatedIDsKeyPrefix)
			nodeID, err := strconv.Atoi(nodeIDStr)
			if err != nil {
				return err
			}
			return sc.processDeletedNode(nodeID)
		} else if diff {
			return sc.processUpdatedNode(&value)
		}
		return sc.processNewNode(&value)
	}

	// Process Pod CHANGE event
	_, _, err = podmodel.ParsePodFromKey(key)
	if err == nil {
		var value, prevValue podmodel.Pod

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		// Process notification about a new or updated pod.
		if datasync.Delete != dataChngEv.GetChangeType() {
			return sc.processUpdatedPod(&value)
		}
		return nil
	}

	// Process Endpoints CHANGE event
	epsName, epsNs, err := epmodel.ParseEndpointsFromKey(key)
	if err == nil {
		var value, prevValue epmodel.Endpoints

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			return sc.processDeletedEndpoints(epmodel.ID{Name: epsName, Namespace: epsNs})
		} else if diff {
			return sc.processUpdatedEndpoints(&value)
		}
		return sc.processNewEndpoints(&value)
	}

	// Process Service CHANGE event
	svcName, svcNs, err := svcmodel.ParseServiceFromKey(key)
	if err == nil {
		var value, prevValue svcmodel.Service

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			return sc.processDeletedService(svcmodel.ID{Name: svcName, Namespace: svcNs})
		} else if diff {
			return sc.processUpdatedService(&value)
		}
		return sc.processNewService(&value)
	}

	return nil
}
