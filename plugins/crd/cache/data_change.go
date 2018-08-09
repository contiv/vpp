// Copyright (c) 2017 Cisco and/or its affiliates.
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

package cache

import (
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"

	"fmt"
	"strings"
)

type dataChangeProcessor interface {
	GetNames(key string) ([]string, error)
	GetValueProto() proto.Message
	AddRecord(ctc *ContivTelemetryCache, names []string, record proto.Message) error
	UpdateRecord(ctc *ContivTelemetryCache, names []string, oldRecord proto.Message, newRecord proto.Message) error
	DeleteRecord(ctc *ContivTelemetryCache, names []string) error
}

// dataChangeProcessor implementation for K8s pod data
type podChange struct{}

func (pc *podChange) GetNames(key string) ([]string, error) {
	pod, namespace, err := podmodel.ParsePodFromKey(key)
	return []string{pod, namespace}, err
}

func (pc *podChange) GetValueProto() proto.Message {
	return &podmodel.Pod{}
}

func (pc *podChange) AddRecord(ctc *ContivTelemetryCache, names []string, record proto.Message) error {
	ctc.Log.Infof("Adding pod %s in namespace %s, podValue %+v", names[0], names[1], record)
	// TODO: ctc.createPod(names[0], names[1], podValue)
	return nil
}

func (pc *podChange) UpdateRecord(ctc *ContivTelemetryCache,
	names []string, oldRecord proto.Message, newRecord proto.Message) error {
	ctc.Log.Infof("Updating pod %s in namespace %s, podValue %+v, prevPodValue %+v",
		names[0], names[1], oldRecord, newRecord)
	// TODO: ctc.updatePod(names[0], names[1], prevPodValue, podValue)
	return nil
}

func (pc *podChange) DeleteRecord(ctc *ContivTelemetryCache, names []string) error {
	ctc.Log.Infof("Deleting pod %s in namespace %s", names[0], names[1])
	// TODO: ctc.deletePod(names[0], names[1])
	return nil
}

// dataChangeProcessor implementation for K8s node data
type nodeChange struct{}

func (nc *nodeChange) GetNames(key string) ([]string, error) {
	node, err := nodemodel.ParseNodeFromKey(key)
	return []string{node}, err
}

func (nc *nodeChange) GetValueProto() proto.Message {
	return &nodemodel.Node{}
}

func (nc *nodeChange) AddRecord(ctc *ContivTelemetryCache, names []string, record proto.Message) error {
	ctc.Log.Infof("Adding node %s, nodeValue %+v", names[0], record)
	// TODO: ctc.addNode(names[0], podValue)
	return nil
}

func (nc *nodeChange) UpdateRecord(ctc *ContivTelemetryCache,
	names []string, oldRecord proto.Message, newRecord proto.Message) error {
	ctc.Log.Infof("Updating node %s, nodeValue %+v, prevNodeValue %+v", names[0], oldRecord, newRecord)
	// TODO: ctc.updatePod(names[0], prevPodValue, podValue)
	return nil
}

func (nc *nodeChange) DeleteRecord(ctc *ContivTelemetryCache, names []string) error {
	ctc.Log.Infof("Deleting node %s", names[0])
	// TODO: ctc.deletePod(names[0])
	return nil
}

// dataChangeProcessor implementation for nodeIndo data
type nodeInfoChange struct{}

func (nic *nodeInfoChange) GetNames(key string) ([]string, error) {
	nodeParts := strings.Split(key, "/")
	if len(nodeParts) != 2 {
		return nil, fmt.Errorf("invalid nodeLiveness key %s", key)
	}
	return []string{nodeParts[1]}, nil
}

func (nic *nodeInfoChange) GetValueProto() proto.Message {
	return &nodeinfomodel.NodeInfo{}
}

func (nic *nodeInfoChange) AddRecord(ctc *ContivTelemetryCache, names []string, record proto.Message) error {
	ctc.Log.Infof("Adding nodeLiveness %s, nodeValue %+v", names[0], record)
	// TODO: return ctc.addNodeInfo(names[0], podValue)
	return nil
}

func (nic *nodeInfoChange) UpdateRecord(ctc *ContivTelemetryCache,
	names []string, oldRecord proto.Message, newRecord proto.Message) error {
	ctc.Log.Infof("Updating nodeLiveness %s, nodeInfoValue %+v, prevNodeInfoValue %+v",
		names[0], oldRecord, newRecord)
	// TODO: return ctc.updateNodeInfonames[0], prevPodValue, podValue)
	return nil
}

func (nic *nodeInfoChange) DeleteRecord(ctc *ContivTelemetryCache, names []string) error {
	ctc.Log.Infof("Deleting nodeLiveness %s", names[0])
	// TODO: return ctc.deleteNodeInfo(names[0])
	return nil
}

// Update processes a data sync change event associated with K8s State data.
// The change is applied into the cache and all subscribed watchers are
// notified.
// The function will forward any error returned by a watcher.
func (ctc *ContivTelemetryCache) Update(dataChngEv datasync.ChangeEvent) error {
	err := error(nil)
	key := dataChngEv.GetKey()
	var dcp dataChangeProcessor

	// Determine which data is changing
	switch {
	case strings.HasPrefix(key, nodeinfomodel.AllocatedIDsKeyPrefix):
		dcp = &nodeInfoChange{}

	case strings.HasPrefix(key, nodemodel.KeyPrefix()):
		dcp = &nodeChange{}

	case strings.HasPrefix(key, podmodel.KeyPrefix()):
		dcp = &podChange{}

	default:
		return fmt.Errorf("unknown DATA CHANGE key %s", key)
	}

	names, err := dcp.GetNames(key)
	if err != nil {
		return err
	}

	// Determine the type of & perform the data change operation
	switch dataChngEv.GetChangeType() {
	case datasync.Delete:
		err = dcp.DeleteRecord(ctc, names)

	case datasync.Put:
		newRecord := dcp.GetValueProto()
		if err := dataChngEv.GetValue(newRecord); err != nil {
			err = fmt.Errorf("could not get new proto data for key %s, error %s", key, err)
			break
		}

		oldRecord := dcp.GetValueProto()
		exists, err := dataChngEv.GetPrevValue(oldRecord)
		if err != nil {
			err = fmt.Errorf("could not get previous proto data for key %s, error %s", key, err)
			break
		}

		if exists {
			err = dcp.UpdateRecord(ctc, names, oldRecord, newRecord)
		} else {
			err = dcp.AddRecord(ctc, names, newRecord)
		}

	default:
		err = fmt.Errorf("unknown event change type %+v", dataChngEv.GetChangeType())
	}

	return err
}
