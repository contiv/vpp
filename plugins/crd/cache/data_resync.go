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
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"

	"strings"
	"fmt"
)

// DataResyncEvent wraps an entire state of K8s that should be reflected into VPP.
type DataResyncEvent struct {
	Pods  []*podmodel.Pod
	Nodes []*nodemodel.Node
	// add more types here
}

// resyncParseEvent parses K8s configuration RESYNC event for use by the Config Processor.
func (ctc *ContivTelemetryCache) resyncParseEvent(resyncEv datasync.ResyncEvent) error {

	for resyncKey, resyncData := range resyncEv.GetValues() {

		for {
			evData, stop := resyncData.GetNext()
			if stop {
				break
			}

			key := evData.GetKey()
			switch resyncKey {
			case nodeinfomodel.AllocatedIDsKeyPrefix:
				ctc.parseAndCacheNodeInfoData(key, evData)

			case podmodel.KeyPrefix():
				ctc.parseAndCachePodData(key, evData)

			case nodemodel.KeyPrefix():
				ctc.parseAndCacheNodeData(key, evData)

			default:
				ctc.Log.Errorf("Unknown RESYNC Key %s, key %s", resyncKey, key)
			}
		}
	}
	return nil

}

func (ctc *ContivTelemetryCache) parseAndCacheNodeInfoData(key string, evData datasync.KeyVal) error {
	nodeIdParts := strings.Split(key, "/")
	if len(nodeIdParts) != 2 {
		err := fmt.Errorf("invalid key %s", key)
		ctc.Log.Error(err)
		return err
	}

	nodeInfoValue := &nodeinfomodel.NodeInfo{}
	err := evData.GetValue(nodeInfoValue)
	if err != nil {
		err1 := fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
		ctc.Log.Error(err1)
		return err1
	}

	ctc.Log.Infof("*** parseAndCacheNodeInfoData: key %s, value %+v", nodeIdParts[1], nodeInfoValue)
	// TODO: Register nodeInfoValue in cache.
	return nil
}

func (ctc *ContivTelemetryCache) parseAndCachePodData(key string, evData datasync.KeyVal) error {
	pod, namespace, err := podmodel.ParsePodFromKey(key)
	if err != nil {
		err := fmt.Errorf("invalid key %s", key)
		ctc.Log.Error(err)
		return err
	}

	podValue := &podmodel.Pod{}
	err = evData.GetValue(podValue)
	if err != nil {
		err1 := fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
		ctc.Log.Error(err1)
		return err1
	}

	ctc.Log.Infof("*** parseAndCachePodData: pod %s, namespace %s, value %+v", pod, namespace, podValue)
	// TODO: Register podValue in cache.
	return nil
}

func (ctc *ContivTelemetryCache) parseAndCacheNodeData(key string, evData datasync.KeyVal) error {
	node, err := nodemodel.ParseNodeFromKey(key)
	if err != nil {
		err := fmt.Errorf("invalid key %s", key)
		ctc.Log.Error(err)
		return err
	}

	nodeValue := &nodemodel.Node{}
	err = evData.GetValue(nodeValue)
	if err != nil {
		err1 := fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
		ctc.Log.Error(err1)
		return err1
	}

	ctc.Log.Infof("*** parseAndCacheNodeData: node %s, value %+v", node, nodeValue)
	// TODO: Register nodeValue in cache.
	return nil
}
