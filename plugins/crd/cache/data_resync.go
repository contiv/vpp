// Copyright (c) 2018 Cisco and/or its affiliates.
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
	"github.com/ligato/cn-infra/datasync"

	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"

	"fmt"
	"github.com/pkg/errors"
	"regexp"
	"strconv"
	"strings"
)

// Resync processes a data sync re sync event associated with K8s State data.
// The cache content is full replaced with the received data.
func (ctc *ContivTelemetryCache) Resync(resyncEv datasync.ResyncEvent) error {
	err := error(nil)
	ctc.Synced = true

	// Delete all previous data from cache, we are starting from scratch again
	ctc.ReinitializeCache()

	for resyncKey, resyncData := range resyncEv.GetValues() {
		for {
			evData, stop := resyncData.GetNext()
			if stop {
				break
			}

			key := evData.GetKey()
			switch resyncKey {
			case nodeinfomodel.AllocatedIDsKeyPrefix:
				err = ctc.parseAndCacheNodeInfoData(key, evData)

			case podmodel.KeyPrefix():
				err = ctc.parseAndCachePodData(key, evData)

			case nodemodel.KeyPrefix():
				err = ctc.parseAndCacheNodeData(key, evData)

			default:
				err = fmt.Errorf("unknown RESYNC Key %s, key %s", resyncKey, key)
			}

			if err != nil {
				ctc.report = append(ctc.report, err.Error())
				ctc.Log.Error(err)
				ctc.Synced = false
			}
		}
	}

	ctc.Processor.RetrieveNetworkInfo()

	if ctc.Synced == false {
		ctc.report = append(ctc.report, errors.Errorf("%s",
			"datasync error, cache may be out of sync").Error())
		return fmt.Errorf("%s", "datasync error, cache may be out of sync")
	}

	return nil
}

func (ctc *ContivTelemetryCache) parseAndCacheNodeInfoData(key string, evData datasync.KeyVal) error {
	pattern := fmt.Sprintf("%s[0-9]*$", nodeinfomodel.AllocatedIDsKeyPrefix)
	matched, err := regexp.Match(pattern, []byte(key))
	if !matched || err != nil {
		ctc.report = append(ctc.report, errors.Errorf("invalid key %s", key).Error())
		return fmt.Errorf("invalid key %s", key)
	}

	nodeInfoValue := &nodeinfomodel.NodeInfo{}
	err = evData.GetValue(nodeInfoValue)
	if err != nil {
		ctc.report = append(ctc.report, errors.Errorf("could not parse node info data for key %s, error %s",
			key, err).Error())
		return fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
	}

	id, _ := strconv.Atoi(strings.Split(key, "/")[1])
	if nodeInfoValue.Id != uint32(id) {
		ctc.report = append(ctc.report, errors.Errorf("invalid key '%s' or node id '%d'",
			key, nodeInfoValue.Id).Error())
		return fmt.Errorf("invalid key '%s' or node id '%d'", key, nodeInfoValue.Id)
	}

	if nodeInfoValue.Id == 0 || nodeInfoValue.Name == "" ||
		nodeInfoValue.IpAddress == "" || nodeInfoValue.ManagementIpAddress == "" {
		ctc.report = append(ctc.report, errors.Errorf("invalid nodeInfo data: '%+v'",
			nodeInfoValue).Error())
		return fmt.Errorf("invalid nodeInfo data: '%+v'", nodeInfoValue)
	}

	err = ctc.VppCache.CreateNode(nodeInfoValue.Id, nodeInfoValue.Name,
		nodeInfoValue.IpAddress, nodeInfoValue.ManagementIpAddress)
	if err != nil {
		ctc.report = append(ctc.report, err.Error())
		return fmt.Errorf("failed to add vpp node, error: '%s'", err)
	}

	return nil
}

func (ctc *ContivTelemetryCache) parseAndCachePodData(key string, evData datasync.KeyVal) error {
	pod, namespace, err := podmodel.ParsePodFromKey(key)
	if err != nil {
		ctc.report = append(ctc.report, errors.Errorf("invalid key %s", key).Error())
		return fmt.Errorf("invalid key %s", key)
	}

	podValue := &podmodel.Pod{}
	err = evData.GetValue(podValue)
	if err != nil {
		return fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
	}

	ctc.Log.Infof("parseAndCachePodData: pod %s, namespace %s, value %+v", pod, namespace, podValue)
	ctc.K8sCache.createPod(podValue.Name, podValue.Namespace, podValue.Label, podValue.IpAddress, podValue.HostIpAddress, podValue.Container)

	return nil
}

func (ctc *ContivTelemetryCache) parseAndCacheNodeData(key string, evData datasync.KeyVal) error {
	node, err := nodemodel.ParseNodeFromKey(key)
	if err != nil {
		ctc.report = append(ctc.report, errors.Errorf("invalid key %s", key).Error())
		return fmt.Errorf("invalid key %s", key)
	}

	nodeValue := &nodemodel.Node{}
	err = evData.GetValue(nodeValue)
	if err != nil {
		ctc.report = append(ctc.report, errors.Errorf("could not parse node info data for key %s, error %s",
			key, err).Error())
		return fmt.Errorf("could not parse node info data for key %s, error %s", key, err)
	}

	ctc.Log.Infof("parseAndCacheNodeData: node %s, value %+v", node, nodeValue)
	ctc.K8sCache.createK8sNode(nodeValue.Name, nodeValue.Pod_CIDR, nodeValue.Provider_ID, nodeValue.Addresses, nodeValue.NodeInfo)
	return nil
}
