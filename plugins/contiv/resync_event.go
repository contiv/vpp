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

package contiv

import (
	"fmt"
	"strings"

	"github.com/ligato/cn-infra/datasync"

	"github.com/contiv/vpp/plugins/contiv/model/node"
	k8sNode "github.com/contiv/vpp/plugins/ksr/model/node"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// ResyncEventData is a snapshot of the Kubernetes state data
// (the subset used by Contiv plugin).
type ResyncEventData struct {
	NodeInfo map[int]*node.NodeInfo
	Pods     []*k8sPod.Pod
	Nodes    []*k8sNode.Node
}

// NewResyncEventData creates an empty instance of ResyncEventData.
func NewResyncEventData() *ResyncEventData {
	return &ResyncEventData{
		NodeInfo: make(map[int]*node.NodeInfo),
		Pods:     []*k8sPod.Pod{},
		Nodes:    []*k8sNode.Node{},
	}
}

// String converts ResyncEventData into a human-readable string.
func (red ResyncEventData) String() string {
	pods := ""
	for idx, pod := range red.Pods {
		pods += pod.String()
		if idx < len(red.Pods)-1 {
			pods += ", "
		}
	}
	nodes := ""
	for idx, node := range red.Nodes {
		nodes += node.String()
		if idx < len(red.Nodes)-1 {
			nodes += ", "
		}
	}
	return fmt.Sprintf("ResyncEventData <NodeInfo:%v Pods:[%s] Nodes:[%s]>",
		red.NodeInfo, pods, nodes)
}

// ParseResyncEvent converts datasync.ResyncEvent into ResyncEventData.
func ParseResyncEvent(resyncEv datasync.ResyncEvent, revs map[string]datasync.KeyVal) *ResyncEventData {
	var err error

	event := NewResyncEventData()

	for _, resyncData := range resyncEv.GetValues() {

		for {
			evData, stop := resyncData.GetNext()

			if stop {
				break
			}
			key := evData.GetKey()
			if revs != nil {
				revs[key] = evData
			}

			// Parse nodeinfo RESYNC event
			if strings.HasPrefix(key, node.AllocatedIDsKeyPrefix) {
				value := &node.NodeInfo{}
				err := evData.GetValue(value)
				if err == nil {
					event.NodeInfo[int(value.Id)] = value
				}
				continue
			}

			// Parse pod RESYNC event
			_, _, err = k8sPod.ParsePodFromKey(key)
			if err == nil {
				value := &k8sPod.Pod{}
				err := evData.GetValue(value)
				if err == nil {
					event.Pods = append(event.Pods, value)
				}
				continue
			}

			// Parse node RESYNC event
			_, err = k8sNode.ParseNodeFromKey(key)
			if err == nil {
				value := &k8sNode.Node{}
				err := evData.GetValue(value)
				if err == nil {
					event.Nodes = append(event.Nodes, value)
				}
				continue
			}
		}
	}

	return event
}
