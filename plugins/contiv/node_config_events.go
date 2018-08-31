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

package contiv

import (
	"context"

	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
)

// handleNodeConfigEvents handles changes in the configuration specific to this node.
func (s *remoteCNIserver) handleNodeConfigEvents(ctx context.Context, resyncChan chan datasync.ResyncEvent, changeChan chan datasync.ChangeEvent) {
	for {
		select {

		case resyncEv := <-resyncChan:
			err := s.processNodeConfigResync(resyncEv)
			resyncEv.Done(err)

		case changeEv := <-changeChan:
			err := s.processNodeConfigChange(changeEv)
			changeEv.Done(err)

		case <-ctx.Done():
			return
		}
	}
}

// processNodeConfigResync processes resync event carrying the node-specific configuration.
func (s *remoteCNIserver) processNodeConfigResync(dataResyncEv datasync.ResyncEvent) error {
	data := dataResyncEv.GetValues()

	for _, it := range data {
		for {
			kv, stop := it.GetNext()
			if stop {
				break
			}

			nodeConfigProto := &nodeconfig.NodeConfig{}
			err := kv.GetValue(nodeConfigProto)
			if err != nil {
				return err
			}

			return s.processUpdatedNodeConfig(nodeConfigProto)
		}
	}

	return nil
}

// processNodeConfigChange processes data change event carrying the node-specific
// configuration.
func (s *remoteCNIserver) processNodeConfigChange(dataChngEv datasync.ChangeEvent) error {
	var nodeConfigProto *nodeconfig.NodeConfig
	if dataChngEv.GetChangeType() == datasync.Put {
		nodeConfigProto = &nodeconfig.NodeConfig{}
		err := dataChngEv.GetValue(nodeConfigProto)
		if err != nil {
			return err
		}
	}

	return s.processUpdatedNodeConfig(nodeConfigProto)
}

// processUpdatedNodeConfig processes updated node-specific configuration.
func (s *remoteCNIserver) processUpdatedNodeConfig(nodeConfigProto *nodeconfig.NodeConfig) error {
	s.Logger.WithField("config", nodeConfigProto).Info("Processing node-specific configuration update")

	// TODO: as long as the vpp-agent configuration is persisted, we cannot support runtime
	// node configuration change - not even through a full restart, since the agent would
	// reload the same obsolete configuration again, before we can do anything about it.
	var (
		nodeConfig *NodeConfig
		changed    bool
	)
	if nodeConfigProto == nil {
		// removed
		if s.nodeConfig != nil {
			changed = true
		}
	} else {
		// created/modified
		nodeConfig = nodeConfigFromProto(nodeConfigProto)
		if s.nodeConfig != nil && !s.nodeConfig.EqualsTo(&nodeConfig.NodeConfigSpec) {
			changed = true
		}
	}

	if changed {
		s.Logger.WithFields(logging.Fields{
			"oldConfig": s.nodeConfig,
			"newConfig": nodeConfig,
		}).Error("Runtime node configuration change is unsupported")
	}

	return nil
}
