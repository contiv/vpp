// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
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

package handler

import (
	"errors"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/linux/iptables"
)

// RuleChainMockHandler mocks VPP-Agent for RuleChain configuration part. It remembers RuleChains as VPP-Agent would do and exposes it later for unit test for verification.
type RuleChainMockHandler struct {
	log        logging.Logger
	RuleChains map[string]*linux_iptables.RuleChain
}

// NewRuleChainMock creates new RuleChainMockHandler
func NewRuleChainMock(log logging.Logger) *RuleChainMockHandler {
	return &RuleChainMockHandler{
		log:        log,
		RuleChains: make(map[string]*linux_iptables.RuleChain),
	}
}

// ApplyTxn is called when applying transaction created by Contiv code for VPP-Agent to set up VPP. RuleChains data from transaction
// are further stored (mocking VPP-Agent) and later exposed by other methods/fields to i.e. unit tests for verification purposes.
func (h *RuleChainMockHandler) ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	h.log.Debug("Started retrieving RuleChains data from localclient transaction that is currently applied")

	if txn == nil {
		return errors.New("txn is nil")
	}

	values := make(map[string]proto.Message)
	if txn.VPPDataResyncTxn != nil {
		h.reset()
		values = mapAppend(values, txn.VPPDataResyncTxn.CommonMockDSL.Values)
	}
	if txn.LinuxDataResyncTxn != nil {
		h.reset()
		values = mapAppend(values, txn.LinuxDataResyncTxn.CommonMockDSL.Values)
	}
	if txn.VPPDataChangeTxn != nil {
		values = mapAppend(values, txn.VPPDataChangeTxn.CommonMockDSL.Values)
	}
	if txn.LinuxDataChangeTxn != nil {
		values = mapAppend(values, txn.LinuxDataChangeTxn.CommonMockDSL.Values)
	}

	for key, value := range values {
		if name, isValid := linux_iptables.ModelRuleChain.ParseKey(key); isValid {
			if value != nil {
				h.RuleChains[name] = value.(*linux_iptables.RuleChain)
			} else {
				delete(h.RuleChains, name)
			}
		}
	}

	return nil
}

func (h *RuleChainMockHandler) reset() {
	h.RuleChains = make(map[string]*linux_iptables.RuleChain)
}
