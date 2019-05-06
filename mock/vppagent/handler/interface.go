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
	linux_interfaces "github.com/ligato/vpp-agent/api/models/linux/interfaces"
)

// InterfaceMockHandler mocks VPP-Agent for Interface configuration part. It remembers Interfaces as VPP-Agent would do and exposes it later for unit test for verification.
type InterfaceMockHandler struct {
	log        logging.Logger
	Interfaces map[string]*linux_interfaces.Interface
}

// NewInterfaceMock creates new InterfaceMockHandler
func NewInterfaceMock(log logging.Logger) *InterfaceMockHandler {
	return &InterfaceMockHandler{
		log:        log,
		Interfaces: make(map[string]*linux_interfaces.Interface),
	}
}

// ApplyTxn is called when applying transaction created by Contiv code for VPP-Agent to set up VPP. Interface data from transaction
// are further stored (mocking VPP-Agent) and later exposed by other methods/fields to i.e. unit tests for verification purposes.
func (h *InterfaceMockHandler) ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	h.log.Debug("Started retrieving Interface data from localclient transaction that is currently applied")

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
		if name, isValid := linux_interfaces.ModelInterface.ParseKey(key); isValid {
			if value != nil {
				h.Interfaces[name] = value.(*linux_interfaces.Interface)
			} else {
				delete(h.Interfaces, name)
			}
		}
	}

	return nil
}

func (h *InterfaceMockHandler) reset() {
	h.Interfaces = make(map[string]*linux_interfaces.Interface)
}
