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

package vppagent

import (
	"fmt"
	"sync"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/ligato/cn-infra/datasync/syncbase"
)

// MockVPPAgent mocks vpp agent behaviour related to transaction committing to vpp agent using vpp agent client. MockVPPAgent
// can register multiple handlers that mock different parts of transaction commit parts (i.e. SRv6, Routes, ...)
type MockVPPAgent struct {
	sync.Mutex
	handlers []MockTransationHandler
}

// MockTransationHandler is API for mocked handlers handling the whole transaction or only part of the transaction. In case of
// partial handling of transaction, parts of transactions handled create some logical group (i.e. SRv6, Routes, Interfaces,...)
type MockTransationHandler interface {
	// ApplyTxn is called when applying transaction created by Contiv code for VPP-Agent to set up VPP. Data from transaction
	// are used by mock transaction handler, usually for exposing to unit tests for verification purposes.
	ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error
}

func NewMockVPPAgent(handlers ...MockTransationHandler) *MockVPPAgent {
	return &MockVPPAgent{
		handlers: handlers,
	}
}

func (m *MockVPPAgent) ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	m.Lock()
	defer m.Unlock()

	for _, handler := range m.handlers {
		if err := handler.ApplyTxn(txn, latestRevs); err != nil {
			return fmt.Errorf("error in handler %T: %v", handler, err)
		}
	}
	return nil
}
