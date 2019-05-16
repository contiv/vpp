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
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
)

// SRv6MockHandler mocks VPP-Agent for SRv6 configuration part. It remembers SRv6 configuration as VPP-Agent would do and exposes it later for unit test for verification.
type SRv6MockHandler struct {
	log       logging.Logger
	LocalSids map[string]*vpp_srv6.LocalSID
	Policies  map[string]*vpp_srv6.Policy
	Steerings map[string]*vpp_srv6.Steering
}

// NewSRv6Mock creates new SRv6MockHandler
func NewSRv6Mock(log logging.Logger) *SRv6MockHandler {
	return &SRv6MockHandler{
		log:       log,
		LocalSids: make(map[string]*vpp_srv6.LocalSID),
		Policies:  make(map[string]*vpp_srv6.Policy),
		Steerings: make(map[string]*vpp_srv6.Steering),
	}
}

// ApplyTxn is called when applying transaction created by Contiv code for VPP-Agent to set up VPP. SRv6 data from transaction
// are further stored (mocking VPP-Agent) and later exposed by other methods/fields to i.e. unit tests for verification purposes.
func (h *SRv6MockHandler) ApplyTxn(txn *localclient.Txn, latestRevs *syncbase.PrevRevisions) error {
	h.log.Debug("Started retrieving SRv6 data from localclient transaction that is currently applied")

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
		if name, isValid := vpp_srv6.ModelLocalSID.ParseKey(key); isValid {
			if value != nil {
				h.LocalSids[name] = value.(*vpp_srv6.LocalSID)
			} else {
				delete(h.LocalSids, name)
			}
		}
		if name, isValid := vpp_srv6.ModelPolicy.ParseKey(key); isValid {
			if value != nil {
				h.Policies[name] = value.(*vpp_srv6.Policy)
			} else {
				delete(h.Policies, name)
			}
		}
		if name, isValid := vpp_srv6.ModelSteering.ParseKey(key); isValid {
			if value != nil {
				h.Steerings[name] = value.(*vpp_srv6.Steering)
			} else {
				delete(h.Steerings, name)
			}
		}
	}

	return nil
}

func (h *SRv6MockHandler) reset() {
	h.LocalSids = make(map[string]*vpp_srv6.LocalSID)
	h.Policies = make(map[string]*vpp_srv6.Policy)
	h.Steerings = make(map[string]*vpp_srv6.Steering)
}

func mapAppend(dest, source map[string]proto.Message) map[string]proto.Message {
	for k, v := range source {
		dest[k] = v
	}
	return dest
}
