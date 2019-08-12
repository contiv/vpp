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

package govpp

import "git.fd.io/govpp.git/api"

// MockGoVPP Simulates GoVpp
type MockGoVPP struct {
}

// NewMockGoVPP is a constructor for MockSessionRules.
func NewMockGoVPP() *MockGoVPP {
	return &MockGoVPP{}
}

// NewAPIChannel does nothing
func (goVPP *MockGoVPP) NewAPIChannel() (api.Channel, error) {
	return nil, nil
}

// NewAPIChannelBuffered does nothing
func (goVPP *MockGoVPP) NewAPIChannelBuffered(reqChanBufSize, replyChanBufSize int) (api.Channel, error) {
	return nil, nil
}
