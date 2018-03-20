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

package servicelabel

// MockServiceLabel is a mock for ServiceLabel plugin.
type MockServiceLabel struct {
	agentLabel string
}

// NewServiceLabel is a constructor for ServiceLabel.
func NewMockServiceLabel() *MockServiceLabel {
	return &MockServiceLabel{}
}

// SetAgentLabel allows to set what tests will assume the agent label is.
func (msl *MockServiceLabel) SetAgentLabel(label string) {
	msl.agentLabel = label
}

// GetAgentLabel return the microservice label associated with this Agent
// instance.
func (msl *MockServiceLabel) GetAgentLabel() string {
	return msl.agentLabel
}

// GetAgentPrefix returns the string that is supposed to be used
// as the key prefix for the configuration "subtree" of the current Agent
// instance (e.g. in ETCD).
func (msl *MockServiceLabel) GetAgentPrefix() string {
	return msl.GetAllAgentsPrefix() + msl.GetAgentLabel() + "/"
}

// GetDifferentAgentPrefix returns the key prefix used by (another) Agent
// instance from microservice labelled as <microserviceLabel>.
func (msl *MockServiceLabel) GetDifferentAgentPrefix(microserviceLabel string) string {
	return msl.GetAllAgentsPrefix() + microserviceLabel + "/"
}

// GetAllAgentsPrefix returns the part of the key prefix common to all
// prefixes of all agents.
func (msl *MockServiceLabel) GetAllAgentsPrefix() string {
	return "/vnf-agent/"
}
