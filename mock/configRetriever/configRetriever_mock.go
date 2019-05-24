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

package configRetriever

import "github.com/gogo/protobuf/proto"

// MockConfigRetriever mocks ConfigRetriever that allows to read configuration in order to adjust a config item
// by multiple event handlers.
type MockConfigRetriever struct {
	configs map[string]proto.Message
}

// GetConfig is mock implementation that mocks returning value for the given key in the controller's transaction (or if
// data is missing in transaction, controller's stored internal config is retrieved).
func (m *MockConfigRetriever) GetConfig(key string) proto.Message {
	return m.configs[key]
}

func (m *MockConfigRetriever) AddConfig(key string, val proto.Message) {
	m.configs[key] = val
}

// NewMockConfigRetriever is a constructor for MockConfigRetriever.
func NewMockConfigRetriever() *MockConfigRetriever {
	return &MockConfigRetriever{
		configs: make(map[string]proto.Message),
	}
}
