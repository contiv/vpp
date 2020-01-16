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

package pluginvpp

import (
	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/logging/logrus"

	"go.ligato.io/vpp-agent/v2/plugins/vpp/ifplugin/ifaceidx"
	"go.ligato.io/vpp-agent/v2/proto/ligato/vpp"
)

// MockVppIfPlugin is a mock for VPP ifplugin.
type MockVppIfPlugin struct {
	swIfIndexes ifaceidx.IfaceMetadataIndexRW
}

// NewMockVppPlugin is a constructor for MockVppPlugin.
func NewMockVppPlugin() *MockVppIfPlugin {
	return &MockVppIfPlugin{
		swIfIndexes: ifaceidx.NewIfaceIndex(logrus.DefaultLogger(), "sw_if_indexes"),
	}
}

// AddInterface adds interface into the map of interfaces (returned by GetSwIfIndexes()).
func (mvp *MockVppIfPlugin) AddInterface(ifName string, swIfIndex uint32, ip string) {
	mvp.swIfIndexes.Put(ifName, ifaceidx.IfaceMetadata{
		SwIfIndex:   swIfIndex,
		IPAddresses: []string{ip},
	})
}

// GetInterfaceIndex return map of interfaces added via AddInterface.
func (mvp *MockVppIfPlugin) GetInterfaceIndex() ifaceidx.IfaceMetadataIndex {
	return mvp.swIfIndexes
}

// GetDHCPIndex does nothing here.
func (mvp *MockVppIfPlugin) GetDHCPIndex() idxmap.NamedMapping {
	return nil
}

// SetNotifyService does nothing here
func (mvp *MockVppIfPlugin) SetNotifyService(notify func(notification *vpp.Notification)) {}
