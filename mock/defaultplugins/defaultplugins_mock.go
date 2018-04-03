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

package defaultplugins

import (
	"github.com/ligato/cn-infra/logging/logrus"

	"github.com/ligato/vpp-agent/idxvpp"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"
	vppintf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/bdidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/nsidx"
)

// MockVppPlugin is a mock for VPP plugin (defaultplugins).
type MockVppPlugin struct {
	swIfIndexes ifaceidx.SwIfIndexRW
	ACLs        []*acl.AccessLists_Acl
	nat44Global *nat.Nat44Global
	nat44Dnat   *nat.Nat44DNat
}

// NewMockVppPlugin is a constructor for MockVppPlugin.
func NewMockVppPlugin() *MockVppPlugin {
	return &MockVppPlugin{
		swIfIndexes: ifaceidx.NewSwIfIndex(nametoidx.NewNameToIdx(logrus.DefaultLogger(), "defaultplugins-mock",
			"sw_if_indexes", ifaceidx.IndexMetadata)),
		ACLs: []*acl.AccessLists_Acl{},
	}
}

// AddInterface adds interface into the map of interfaces (returned by GetSwIfIndexes()).
func (mvp *MockVppPlugin) AddInterface(ifName string, swIfIndex uint32, ip string) {
	mvp.swIfIndexes.RegisterName(ifName, swIfIndex, &vppintf.Interfaces_Interface{
		Name:        ifName,
		IpAddresses: []string{ip},
	})
}

// DumpACL dumps ACLs added with AddACL().
func (mvp *MockVppPlugin) DumpACL() (acls []*acl.AccessLists_Acl, err error) {
	return mvp.ACLs, nil
}

// ClearACLs clears the list ACLs for the dump.
func (mvp *MockVppPlugin) ClearACLs() {
	mvp.ACLs = []*acl.AccessLists_Acl{}
}

// AddAcl adds ACL for DumpACLs().
func (mvp *MockVppPlugin) AddACL(acls ...*acl.AccessLists_Acl) {
	for _, acl := range acls {
		mvp.ACLs = append(mvp.ACLs, acl)
	}
}

// SetNat44Global sets data for DumpNat44Global().
func (mvp *MockVppPlugin) SetNat44Global(cfg *nat.Nat44Global) {
	mvp.nat44Global = cfg
}

// SetNat44Dnat sets data for DumpNat44Dnat().
func (mvp *MockVppPlugin) SetNat44Dnat(cfg *nat.Nat44DNat) {
	mvp.nat44Dnat = cfg
}

// DisableResync does nothing here.
func (mvp *MockVppPlugin) DisableResync(keyPrefix ...string) {
}

// GetSwIfIndexes does nothing here.
func (mvp *MockVppPlugin) GetSwIfIndexes() ifaceidx.SwIfIndex {
	return mvp.swIfIndexes
}

// GetSwIfIndexes does nothing here.
func (mvp *MockVppPlugin) GetDHCPIndices() ifaceidx.DhcpIndex {
	return nil
}

// GetBfdSessionIndexes does nothing here.
func (mvp *MockVppPlugin) GetBfdSessionIndexes() idxvpp.NameToIdx {
	return nil
}

// GetBfdAuthKeyIndexes does nothing here.
func (mvp *MockVppPlugin) GetBfdAuthKeyIndexes() idxvpp.NameToIdx {
	return nil
}

// GetBfdEchoFunctionIndexes does nothing here.
func (mvp *MockVppPlugin) GetBfdEchoFunctionIndexes() idxvpp.NameToIdx {
	return nil
}

// GetBDIndexes does nothing here.
func (mvp *MockVppPlugin) GetBDIndexes() bdidx.BDIndex {
	return nil
}

// GetFIBIndexes does nothing here.
func (mvp *MockVppPlugin) GetFIBIndexes() idxvpp.NameToIdx {
	return nil
}

// GetXConnectIndexes does nothing here.
func (mvp *MockVppPlugin) GetXConnectIndexes() idxvpp.NameToIdx {
	return nil
}

// GetAppNsIndexes does nothing here.
func (mvp *MockVppPlugin) GetAppNsIndexes() nsidx.AppNsIndex {
	return nil
}

// DumpNat44Global returns the current NAT44 global config
func (mvp *MockVppPlugin) DumpNat44Global() (*nat.Nat44Global, error) {
	return mvp.nat44Global, nil
}

// DumpNat44DNat returns the current NAT44 DNAT config
func (mvp *MockVppPlugin) DumpNat44DNat() (*nat.Nat44DNat, error) {
	return mvp.nat44Dnat, nil
}

// GetIPSecSAIndexes
func (mvp *MockVppPlugin) GetIPSecSAIndexes() idxvpp.NameToIdx {
	return nil
}

// GetIPSecSPDIndexes
func (mvp *MockVppPlugin) GetIPSecSPDIndexes() idxvpp.NameToIdx {
	return nil
}
