package defaultplugins

import (
	"github.com/ligato/vpp-agent/idxvpp"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/bdidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/nsidx"
)

// MockVppPlugin is a mock for VPP plugin (defaultplugins).
type MockVppPlugin struct {
	ACLs []*acl.AccessLists_Acl
}

// NewMockVppPlugin is a constructor for MockVppPlugin.
func NewMockVppPlugin() *MockVppPlugin {
	return &MockVppPlugin{ACLs: []*acl.AccessLists_Acl{}}
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

// DisableResync does nothing here.
func (mvp *MockVppPlugin) DisableResync(keyPrefix ...string) {
}

// GetSwIfIndexes does nothing here.
func (mvp *MockVppPlugin) GetSwIfIndexes() ifaceidx.SwIfIndex {
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
