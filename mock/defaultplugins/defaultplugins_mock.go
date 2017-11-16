package defaultplugins

import (
	"github.com/ligato/vpp-agent/idxvpp"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/bdidx"
)

// MockVppPlugin is a mock for VPP plugin (defaultplugins).
type MockVppPlugin struct {
	ACLs []*acl.AccessLists_Acl
}

// NewMockVppPlugin is a constructor for MockVppPlugin.
func NewMockVppPlugin() *MockVppPlugin {
	return &MockVppPlugin{ACLs: []*acl.AccessLists_Acl{}}
}

// DumpACLs dumps ACLs added with AddACL().
func (mvp *MockVppPlugin) DumpACLs() []*acl.AccessLists_Acl {
	return mvp.ACLs
}

// ClearACLs clears the list ACLs for the dump.
func (mvp *MockVppPlugin) ClearACLs() {
	mvp.ACLs = []*acl.AccessLists_Acl{}
}

// AddAcl adds ACL for DumpACLs().
func (mvp *MockVppPlugin) AddACL(acl *acl.AccessLists_Acl) {
	mvp.ACLs = append(mvp.ACLs, acl)
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
