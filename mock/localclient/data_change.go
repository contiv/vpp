package localclient

import (
	"net"

	"github.com/ligato/vpp-agent/clientv1/defaultplugins"
	"github.com/ligato/vpp-agent/clientv1/linux"

	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/bfd"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"
)

// MockDataChangeDSL is mock for DataChangeDSL.
type MockDataChangeDSL struct {
	// List of transaction operations in the order as they were called.
	Ops []TxnOp

	txnTracker *TxnTracker
	txn        *Txn
}

// newMockDataChangeDSL is a constructor for MockDataChangeDSL.
func newMockDataChangeDSL(tracker *TxnTracker, transaction *Txn) *MockDataChangeDSL {
	return &MockDataChangeDSL{txnTracker: tracker, txn: transaction}
}

// MockPutDSL is a mock for PutDSL.
type MockPutDSL struct {
	parent *MockDataChangeDSL
}

// MockDeleteDSL is a mock for DeleteDSL.
type MockDeleteDSL struct {
	parent *MockDataChangeDSL
}

// Put initiates a chained sequence of data change DSL statements declaring
// new or changing existing configurable objects.
func (dsl *MockDataChangeDSL) Put() linux.PutDSL {
	return &MockPutDSL{dsl}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (dsl *MockDataChangeDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{dsl}
}

// Send commits the transaction into the mock DB.
func (dsl *MockDataChangeDSL) Send() defaultplugins.Reply {
	err := dsl.txnTracker.commit(dsl.txn)
	return &Reply{err}
}

// apply reflects the effect of transaction operations into the mock DB.
func (dsl *MockDataChangeDSL) apply() {
	for _, op := range dsl.Ops {
		if op.Value != nil {
			dsl.txnTracker.AppliedConfig[op.Key] = op.Value
		} else {
			_, exists := dsl.txnTracker.AppliedConfig[op.Key]
			if exists {
				delete(dsl.txnTracker.AppliedConfig, op.Key)
			}
		}
	}
}

// Interface adds a mock request to create or update VPP network interface.
func (dsl *MockPutDSL) VppInterface(val *vpp_intf.Interfaces_Interface) linux.PutDSL {
	op := TxnOp{Key: vpp_intf.InterfaceKey(val.Name), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdSession adds a mock request to create or update bidirectional forwarding
// detection session.
func (dsl *MockPutDSL) BfdSession(val *bfd.SingleHopBFD_Session) linux.PutDSL {
	op := TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdAuthKeys adds a mock request to create or update bidirectional forwarding
// detection key.
func (dsl *MockPutDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linux.PutDSL {
	op := TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdEchoFunction adds a mock request to create or update bidirectional
// forwarding detection echo function.
func (dsl *MockPutDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linux.PutDSL {
	op := TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (dsl *MockPutDSL) BD(val *l2.BridgeDomains_BridgeDomain) linux.PutDSL {
	op := TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (dsl *MockPutDSL) BDFIB(val *l2.FibTableEntries_FibTableEntry) linux.PutDSL {
	op := TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (dsl *MockPutDSL) XConnect(val *l2.XConnectPairs_XConnectPair) linux.PutDSL {
	op := TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (dsl *MockPutDSL) StaticRoute(val *l3.StaticRoutes_Route) linux.PutDSL {
	_, dstAddr, _ := net.ParseCIDR(val.DstIpAddr)
	op := TxnOp{Key: l3.RouteKey(val.VrfId, dstAddr, val.NextHopAddr), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// ACL adds a mock request to create or update VPP Access Control List.
func (dsl *MockPutDSL) ACL(val *acl.AccessLists_Acl) linux.PutDSL {
	op := TxnOp{Key: acl.Key(val.AclName), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// LinuxInterface adds a mock request to create or update Linux network interface.
func (dsl *MockPutDSL) LinuxInterface(val *linux_intf.LinuxInterfaces_Interface) linux.PutDSL {
	op := TxnOp{Key: linux_intf.InterfaceKey(val.Name), Value: val}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (dsl *MockPutDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{dsl.parent}
}

// Send commits the transaction into the mock DB.
func (dsl *MockPutDSL) Send() defaultplugins.Reply {
	return dsl.parent.Send()
}

// Interface adds a mock request to delete an existing VPP network interface.
func (dsl *MockDeleteDSL) VppInterface(interfaceName string) linux.DeleteDSL {
	op := TxnOp{Key: vpp_intf.InterfaceKey(interfaceName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdSession adds a mock request to delete an existing bidirectional forwarding
// detection session.
func (dsl *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) linux.DeleteDSL {
	op := TxnOp{Key: bfd.SessionKey(bfdSessionIfaceName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdAuthKeys adds a mock request to delete an existing bidirectional forwarding
// detection key.
func (dsl *MockDeleteDSL) BfdAuthKeys(bfdKeyName string) linux.DeleteDSL {
	op := TxnOp{Key: bfd.AuthKeysKey(bfdKeyName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BfdEchoFunction adds a mock request to delete an existing bidirectional
// forwarding detection echo function.
func (dsl *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) linux.DeleteDSL {
	op := TxnOp{Key: bfd.EchoFunctionKey(bfdEchoName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (dsl *MockDeleteDSL) BD(bdName string) linux.DeleteDSL {
	op := TxnOp{Key: l2.BridgeDomainKey(bdName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (dsl *MockDeleteDSL) BDFIB(bdName string, mac string) linux.DeleteDSL {
	op := TxnOp{Key: l2.FibKey(bdName, mac)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (dsl *MockDeleteDSL) XConnect(rxIfName string) linux.DeleteDSL {
	op := TxnOp{Key: l2.XConnectKey(rxIfName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (dsl *MockDeleteDSL) StaticRoute(vrf uint32, dstAddrInput *net.IPNet, nextHopAddr net.IP) linux.DeleteDSL {
	op := TxnOp{Key: l3.RouteKey(vrf, dstAddrInput, nextHopAddr.String())}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (dsl *MockDeleteDSL) ACL(aclName string) linux.DeleteDSL {
	op := TxnOp{Key: acl.Key(aclName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// LinuxInterface adds a mock request to delete an existing Linux network
// interface.
func (dsl *MockDeleteDSL) LinuxInterface(ifName string) linux.DeleteDSL {
	op := TxnOp{Key: linux_intf.InterfaceKey(ifName)}
	dsl.parent.Ops = append(dsl.parent.Ops, op)
	return dsl
}

// Put changes the DSL mode to allow configuration editing.
func (dsl *MockDeleteDSL) Put() linux.PutDSL {
	return &MockPutDSL{dsl.parent}
}

// Send commits the transaction into the mock DB.
func (dsl *MockDeleteDSL) Send() defaultplugins.Reply {
	return dsl.parent.Send()
}

// Reply interface allows to wait for a reply to previously called Send() and
// extract the result from it (success/error).
type Reply struct {
	err error
}

// ReceiveReply waits for a reply to previously called Send() and returns
// the result (error or nil).
func (dsl Reply) ReceiveReply() error {
	return dsl.err
}
