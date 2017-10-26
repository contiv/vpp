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

// MockDataResyncDSL is mock for DataResyncDSL.
type MockDataResyncDSL struct {
	// List of transaction operations in the order as they were called.
	Ops []TxnOp

	txnTracker *TxnTracker
	txn        *Txn
}

// newMockDataResyncDSL is a constructor for MockDataResyncDSL.
func newMockDataResyncDSL(tracker *TxnTracker, transaction *Txn) *MockDataResyncDSL {
	return &MockDataResyncDSL{txnTracker: tracker, txn: transaction}
}

// apply reflects the effect of transaction operations into the mock DB.
func (dsl *MockDataResyncDSL) apply() {
	dsl.txnTracker.AppliedConfig = nil /* clear the previous configuration */
	for _, op := range dsl.Ops {
		dsl.txnTracker.AppliedConfig[op.Key] = op.Value
	}
}

// LinuxInterface adds Linux interface to the mock RESYNC request.
func (dsl *MockDataResyncDSL) LinuxInterface(val *linux_intf.LinuxInterfaces_Interface) linux.DataResyncDSL {
	op := TxnOp{Key: linux_intf.InterfaceKey(val.Name), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// VppInterface adds VPP interface to the mock RESYNC request.
func (dsl *MockDataResyncDSL) VppInterface(val *vpp_intf.Interfaces_Interface) linux.DataResyncDSL {
	op := TxnOp{Key: vpp_intf.InterfaceKey(val.Name), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (dsl *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) linux.DataResyncDSL {
	op := TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (dsl *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linux.DataResyncDSL {
	op := TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (dsl *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linux.DataResyncDSL {
	op := TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (dsl *MockDataResyncDSL) BD(val *l2.BridgeDomains_BridgeDomain) linux.DataResyncDSL {
	op := TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (dsl *MockDataResyncDSL) BDFIB(val *l2.FibTableEntries_FibTableEntry) linux.DataResyncDSL {
	op := TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (dsl *MockDataResyncDSL) XConnect(val *l2.XConnectPairs_XConnectPair) linux.DataResyncDSL {
	op := TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (dsl *MockDataResyncDSL) StaticRoute(val *l3.StaticRoutes_Route) linux.DataResyncDSL {
	_, dstAddr, _ := net.ParseCIDR(val.DstIpAddr)
	key := l3.RouteKey(val.VrfId, dstAddr, val.NextHopAddr)
	op := TxnOp{Key: key, Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (dsl *MockDataResyncDSL) ACL(val *acl.AccessLists_Acl) linux.DataResyncDSL {
	op := TxnOp{Key: acl.Key(val.AclName), Value: val}
	dsl.Ops = append(dsl.Ops, op)
	return dsl
}

// Send commits the transaction into the mock DB.
func (dsl *MockDataResyncDSL) Send() defaultplugins.Reply {
	dsl.txnTracker.commit(dsl.txn)
	return &Reply{nil}
}
