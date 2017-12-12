package defaultplugins

import (
	"net"

	"github.com/ligato/vpp-agent/clientv1/defaultplugins"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/bfd"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/stn"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
)

// MockDataChangeDSL is mock for DataChangeDSL.
type MockDataChangeDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataChangeDSL is a constructor for MockDataChangeDSL.
func NewMockDataChangeDSL(commitFunc dsl.CommitFunc) *MockDataChangeDSL {
	return &MockDataChangeDSL{CommonMockDSL: dsl.CommonMockDSL{CommitFunc: commitFunc}}
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
func (d *MockDataChangeDSL) Put() defaultplugins.PutDSL {
	return &MockPutDSL{d}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (d *MockDataChangeDSL) Delete() defaultplugins.DeleteDSL {
	return &MockDeleteDSL{d}
}

// Send commits the transaction into the mock DB.
func (d *MockDataChangeDSL) Send() defaultplugins.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}

// Interface adds interface to the RESYNC request.
func (d *MockPutDSL) Interface(val *interfaces.Interfaces_Interface) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to create or update bidirectional forwarding
// detection session.
func (d *MockPutDSL) BfdSession(val *bfd.SingleHopBFD_Session) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to create or update bidirectional forwarding
// detection key.
func (d *MockPutDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to create or update bidirectional
// forwarding detection echo function.
func (d *MockPutDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (d *MockPutDSL) BD(val *l2.BridgeDomains_BridgeDomain) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (d *MockPutDSL) BDFIB(val *l2.FibTableEntries_FibTableEntry) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (d *MockPutDSL) XConnect(val *l2.XConnectPairs_XConnectPair) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (d *MockPutDSL) StaticRoute(val *l3.StaticRoutes_Route) defaultplugins.PutDSL {
	_, dstAddr, _ := net.ParseCIDR(val.DstIpAddr)
	op := dsl.TxnOp{Key: l3.RouteKey(val.VrfId, dstAddr, val.NextHopAddr), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to create or update VPP Access Control List.
func (d *MockPutDSL) ACL(val *acl.AccessLists_Acl) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: acl.Key(val.AclName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to create or update VPP L3 ARP.
func (d *MockPutDSL) Arp(val *l3.ArpTable_ArpTableEntry) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockPutDSL) L4Features(val *l4.L4Features) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey(), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to create or update VPP Application namespace
func (d *MockPutDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds a request to create or update Stn rule to the RESYNC request.
func (d *MockPutDSL) StnRule(val *stn.StnRule) defaultplugins.PutDSL {
	op := dsl.TxnOp{Key: stn.Key(val.RuleName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (d *MockPutDSL) Delete() defaultplugins.DeleteDSL {
	return &MockDeleteDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockPutDSL) Send() defaultplugins.Reply {
	return d.parent.Send()
}

// Interface adds a request to delete an existing VPP network interface.
func (d *MockDeleteDSL) Interface(ifaceName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(ifaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to delete an existing bidirectional forwarding
// detection session.
func (d *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(bfdSessionIfaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to delete an existing bidirectional forwarding
// detection key.
func (d *MockDeleteDSL) BfdAuthKeys(bfdKey uint32) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(bfdKey))}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to delete an existing bidirectional
// forwarding detection echo function.
func (d *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(bfdEchoName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (d *MockDeleteDSL) BD(bdName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(bdName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (d *MockDeleteDSL) BDFIB(bdName string, mac string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l2.FibKey(bdName, mac)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (d *MockDeleteDSL) XConnect(rxIfName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(rxIfName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (d *MockDeleteDSL) StaticRoute(vrf uint32, dstAddrInput *net.IPNet, nextHopAddr net.IP) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l3.RouteKey(vrf, dstAddrInput, nextHopAddr.String())}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (d *MockDeleteDSL) ACL(aclName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: acl.Key(aclName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockDeleteDSL) L4Features() defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey()}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to delete VPP Application namespace
// Note: current version does not support application namespace deletion
func (d *MockDeleteDSL) AppNamespace(id string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(id)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to delete an existing VPP L3 ARP.
func (d *MockDeleteDSL) Arp(ifaceName string, ipAddr net.IP) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(ifaceName, ipAddr.String())}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds a request to delete an existing Stn rule to the RESYNC request.
func (d *MockDeleteDSL) StnRule(ruleName string) defaultplugins.DeleteDSL {
	op := dsl.TxnOp{Key: stn.Key(ruleName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Put changes the DSL mode to allow configuration editing.
func (d *MockDeleteDSL) Put() defaultplugins.PutDSL {
	return &MockPutDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockDeleteDSL) Send() defaultplugins.Reply {
	return d.parent.Send()
}
