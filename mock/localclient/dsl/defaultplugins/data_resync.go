package defaultplugins

import (
	"net"

	"github.com/ligato/vpp-agent/clientv1/defaultplugins"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/bfd"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
)

// MockDataResyncDSL is mock for DataResyncDSL.
type MockDataResyncDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataResyncDSL is a constructor for MockDataResyncDSL.
func NewMockDataResyncDSL(commitFunc dsl.CommitFunc) *MockDataResyncDSL {
	return &MockDataResyncDSL{CommonMockDSL: dsl.CommonMockDSL{CommitFunc: commitFunc}}
}

// Interface adds interface to the RESYNC request.
func (d *MockDataResyncDSL) Interface(val *interfaces.Interfaces_Interface) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (d *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (d *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (d *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *l2.BridgeDomains_BridgeDomain) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *l2.FibTableEntries_FibTableEntry) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *l2.XConnectPairs_XConnectPair) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *l3.StaticRoutes_Route) defaultplugins.DataResyncDSL {
	_, dstAddr, _ := net.ParseCIDR(val.DstIpAddr)
	key := l3.RouteKey(val.VrfId, dstAddr, val.NextHopAddr)
	op := dsl.TxnOp{Key: key, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.AccessLists_Acl) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: acl.Key(val.AclName), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *l3.ArpTable_ArpTableEntry) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// L4Features adds L4 features to the RESYNC request
func (d *MockDataResyncDSL) L4Features(val *l4.L4Features) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey(), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// AppNamespace adds VPP Application namespaces to the RESYNC request
func (d *MockDataResyncDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) defaultplugins.DataResyncDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() defaultplugins.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}
