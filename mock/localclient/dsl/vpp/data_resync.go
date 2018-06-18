package vpp

import (
	"github.com/ligato/vpp-agent/clientv1/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vpp/model/ipsec"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l2"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	"github.com/ligato/vpp-agent/plugins/vpp/model/nat"
	"github.com/ligato/vpp-agent/plugins/vpp/model/stn"
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
func (d *MockDataResyncDSL) Interface(val *interfaces.Interfaces_Interface) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (d *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (d *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (d *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *l2.BridgeDomains_BridgeDomain) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *l2.FibTable_FibEntry) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *l2.XConnectPairs_XConnectPair) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *l3.StaticRoutes_Route) vppclient.DataResyncDSL {
	key := l3.RouteKey(val.VrfId, val.DstIpAddr, val.NextHopAddr)
	op := dsl.TxnOp{Key: key, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.AccessLists_Acl) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: acl.Key(val.AclName), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *l3.ArpTable_ArpEntry) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ProxyArpInterfaces adds L3 proxy ARP interfaces to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArpInterfaces(val *l3.ProxyArpInterfaces_InterfaceList) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpInterfaceKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ProxyArpRanges adds L3 proxy ARP ranges to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArpRanges(val *l3.ProxyArpRanges_RangeList) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpRangeKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// L4Features adds L4 features to the RESYNC request
func (d *MockDataResyncDSL) L4Features(val *l4.L4Features) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey(), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// AppNamespace adds VPP Application namespaces to the RESYNC request
func (d *MockDataResyncDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StnRule adds Stn rule to the RESYNC request.
func (d *MockDataResyncDSL) StnRule(val *stn.STN_Rule) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: stn.Key(val.RuleName), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// NAT44Global adds a request to RESYNC global configuration for NAT44
func (d *MockDataResyncDSL) NAT44Global(val *nat.Nat44Global) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: nat.GlobalConfigKey(), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// NAT44DNat adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) NAT44DNat(val *nat.Nat44DNat_DNatConfig) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: nat.DNatKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDataResyncDSL) IPSecSA(val *ipsec.SecurityAssociations_SA) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: ipsec.SAKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDataResyncDSL) IPSecSPD(val *ipsec.SecurityPolicyDatabases_SPD) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: ipsec.SPDKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}
