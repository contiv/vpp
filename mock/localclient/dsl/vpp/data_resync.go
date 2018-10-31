package vpp

import (
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vpp/model/ipsec"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/nat"
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
func (d *MockDataResyncDSL) Interface(val *interfaces.Interface) vppclient.DataResyncDSL {
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
func (d *MockDataResyncDSL) BD(val *l2.BridgeDomain) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *l2.FIBEntry) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.FIBKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *l2.XConnectPair) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *l3.StaticRoute) vppclient.DataResyncDSL {
	key := l3.RouteKey(val.VrfId, val.DstNetwork, val.NextHopAddr)
	op := dsl.TxnOp{Key: key, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.Acl) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: acl.Key(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *l3.ARPEntry) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ProxyArp adds L3 proxy ARP to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArp(val *l3.ProxyARP) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.ProxyARPKey, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockDataResyncDSL) IPScanNeighbor(val *l3.IPScanNeighbor) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: l3.IPScanNeighborKey, Value: val}
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
	op := dsl.TxnOp{Key: nat.GlobalNAT44Key, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// DNAT44 adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) DNAT44(val *nat.DNat44) vppclient.DataResyncDSL {
	op := dsl.TxnOp{Key: nat.DNAT44Key(val.Label), Value: val}
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
