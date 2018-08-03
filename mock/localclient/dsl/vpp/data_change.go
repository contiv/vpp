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
func (d *MockDataChangeDSL) Put() vppclient.PutDSL {
	return &MockPutDSL{d}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (d *MockDataChangeDSL) Delete() vppclient.DeleteDSL {
	return &MockDeleteDSL{d}
}

// Send commits the transaction into the mock DB.
func (d *MockDataChangeDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}

// Interface adds interface to the RESYNC request.
func (d *MockPutDSL) Interface(val *interfaces.Interfaces_Interface) vppclient.PutDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to create or update bidirectional forwarding
// detection session.
func (d *MockPutDSL) BfdSession(val *bfd.SingleHopBFD_Session) vppclient.PutDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to create or update bidirectional forwarding
// detection key.
func (d *MockPutDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) vppclient.PutDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to create or update bidirectional
// forwarding detection echo function.
func (d *MockPutDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) vppclient.PutDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (d *MockPutDSL) BD(val *l2.BridgeDomains_BridgeDomain) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (d *MockPutDSL) BDFIB(val *l2.FibTable_FibEntry) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (d *MockPutDSL) XConnect(val *l2.XConnectPairs_XConnectPair) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (d *MockPutDSL) StaticRoute(val *l3.StaticRoutes_Route) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l3.RouteKey(val.VrfId, val.DstIpAddr, val.NextHopAddr), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to create or update VPP Access Control List.
func (d *MockPutDSL) ACL(val *acl.AccessLists_Acl) vppclient.PutDSL {
	op := dsl.TxnOp{Key: acl.Key(val.AclName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to create or update VPP L3 ARP.
func (d *MockPutDSL) Arp(val *l3.ArpTable_ArpEntry) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpInterfaces adds a request to create or update VPP L3 proxy ARP interfaces
func (d *MockPutDSL) ProxyArpInterfaces(val *l3.ProxyArpInterfaces_InterfaceList) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpInterfaceKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpRanges adds a request to create or update VPP L3 proxy ARP ranges
func (d *MockPutDSL) ProxyArpRanges(val *l3.ProxyArpRanges_RangeList) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpRangeKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockPutDSL) L4Features(val *l4.L4Features) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey(), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to create or update VPP Application namespace
func (d *MockPutDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) vppclient.PutDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds a request to create or update Stn rule to the RESYNC request.
func (d *MockPutDSL) StnRule(val *stn.STN_Rule) vppclient.PutDSL {
	op := dsl.TxnOp{Key: stn.Key(val.RuleName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44Global adds a request to set global configuration for NAT44
func (d *MockPutDSL) NAT44Global(val *nat.Nat44Global) vppclient.PutDSL {
	op := dsl.TxnOp{Key: nat.GlobalPrefix, Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44DNat adds a request to create a new DNAT configuration
func (d *MockPutDSL) NAT44DNat(val *nat.Nat44DNat_DNatConfig) vppclient.PutDSL {
	op := dsl.TxnOp{Key: nat.DNatKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockPutDSL) IPSecSA(val *ipsec.SecurityAssociations_SA) vppclient.PutDSL {
	op := dsl.TxnOp{Key: ipsec.SAKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockPutDSL) IPSecSPD(val *ipsec.SecurityPolicyDatabases_SPD) vppclient.PutDSL {
	op := dsl.TxnOp{Key: ipsec.SPDKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (d *MockPutDSL) Delete() vppclient.DeleteDSL {
	return &MockDeleteDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockPutDSL) Send() vppclient.Reply {
	return d.parent.Send()
}

// Interface adds a request to delete an existing VPP network interface.
func (d *MockDeleteDSL) Interface(ifaceName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: interfaces.InterfaceKey(ifaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to delete an existing bidirectional forwarding
// detection session.
func (d *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(bfdSessionIfaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to delete an existing bidirectional forwarding
// detection key.
func (d *MockDeleteDSL) BfdAuthKeys(bfdKey string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(bfdKey)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to delete an existing bidirectional
// forwarding detection echo function.
func (d *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(bfdEchoName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (d *MockDeleteDSL) BD(bdName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l2.BridgeDomainKey(bdName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (d *MockDeleteDSL) BDFIB(bdName string, mac string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l2.FibKey(bdName, mac)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (d *MockDeleteDSL) XConnect(rxIfName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l2.XConnectKey(rxIfName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (d *MockDeleteDSL) StaticRoute(vrf uint32, dstAddr string, nextHopAddr string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l3.RouteKey(vrf, dstAddr, nextHopAddr)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (d *MockDeleteDSL) ACL(aclName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: acl.Key(aclName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockDeleteDSL) L4Features() vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l4.FeatureKey()}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to delete VPP Application namespace
// Note: current version does not support application namespace deletion
func (d *MockDeleteDSL) AppNamespace(id string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l4.AppNamespacesKey(id)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to delete an existing VPP L3 ARP.
func (d *MockDeleteDSL) Arp(ifaceName string, ipAddr string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l3.ArpEntryKey(ifaceName, ipAddr)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpInterfaces adds a request to delete an existing VPP L3 proxy ARP interfaces
func (d *MockDeleteDSL) ProxyArpInterfaces(label string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpInterfaceKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpRanges adds a request to delete an existing VPP L3 proxy ARP ranges
func (d *MockDeleteDSL) ProxyArpRanges(label string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: l3.ProxyArpRangeKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds a request to delete an existing Stn rule to the RESYNC request.
func (d *MockDeleteDSL) StnRule(ruleName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: stn.Key(ruleName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44Global adds a request to remove global configuration for NAT44
func (d *MockDeleteDSL) NAT44Global() vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: nat.GlobalPrefix}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44DNat adds a request to delete a DNAT configuration identified by label
func (d *MockDeleteDSL) NAT44DNat(label string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: nat.DNatKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDeleteDSL) IPSecSA(saName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: ipsec.SAKey(saName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDeleteDSL) IPSecSPD(spdName string) vppclient.DeleteDSL {
	op := dsl.TxnOp{Key: ipsec.SPDKey(spdName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Put changes the DSL mode to allow configuration editing.
func (d *MockDeleteDSL) Put() vppclient.PutDSL {
	return &MockPutDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockDeleteDSL) Send() vppclient.Reply {
	return d.parent.Send()
}
