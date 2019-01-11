package vpp

import (
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	"github.com/ligato/vpp-agent/plugins/vpp/model/stn"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/acl"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/ipsec"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/nat"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/punt"
)

// MockDataResyncDSL is mock for DataResyncDSL.
type MockDataResyncDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataResyncDSL is a constructor for MockDataResyncDSL.
func NewMockDataResyncDSL(commitFunc dsl.CommitFunc) *MockDataResyncDSL {
	return &MockDataResyncDSL{CommonMockDSL: dsl.NewCommonMockDSL(commitFunc)}
}

// Interface adds interface to the RESYNC request.
func (d *MockDataResyncDSL) Interface(val *interfaces.Interface) vppclient.DataResyncDSL {
	key := interfaces.InterfaceKey(val.Name)
	d.Values[key] = val
	return d
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (d *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) vppclient.DataResyncDSL {
	key := bfd.SessionKey(val.Interface)
	d.Values[key] = val
	return d
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (d *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) vppclient.DataResyncDSL {
	key := bfd.AuthKeysKey(string(val.Id))
	d.Values[key] = val
	return d
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (d *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) vppclient.DataResyncDSL {
	key := bfd.EchoFunctionKey(val.EchoSourceInterface)
	d.Values[key] = val
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *l2.BridgeDomain) vppclient.DataResyncDSL {
	key := l2.BridgeDomainKey(val.Name)
	d.Values[key] = val
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *l2.FIBEntry) vppclient.DataResyncDSL {
	key := l2.FIBKey(val.BridgeDomain, val.PhysAddress)
	d.Values[key] = val
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *l2.XConnectPair) vppclient.DataResyncDSL {
	key := l2.XConnectKey(val.ReceiveInterface)
	d.Values[key] = val
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *l3.StaticRoute) vppclient.DataResyncDSL {
	key := l3.RouteKey(val.VrfId, val.DstNetwork, val.NextHopAddr)
	d.Values[key] = val
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.Acl) vppclient.DataResyncDSL {
	key := acl.Key(val.Name)
	d.Values[key] = val
	return d
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *l3.ARPEntry) vppclient.DataResyncDSL {
	key := l3.ArpEntryKey(val.Interface, val.IpAddress)
	d.Values[key] = val
	return d
}

// ProxyArp adds L3 proxy ARP to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArp(val *l3.ProxyARP) vppclient.DataResyncDSL {
	key := l3.ProxyARPKey
	d.Values[key] = val
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockDataResyncDSL) IPScanNeighbor(val *l3.IPScanNeighbor) vppclient.DataResyncDSL {
	key := l3.IPScanNeighborKey
	d.Values[key] = val
	return d
}

// L4Features adds L4 features to the RESYNC request
func (d *MockDataResyncDSL) L4Features(val *l4.L4Features) vppclient.DataResyncDSL {
	key := l4.FeatureKey()
	d.Values[key] = val
	return d
}

// AppNamespace adds VPP Application namespaces to the RESYNC request
func (d *MockDataResyncDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) vppclient.DataResyncDSL {
	key := l4.AppNamespacesKey(val.NamespaceId)
	d.Values[key] = val
	return d
}

// StnRule adds Stn rule to the RESYNC request.
func (d *MockDataResyncDSL) StnRule(val *stn.STN_Rule) vppclient.DataResyncDSL {
	key := stn.Key(val.RuleName)
	d.Values[key] = val
	return d
}

// NAT44Global adds a request to RESYNC global configuration for NAT44
func (d *MockDataResyncDSL) NAT44Global(val *nat.Nat44Global) vppclient.DataResyncDSL {
	key := nat.GlobalNAT44Key
	d.Values[key] = val
	return d
}

// DNAT44 adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) DNAT44(val *nat.DNat44) vppclient.DataResyncDSL {
	key := nat.DNAT44Key(val.Label)
	d.Values[key] = val
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDataResyncDSL) IPSecSA(val *ipsec.SecurityAssociation) vppclient.DataResyncDSL {
	key := ipsec.SAKey(val.Index)
	d.Values[key] = val
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDataResyncDSL) IPSecSPD(val *ipsec.SecurityPolicyDatabase) vppclient.DataResyncDSL {
	key := ipsec.SPDKey(val.Index)
	d.Values[key] = val
	return d
}

// PuntIPRedirect adds request to RESYNC a rule used to punt L3 traffic via interface.
func (d *MockDataResyncDSL) PuntIPRedirect(val *punt.IpRedirect) vppclient.DataResyncDSL {
	key := punt.IPRedirectKey(val.L3Protocol, val.TxInterface)
	d.Values[key] = val
	return d
}

// PuntToHost adds request to RESYNC a rule used to punt L4 traffic to a host.
func (d *MockDataResyncDSL) PuntToHost(val *punt.ToHost) vppclient.DataResyncDSL {
	key := punt.ToHostKey(val.L3Protocol, val.L4Protocol, val.Port)
	d.Values[key] = val
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Values)
	return &dsl.Reply{Err: err}
}
