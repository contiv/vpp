package vpp

import (
	"go.ligato.io/vpp-agent/v3/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"

	"go.ligato.io/vpp-agent/v3/pkg/models"

	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/abf"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/acl"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/nat"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/punt"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/stn"
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
func (d *MockDataResyncDSL) Interface(val *vpp_interfaces.Interface) vppclient.DataResyncDSL {
	key := vpp_interfaces.InterfaceKey(val.Name)
	d.Values[key] = val
	return d
}

// ABF adds a request to create or update VPP ACL-based forwarding.
func (d *MockDataResyncDSL) ABF(val *vpp_abf.ABF) vppclient.DataResyncDSL {
	key := vpp_abf.Key(val.Index)
	d.Values[key] = val
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *vpp_l2.BridgeDomain) vppclient.DataResyncDSL {
	key := vpp_l2.BridgeDomainKey(val.Name)
	d.Values[key] = val
	return d
}

// NAT44Interface adds NAT44 interface configuration to the RESYNC request.
func (d *MockDataResyncDSL) NAT44Interface(natIf *vpp_nat.Nat44Interface) vppclient.DataResyncDSL {
	key := vpp_nat.Nat44InterfaceKey(natIf.Name)
	d.Values[key] = natIf
	return d
}

// NAT44AddressPool adds NAT44 address pool configuration to the RESYNC request.
func (d *MockDataResyncDSL) NAT44AddressPool(pool *vpp_nat.Nat44AddressPool) vppclient.DataResyncDSL {
	key := vpp_nat.Nat44AddressPoolKey(pool.VrfId, pool.FirstIp, pool.LastIp)
	d.Values[key] = pool
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *vpp_l2.FIBEntry) vppclient.DataResyncDSL {
	key := vpp_l2.FIBKey(val.BridgeDomain, val.PhysAddress)
	d.Values[key] = val
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *vpp_l2.XConnectPair) vppclient.DataResyncDSL {
	key := vpp_l2.XConnectKey(val.ReceiveInterface)
	d.Values[key] = val
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *vpp_l3.Route) vppclient.DataResyncDSL {
	key := vpp_l3.RouteKey(val.OutgoingInterface, val.VrfId, val.DstNetwork, val.NextHopAddr)
	d.Values[key] = val
	return d
}

// Span adds VPP span to the RESYNC request.
func (d *MockDataResyncDSL) Span(val *vpp_interfaces.Span) vppclient.DataResyncDSL {
	key := vpp_interfaces.SpanKey(val.InterfaceFrom, val.InterfaceTo)
	d.Values[key] = val
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *vpp_acl.ACL) vppclient.DataResyncDSL {
	key := vpp_acl.Key(val.Name)
	d.Values[key] = val
	return d
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *vpp_l3.ARPEntry) vppclient.DataResyncDSL {
	key := vpp_l3.ArpEntryKey(val.Interface, val.IpAddress)
	d.Values[key] = val
	return d
}

// ProxyArp adds L3 proxy ARP to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArp(val *vpp_l3.ProxyARP) vppclient.DataResyncDSL {
	key := vpp_l3.ProxyARPKey()
	d.Values[key] = val
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockDataResyncDSL) IPScanNeighbor(val *vpp_l3.IPScanNeighbor) vppclient.DataResyncDSL {
	key := vpp_l3.IPScanNeighborKey()
	d.Values[key] = val
	return d
}

// StnRule adds Stn rule to the RESYNC request.
func (d *MockDataResyncDSL) StnRule(val *vpp_stn.Rule) vppclient.DataResyncDSL {
	key := vpp_stn.Key(val.Interface, val.IpAddress)
	d.Values[key] = val
	return d
}

// NAT44Global adds a request to RESYNC global configuration for NAT44
func (d *MockDataResyncDSL) NAT44Global(val *vpp_nat.Nat44Global) vppclient.DataResyncDSL {
	key := vpp_nat.GlobalNAT44Key()
	d.Values[key] = val
	return d
}

// DNAT44 adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) DNAT44(val *vpp_nat.DNat44) vppclient.DataResyncDSL {
	key := vpp_nat.DNAT44Key(val.Label)
	d.Values[key] = val
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDataResyncDSL) IPSecSA(val *vpp_ipsec.SecurityAssociation) vppclient.DataResyncDSL {
	key := vpp_ipsec.SAKey(val.Index)
	d.Values[key] = val
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDataResyncDSL) IPSecSPD(val *vpp_ipsec.SecurityPolicyDatabase) vppclient.DataResyncDSL {
	key := vpp_ipsec.SPDKey(val.Index)
	d.Values[key] = val
	return d
}

// IPSecTunnelProtection adds request to RESYNC an IPSec tunnel protection
func (d *MockDataResyncDSL) IPSecTunnelProtection(val *vpp_ipsec.TunnelProtection) vppclient.DataResyncDSL {
	key := models.Key(val)
	d.Values[key] = val
	return d
}

// PuntIPRedirect adds request to RESYNC a rule used to punt L3 traffic via interface.
func (d *MockDataResyncDSL) PuntIPRedirect(val *vpp_punt.IPRedirect) vppclient.DataResyncDSL {
	key := vpp_punt.IPRedirectKey(val.L3Protocol, val.TxInterface)
	d.Values[key] = val
	return d
}

// PuntToHost adds request to RESYNC a rule used to punt L4 traffic to a host.
func (d *MockDataResyncDSL) PuntToHost(val *vpp_punt.ToHost) vppclient.DataResyncDSL {
	key := vpp_punt.ToHostKey(val.L3Protocol, val.L4Protocol, val.Port)
	d.Values[key] = val
	return d
}

// PuntException adds request to RESYNC a rule used to add punt exception in punting traffic to a host.
func (d *MockDataResyncDSL) PuntException(val *vpp_punt.Exception) vppclient.DataResyncDSL {
	key := vpp_punt.ExceptionKey(val.Reason)
	d.Values[key] = val
	return d
}

// VrfTable adds VRF table to the RESYNC request.
func (d *MockDataResyncDSL) VrfTable(val *vpp_l3.VrfTable) vppclient.DataResyncDSL {
	key := vpp_l3.VrfTableKey(val.Id, val.Protocol)
	d.Values[key] = val
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Values)
	return &dsl.Reply{Err: err}
}
