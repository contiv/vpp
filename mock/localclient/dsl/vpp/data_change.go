package vpp

import (
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	"github.com/ligato/vpp-agent/api/models/vpp/acl"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/ipsec"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/nat"
	"github.com/ligato/vpp-agent/api/models/vpp/punt"
	"github.com/ligato/vpp-agent/api/models/vpp/stn"
)

// MockDataChangeDSL is mock for DataChangeDSL.
type MockDataChangeDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataChangeDSL is a constructor for MockDataChangeDSL.
func NewMockDataChangeDSL(commitFunc dsl.CommitFunc) *MockDataChangeDSL {
	return &MockDataChangeDSL{CommonMockDSL: dsl.NewCommonMockDSL(commitFunc)}
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
	err := d.CommitFunc(d.Values)
	return &dsl.Reply{Err: err}
}

// Interface adds interface to the RESYNC request.
func (d *MockPutDSL) Interface(val *vpp_interfaces.Interface) vppclient.PutDSL {
	key := vpp_interfaces.InterfaceKey(val.Name)
	d.parent.Values[key] = val
	return d
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (d *MockPutDSL) BD(val *vpp_l2.BridgeDomain) vppclient.PutDSL {
	key := vpp_l2.BridgeDomainKey(val.Name)
	d.parent.Values[key] = val
	return d
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (d *MockPutDSL) BDFIB(val *vpp_l2.FIBEntry) vppclient.PutDSL {
	key := vpp_l2.FIBKey(val.BridgeDomain, val.PhysAddress)
	d.parent.Values[key] = val
	return d
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (d *MockPutDSL) XConnect(val *vpp_l2.XConnectPair) vppclient.PutDSL {
	key := vpp_l2.XConnectKey(val.ReceiveInterface)
	d.parent.Values[key] = val
	return d
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (d *MockPutDSL) StaticRoute(val *vpp_l3.Route) vppclient.PutDSL {
	key := vpp_l3.RouteKey(val.VrfId, val.DstNetwork, val.NextHopAddr)
	d.parent.Values[key] = val
	return d
}

// ACL adds a mock request to create or update VPP Access Control List.
func (d *MockPutDSL) ACL(val *vpp_acl.ACL) vppclient.PutDSL {
	key := vpp_acl.Key(val.Name)
	d.parent.Values[key] = val
	return d
}

// Arp adds a request to create or update VPP L3 ARP.
func (d *MockPutDSL) Arp(val *vpp_l3.ARPEntry) vppclient.PutDSL {
	key := vpp_l3.ArpEntryKey(val.Interface, val.IpAddress)
	d.parent.Values[key] = val
	return d
}

// ProxyArp adds a request to create or update VPP L3 proxy ARP.
func (d *MockPutDSL) ProxyArp(val *vpp_l3.ProxyARP) vppclient.PutDSL {
	key := vpp_l3.ProxyARPKey()
	d.parent.Values[key] = val
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockPutDSL) IPScanNeighbor(val *vpp_l3.IPScanNeighbor) vppclient.PutDSL {
	key := vpp_l3.IPScanNeighborKey()
	d.parent.Values[key] = val
	return d
}

// StnRule adds a request to create or update Stn rule to the RESYNC request.
func (d *MockPutDSL) StnRule(val *vpp_stn.Rule) vppclient.PutDSL {
	key := vpp_stn.Key(val.Interface, val.IpAddress)
	d.parent.Values[key] = val
	return d
}

// NAT44Global adds a request to set global configuration for NAT44
func (d *MockPutDSL) NAT44Global(val *vpp_nat.Nat44Global) vppclient.PutDSL {
	key := vpp_nat.GlobalNAT44Key()
	d.parent.Values[key] = val
	return d
}

// DNAT44 adds a request to create a new DNAT configuration
func (d *MockPutDSL) DNAT44(val *vpp_nat.DNat44) vppclient.PutDSL {
	key := vpp_nat.DNAT44Key(val.Label)
	d.parent.Values[key] = val
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockPutDSL) IPSecSA(val *vpp_ipsec.SecurityAssociation) vppclient.PutDSL {
	key := vpp_ipsec.SAKey(val.Index)
	d.parent.Values[key] = val
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockPutDSL) IPSecSPD(val *vpp_ipsec.SecurityPolicyDatabase) vppclient.PutDSL {
	key := vpp_ipsec.SPDKey(val.Index)
	d.parent.Values[key] = val
	return d
}

// PuntIPRedirect adds request to create or update rule to punt L3 traffic via interface.
func (d *MockPutDSL) PuntIPRedirect(val *vpp_punt.IPRedirect) vppclient.PutDSL {
	key := vpp_punt.IPRedirectKey(val.L3Protocol, val.TxInterface)
	d.parent.Values[key] = val
	return d
}

// PuntToHost adds request to create or update rule to punt L4 traffic to a host.
func (d *MockPutDSL) PuntToHost(val *vpp_punt.ToHost) vppclient.PutDSL {
	key := vpp_punt.ToHostKey(val.L3Protocol, val.L4Protocol, val.Port)
	d.parent.Values[key] = val
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
	key := vpp_interfaces.InterfaceKey(ifaceName)
	d.parent.Values[key] = nil
	return d
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (d *MockDeleteDSL) BD(bdName string) vppclient.DeleteDSL {
	key := vpp_l2.BridgeDomainKey(bdName)
	d.parent.Values[key] = nil
	return d
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (d *MockDeleteDSL) BDFIB(bdName string, mac string) vppclient.DeleteDSL {
	key := vpp_l2.FIBKey(bdName, mac)
	d.parent.Values[key] = nil
	return d
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (d *MockDeleteDSL) XConnect(rxIfName string) vppclient.DeleteDSL {
	key := vpp_l2.XConnectKey(rxIfName)
	d.parent.Values[key] = nil
	return d
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (d *MockDeleteDSL) StaticRoute(vrf uint32, dstAddr string, nextHopAddr string) vppclient.DeleteDSL {
	key := vpp_l3.RouteKey(vrf, dstAddr, nextHopAddr)
	d.parent.Values[key] = nil
	return d
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (d *MockDeleteDSL) ACL(aclName string) vppclient.DeleteDSL {
	key := vpp_acl.Key(aclName)
	d.parent.Values[key] = nil
	return d
}

// Arp adds a request to delete an existing VPP L3 ARP.
func (d *MockDeleteDSL) Arp(ifaceName string, ipAddr string) vppclient.DeleteDSL {
	key := vpp_l3.ArpEntryKey(ifaceName, ipAddr)
	d.parent.Values[key] = nil
	return d
}

// ProxyArp adds a request to delete an existing VPP L3 proxy ARP.
func (d *MockDeleteDSL) ProxyArp() vppclient.DeleteDSL {
	key := vpp_l3.ProxyARPKey()
	d.parent.Values[key] = nil
	return d
}

// IPScanNeighbor adds a request to delete an existing VPP L3 IP Scan Neighbor.
func (d *MockDeleteDSL) IPScanNeighbor() vppclient.DeleteDSL {
	key := vpp_l3.IPScanNeighborKey()
	d.parent.Values[key] = nil
	return d
}

// StnRule adds a request to delete an existing Stn rule to the RESYNC request.
func (d *MockDeleteDSL) StnRule(ifName, ipAddr string) vppclient.DeleteDSL {
	key := vpp_stn.Key(ifName, ipAddr)
	d.parent.Values[key] = nil
	return d
}

// NAT44Global adds a request to remove global configuration for NAT44
func (d *MockDeleteDSL) NAT44Global() vppclient.DeleteDSL {
	key := vpp_nat.GlobalNAT44Key()
	d.parent.Values[key] = nil
	return d
}

// DNAT44 adds a request to delete a DNAT configuration identified by label
func (d *MockDeleteDSL) DNAT44(label string) vppclient.DeleteDSL {
	key := vpp_nat.DNAT44Key(label)
	d.parent.Values[key] = nil
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDeleteDSL) IPSecSA(saIndex string) vppclient.DeleteDSL {
	key := vpp_ipsec.SAKey(saIndex)
	d.parent.Values[key] = nil
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDeleteDSL) IPSecSPD(spdIndex string) vppclient.DeleteDSL {
	key := vpp_ipsec.SPDKey(spdIndex)
	d.parent.Values[key] = nil
	return d
}

// PuntIPRedirect adds request to delete a rule used to punt L3 traffic via interface.
func (d *MockDeleteDSL) PuntIPRedirect(l3Proto vpp_punt.L3Protocol, txInterface string) vppclient.DeleteDSL {
	key := vpp_punt.IPRedirectKey(l3Proto, txInterface)
	d.parent.Values[key] = nil
	return d
}

// PuntToHost adds request to delete a rule used to punt L4 traffic to a host.
func (d *MockDeleteDSL) PuntToHost(l3Proto vpp_punt.L3Protocol, l4Proto vpp_punt.L4Protocol, port uint32) vppclient.DeleteDSL {
	key := vpp_punt.ToHostKey(l3Proto, l4Proto, port)
	d.parent.Values[key] = nil
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
