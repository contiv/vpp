package linux

import (
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/clientv1/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	linux_intf "github.com/ligato/vpp-agent/plugins/linux/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linux/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vpp/model/ipsec"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vpp/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vpp/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	vpp_nat "github.com/ligato/vpp-agent/plugins/vpp/model/nat"
	vpp_stn "github.com/ligato/vpp-agent/plugins/vpp/model/stn"
)

// MockDataResyncDSL is mock for DataResyncDSL.
type MockDataResyncDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataResyncDSL is a constructor for MockDataResyncDSL.
func NewMockDataResyncDSL(commitFunc dsl.CommitFunc) *MockDataResyncDSL {
	return &MockDataResyncDSL{CommonMockDSL: dsl.CommonMockDSL{CommitFunc: commitFunc}}
}

// LinuxInterface adds Linux interface to the mock RESYNC request.
func (d *MockDataResyncDSL) LinuxInterface(val *linux_intf.LinuxInterfaces_Interface) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: linux_intf.InterfaceKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

func (d *MockDataResyncDSL) LinuxArpEntry(val *linux_l3.LinuxStaticArpEntries_ArpEntry) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticArpKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

func (d *MockDataResyncDSL) LinuxRoute(val *linux_l3.LinuxStaticRoutes_Route) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticRouteKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// VppInterface adds VPP interface to the mock RESYNC request.
func (d *MockDataResyncDSL) VppInterface(val *vpp_intf.Interfaces_Interface) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_intf.InterfaceKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (d *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.SessionKey(val.Interface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (d *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (d *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *vpp_l2.BridgeDomains_BridgeDomain) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l2.BridgeDomainKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *vpp_l2.FibTable_FibEntry) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *vpp_l2.XConnectPairs_XConnectPair) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *vpp_l3.StaticRoutes_Route) linuxclient.DataResyncDSL {
	key := vpp_l3.RouteKey(val.VrfId, val.DstIpAddr, val.NextHopAddr)
	op := dsl.TxnOp{Key: key, Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.AccessLists_Acl) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: acl.Key(val.AclName), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// L4Features adds L4Features to the RESYNC request
func (d *MockDataResyncDSL) L4Features(val *vpp_l4.L4Features) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l4.FeatureKey(), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// AppNamespace adds Application Namespace to the RESYNC request
func (d *MockDataResyncDSL) AppNamespace(val *vpp_l4.AppNamespaces_AppNamespace) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Arp adds L3 ARP entry to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *vpp_l3.ArpTable_ArpEntry) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ProxyArpInterfaces adds L3 proxy ARP interfaces to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArpInterfaces(val *vpp_l3.ProxyArpInterfaces_InterfaceList) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpInterfaceKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// ProxyArpRanges adds L3 proxy ARP ranges to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArpRanges(val *vpp_l3.ProxyArpRanges_RangeList) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpRangeKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// StnRule adds Stn rule to the RESYNC request.
func (d *MockDataResyncDSL) StnRule(val *vpp_stn.STN_Rule) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_stn.Key(val.RuleName), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// NAT44Global adds a request to RESYNC global configuration for NAT44
func (d *MockDataResyncDSL) NAT44Global(val *vpp_nat.Nat44Global) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_nat.GlobalConfigKey(), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// NAT44DNat adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) NAT44DNat(val *vpp_nat.Nat44DNat_DNatConfig) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: vpp_nat.DNatKey(val.Label), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// IPSecSA adds request to create a new Security Association
func (d *MockDataResyncDSL) IPSecSA(val *ipsec.SecurityAssociations_SA) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: ipsec.SAKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// IPSecSPD adds request to create a new Security Policy Database
func (d *MockDataResyncDSL) IPSecSPD(val *ipsec.SecurityPolicyDatabases_SPD) linuxclient.DataResyncDSL {
	op := dsl.TxnOp{Key: ipsec.SPDKey(val.Name), Value: val}
	d.Ops = append(d.Ops, op)
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}
