package linuxplugin

import (
	"github.com/ligato/vpp-agent/clientv1/defaultplugins"
	"github.com/ligato/vpp-agent/clientv1/linux"

	"github.com/contiv/vpp/mock/localclient/dsl"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"
	vpp_bfd "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/bfd"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l4"
	vpp_nat "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"
	vpp_stn "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/stn"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/l3"
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
func (d *MockDataChangeDSL) Put() linux.PutDSL {
	return &MockPutDSL{d}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (d *MockDataChangeDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{d}
}

// Send commits the transaction into the mock DB.
func (d *MockDataChangeDSL) Send() defaultplugins.Reply {
	err := d.CommitFunc(d.Ops)
	return &dsl.Reply{Err: err}
}

// Interface adds a mock request to create or update VPP network interface.
func (d *MockPutDSL) VppInterface(val *vpp_intf.Interfaces_Interface) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_intf.InterfaceKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to create or update bidirectional forwarding
// detection session.
func (d *MockPutDSL) BfdSession(val *vpp_bfd.SingleHopBFD_Session) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_bfd.SessionKey(val.Interface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to create or update bidirectional forwarding
// detection key.
func (d *MockPutDSL) BfdAuthKeys(val *vpp_bfd.SingleHopBFD_Key) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_bfd.AuthKeysKey(string(val.Id)), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to create or update bidirectional
// forwarding detection echo function.
func (d *MockPutDSL) BfdEchoFunction(val *vpp_bfd.SingleHopBFD_EchoFunction) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_bfd.EchoFunctionKey(val.EchoSourceInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (d *MockPutDSL) BD(val *vpp_l2.BridgeDomains_BridgeDomain) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l2.BridgeDomainKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (d *MockPutDSL) BDFIB(val *vpp_l2.FibTable_FibEntry) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l2.FibKey(val.BridgeDomain, val.PhysAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (d *MockPutDSL) XConnect(val *vpp_l2.XConnectPairs_XConnectPair) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l2.XConnectKey(val.ReceiveInterface), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (d *MockPutDSL) StaticRoute(val *vpp_l3.StaticRoutes_Route) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l3.RouteKey(val.VrfId, val.DstIpAddr, val.NextHopAddr), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to create or update VPP Access Control List.
func (d *MockPutDSL) ACL(val *vpp_acl.AccessLists_Acl) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_acl.Key(val.AclName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to create or update VPP L3 ARP.
func (d *MockPutDSL) Arp(val *vpp_l3.ArpTable_ArpEntry) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l3.ArpEntryKey(val.Interface, val.IpAddress), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockPutDSL) L4Features(val *vpp_l4.L4Features) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l4.FeatureKey(), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpInterfaces adds a request to create or update VPP L3 proxy ARP interfaces
func (d *MockPutDSL) ProxyArpInterfaces(val *vpp_l3.ProxyArpInterfaces_InterfaceList) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpInterfaceKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpRanges adds a request to create or update VPP L3 proxy ARP ranges
func (d *MockPutDSL) ProxyArpRanges(val *vpp_l3.ProxyArpRanges_RangeList) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpRangeKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to create or update VPP Application namespace
func (d *MockPutDSL) AppNamespace(val *vpp_l4.AppNamespaces_AppNamespace) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_l4.AppNamespacesKey(val.NamespaceId), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds a request to create or update VPP Stn rule.
func (d *MockPutDSL) StnRule(val *vpp_stn.STN_Rule) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_stn.Key(val.RuleName), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44Global adds a request to set global configuration for NAT44
func (d *MockPutDSL) NAT44Global(val *vpp_nat.Nat44Global) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_nat.GlobalConfigKey(), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44DNat adds a request to create a new DNAT configuration
func (d *MockPutDSL) NAT44DNat(val *vpp_nat.Nat44DNat_DNatConfig) linux.PutDSL {
	op := dsl.TxnOp{Key: vpp_nat.DNatKey(val.Label), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// LinuxInterface adds a mock request to create or update Linux network interface.
func (d *MockPutDSL) LinuxInterface(val *linux_intf.LinuxInterfaces_Interface) linux.PutDSL {
	op := dsl.TxnOp{Key: linux_intf.InterfaceKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

func (d *MockPutDSL) LinuxArpEntry(val *linux_l3.LinuxStaticArpEntries_ArpEntry) linux.PutDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticArpKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

func (d *MockPutDSL) LinuxRoute(val *linux_l3.LinuxStaticRoutes_Route) linux.PutDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticRouteKey(val.Name), Value: val}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (d *MockPutDSL) Delete() linux.DeleteDSL {
	return &MockDeleteDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockPutDSL) Send() defaultplugins.Reply {
	return d.parent.Send()
}

// Interface adds a mock request to delete an existing VPP network interface.
func (d *MockDeleteDSL) VppInterface(interfaceName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_intf.InterfaceKey(interfaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdSession adds a mock request to delete an existing bidirectional forwarding
// detection session.
func (d *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_bfd.SessionKey(bfdSessionIfaceName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdAuthKeys adds a mock request to delete an existing bidirectional forwarding
// detection key.
func (d *MockDeleteDSL) BfdAuthKeys(bfdKey string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_bfd.AuthKeysKey(bfdKey)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BfdEchoFunction adds a mock request to delete an existing bidirectional
// forwarding detection echo function.
func (d *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_bfd.EchoFunctionKey(bfdEchoName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (d *MockDeleteDSL) BD(bdName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l2.BridgeDomainKey(bdName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (d *MockDeleteDSL) BDFIB(bdName string, mac string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l2.FibKey(bdName, mac)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (d *MockDeleteDSL) XConnect(rxIfName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l2.XConnectKey(rxIfName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (d *MockDeleteDSL) StaticRoute(vrf uint32, dstAddr string, nextHopAddr string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l3.RouteKey(vrf, dstAddr, nextHopAddr)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (d *MockDeleteDSL) ACL(aclName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_acl.Key(aclName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// L4Features delete request for the L4Features
func (d *MockDeleteDSL) L4Features() linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l4.FeatureKey()}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Arp adds a request to delete an existing VPP L3 ARP entry.
func (d *MockDeleteDSL) Arp(ifaceName string, ipAddr string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l3.ArpEntryKey(ifaceName, ipAddr)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpInterfaces adds a request to create or update VPP L3 proxy ARP interfaces
func (d *MockDeleteDSL) ProxyArpInterfaces(label string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpInterfaceKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// ProxyArpRanges adds a request to create or update VPP L3 proxy ARP ranges
func (d *MockDeleteDSL) ProxyArpRanges(label string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l3.ProxyArpRangeKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// AppNamespace adds a request to delete an existing VPP Application Namespace.
func (d *MockDeleteDSL) AppNamespace(id string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_l4.AppNamespacesKey(id)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// StnRule adds request to delete Stn rule.
func (d *MockDeleteDSL) StnRule(ruleName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_stn.Key(ruleName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44Global adds a request to remove global configuration for NAT44
func (d *MockDeleteDSL) NAT44Global() linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_nat.GlobalConfigKey()}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// NAT44DNat adds a request to delete a DNAT configuration identified by label
func (d *MockDeleteDSL) NAT44DNat(label string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: vpp_nat.DNatKey(label)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// LinuxInterface adds a mock request to delete an existing Linux network
// interface.
func (d *MockDeleteDSL) LinuxInterface(ifName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: linux_intf.InterfaceKey(ifName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

func (d *MockDeleteDSL) LinuxArpEntry(entryName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticArpKey(entryName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

func (d *MockDeleteDSL) LinuxRoute(routeName string) linux.DeleteDSL {
	op := dsl.TxnOp{Key: linux_l3.StaticRouteKey(routeName)}
	d.parent.Ops = append(d.parent.Ops, op)
	return d
}

// Put changes the DSL mode to allow configuration editing.
func (d *MockDeleteDSL) Put() linux.PutDSL {
	return &MockPutDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockDeleteDSL) Send() defaultplugins.Reply {
	return d.parent.Send()
}
