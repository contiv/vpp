package linux

import (
	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	vpp_bfd "github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	vpp_stn "github.com/ligato/vpp-agent/plugins/vpp/model/stn"
	vpp_acl "github.com/ligato/vpp-agent/plugins/vppv2/model/acl"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	vpp_nat "github.com/ligato/vpp-agent/plugins/vppv2/model/nat"
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
func (d *MockDataChangeDSL) Put() linuxclient.PutDSL {
	return &MockPutDSL{d}
}

// Delete initiates a chained sequence of data change DSL statements
// removing existing configurable objects.
func (d *MockDataChangeDSL) Delete() linuxclient.DeleteDSL {
	return &MockDeleteDSL{d}
}

// Send commits the transaction into the mock DB.
func (d *MockDataChangeDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Values)
	return &dsl.Reply{Err: err}
}

// Interface adds a mock request to create or update VPP network interface.
func (d *MockPutDSL) VppInterface(val *vpp_intf.Interface) linuxclient.PutDSL {
	key := vpp_intf.InterfaceKey(val.Name)
	d.parent.Values[key] = val
	return d
}

// BfdSession adds a mock request to create or update bidirectional forwarding
// detection session.
func (d *MockPutDSL) BfdSession(val *vpp_bfd.SingleHopBFD_Session) linuxclient.PutDSL {
	key := vpp_bfd.SessionKey(val.Interface)
	d.parent.Values[key] = val
	return d
}

// BfdAuthKeys adds a mock request to create or update bidirectional forwarding
// detection key.
func (d *MockPutDSL) BfdAuthKeys(val *vpp_bfd.SingleHopBFD_Key) linuxclient.PutDSL {
	key := vpp_bfd.AuthKeysKey(string(val.Id))
	d.parent.Values[key] = val
	return d
}

// BfdEchoFunction adds a mock request to create or update bidirectional
// forwarding detection echo function.
func (d *MockPutDSL) BfdEchoFunction(val *vpp_bfd.SingleHopBFD_EchoFunction) linuxclient.PutDSL {
	key := vpp_bfd.EchoFunctionKey(val.EchoSourceInterface)
	d.parent.Values[key] = val
	return d
}

// BD adds a mock request to create or update VPP Bridge Domain.
func (d *MockPutDSL) BD(val *vpp_l2.BridgeDomain) linuxclient.PutDSL {
	key := vpp_l2.BridgeDomainKey(val.Name)
	d.parent.Values[key] = val
	return d
}

// BDFIB adds a mock request to create or update VPP L2 Forwarding Information
// Base.
func (d *MockPutDSL) BDFIB(val *vpp_l2.FIBEntry) linuxclient.PutDSL {
	key := vpp_l2.FIBKey(val.BridgeDomain, val.PhysAddress)
	d.parent.Values[key] = val
	return d
}

// XConnect adds a mock request to create or update VPP Cross Connect.
func (d *MockPutDSL) XConnect(val *vpp_l2.XConnectPair) linuxclient.PutDSL {
	key := vpp_l2.XConnectKey(val.ReceiveInterface)
	d.parent.Values[key] = val
	return d
}

// StaticRoute adds a mock request to create or update VPP L3 Static Route.
func (d *MockPutDSL) StaticRoute(val *vpp_l3.StaticRoute) linuxclient.PutDSL {
	key := vpp_l3.RouteKey(val.VrfId, val.DstNetwork, val.NextHopAddr)
	d.parent.Values[key] = val
	return d
}

// ACL adds a mock request to create or update VPP Access Control List.
func (d *MockPutDSL) ACL(val *vpp_acl.Acl) linuxclient.PutDSL {
	key := vpp_acl.Key(val.Name)
	d.parent.Values[key] = val
	return d
}

// Arp adds a request to create or update VPP L3 ARP.
func (d *MockPutDSL) Arp(val *vpp_l3.ARPEntry) linuxclient.PutDSL {
	key := vpp_l3.ArpEntryKey(val.Interface, val.IpAddress)
	d.parent.Values[key] = val
	return d
}

// L4Features adds a request to enable or disable L4 features
func (d *MockPutDSL) L4Features(val *vpp_l4.L4Features) linuxclient.PutDSL {
	key := vpp_l4.FeatureKey()
	d.parent.Values[key] = val
	return d
}

// ProxyArp adds a request to create or update VPP L3 proxy ARP.
func (d *MockPutDSL) ProxyArp(val *vpp_l3.ProxyARP) linuxclient.PutDSL {
	key := vpp_l3.ProxyARPKey
	d.parent.Values[key] = val
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockPutDSL) IPScanNeighbor(val *vpp_l3.IPScanNeighbor) linuxclient.PutDSL {
	key := vpp_l3.IPScanNeighborKey
	d.parent.Values[key] = val
	return d
}

// AppNamespace adds a request to create or update VPP Application namespace
func (d *MockPutDSL) AppNamespace(val *vpp_l4.AppNamespaces_AppNamespace) linuxclient.PutDSL {
	key := vpp_l4.AppNamespacesKey(val.NamespaceId)
	d.parent.Values[key] = val
	return d
}

// StnRule adds a request to create or update VPP Stn rule.
func (d *MockPutDSL) StnRule(val *vpp_stn.STN_Rule) linuxclient.PutDSL {
	key := vpp_stn.Key(val.RuleName)
	d.parent.Values[key] = val
	return d
}

// NAT44Global adds a request to set global configuration for NAT44
func (d *MockPutDSL) NAT44Global(val *vpp_nat.Nat44Global) linuxclient.PutDSL {
	key := vpp_nat.GlobalNAT44Key
	d.parent.Values[key] = val
	return d
}

// DNAT44 adds a request to create a new DNAT configuration
func (d *MockPutDSL) DNAT44(val *vpp_nat.DNat44) linuxclient.PutDSL {
	key := vpp_nat.DNAT44Key(val.Label)
	d.parent.Values[key] = val
	return d
}

// LinuxInterface adds a mock request to create or update Linux network interface.
func (d *MockPutDSL) LinuxInterface(val *linux_intf.LinuxInterface) linuxclient.PutDSL {
	key := linux_intf.InterfaceKey(val.Name)
	d.parent.Values[key] = val
	return d
}

func (d *MockPutDSL) LinuxArpEntry(val *linux_l3.LinuxStaticARPEntry) linuxclient.PutDSL {
	key := linux_l3.StaticArpKey(val.Interface, val.IpAddress)
	d.parent.Values[key] = val
	return d
}

func (d *MockPutDSL) LinuxRoute(val *linux_l3.LinuxStaticRoute) linuxclient.PutDSL {
	key := linux_l3.StaticRouteKey(val.DstNetwork, val.OutgoingInterface)
	d.parent.Values[key] = val
	return d
}

// Delete changes the DSL mode to allow removal of an existing configuration.
func (d *MockPutDSL) Delete() linuxclient.DeleteDSL {
	return &MockDeleteDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockPutDSL) Send() vppclient.Reply {
	return d.parent.Send()
}

// Interface adds a mock request to delete an existing VPP network interface.
func (d *MockDeleteDSL) VppInterface(interfaceName string) linuxclient.DeleteDSL {
	key := vpp_intf.InterfaceKey(interfaceName)
	d.parent.Values[key] = nil
	return d
}

// BfdSession adds a mock request to delete an existing bidirectional forwarding
// detection session.
func (d *MockDeleteDSL) BfdSession(bfdSessionIfaceName string) linuxclient.DeleteDSL {
	key := vpp_bfd.SessionKey(bfdSessionIfaceName)
	d.parent.Values[key] = nil
	return d
}

// BfdAuthKeys adds a mock request to delete an existing bidirectional forwarding
// detection key.
func (d *MockDeleteDSL) BfdAuthKeys(bfdKey string) linuxclient.DeleteDSL {
	key := vpp_bfd.AuthKeysKey(bfdKey)
	d.parent.Values[key] = nil
	return d
}

// BfdEchoFunction adds a mock request to delete an existing bidirectional
// forwarding detection echo function.
func (d *MockDeleteDSL) BfdEchoFunction(bfdEchoName string) linuxclient.DeleteDSL {
	key := vpp_bfd.EchoFunctionKey(bfdEchoName)
	d.parent.Values[key] = nil
	return d
}

// BD adds a mock request to delete an existing VPP Bridge Domain.
func (d *MockDeleteDSL) BD(bdName string) linuxclient.DeleteDSL {
	key := vpp_l2.BridgeDomainKey(bdName)
	d.parent.Values[key] = nil
	return d
}

// BDFIB adds a mock request to delete an existing VPP L2 Forwarding Information
// Base.
func (d *MockDeleteDSL) BDFIB(bdName string, mac string) linuxclient.DeleteDSL {
	key := vpp_l2.FIBKey(bdName, mac)
	d.parent.Values[key] = nil
	return d
}

// XConnect adds a mock request to delete an existing VPP Cross Connect.
func (d *MockDeleteDSL) XConnect(rxIfName string) linuxclient.DeleteDSL {
	key := vpp_l2.XConnectKey(rxIfName)
	d.parent.Values[key] = nil
	return d
}

// StaticRoute adds a mock request to delete an existing VPP L3 Static Route..
func (d *MockDeleteDSL) StaticRoute(vrf uint32, dstAddr string, nextHopAddr string) linuxclient.DeleteDSL {
	key := vpp_l3.RouteKey(vrf, dstAddr, nextHopAddr)
	d.parent.Values[key] = nil
	return d
}

// ACL adds a mock request to delete an existing VPP Access Control List.
func (d *MockDeleteDSL) ACL(aclName string) linuxclient.DeleteDSL {
	key := vpp_acl.Key(aclName)
	d.parent.Values[key] = nil
	return d
}

// L4Features delete request for the L4Features
func (d *MockDeleteDSL) L4Features() linuxclient.DeleteDSL {
	key := vpp_l4.FeatureKey()
	d.parent.Values[key] = nil
	return d
}

// Arp adds a request to delete an existing VPP L3 ARP entry.
func (d *MockDeleteDSL) Arp(ifaceName string, ipAddr string) linuxclient.DeleteDSL {
	key := vpp_l3.ArpEntryKey(ifaceName, ipAddr)
	d.parent.Values[key] = nil
	return d
}

// ProxyArp adds a request to delete an existing VPP L3 proxy ARP.
func (d *MockDeleteDSL) ProxyArp() linuxclient.DeleteDSL {
	key := vpp_l3.ProxyARPKey
	d.parent.Values[key] = nil
	return d
}

// IPScanNeighbor adds a request to delete an existing VPP L3 IP Scan Neighbor.
func (d *MockDeleteDSL) IPScanNeighbor() linuxclient.DeleteDSL {
	key := vpp_l3.IPScanNeighborKey
	d.parent.Values[key] = nil
	return d
}

// AppNamespace adds a request to delete an existing VPP Application Namespace.
func (d *MockDeleteDSL) AppNamespace(id string) linuxclient.DeleteDSL {
	key := vpp_l4.AppNamespacesKey(id)
	d.parent.Values[key] = nil
	return d
}

// StnRule adds request to delete Stn rule.
func (d *MockDeleteDSL) StnRule(ruleName string) linuxclient.DeleteDSL {
	key := vpp_stn.Key(ruleName)
	d.parent.Values[key] = nil
	return d
}

// NAT44Global adds a request to remove global configuration for NAT44
func (d *MockDeleteDSL) NAT44Global() linuxclient.DeleteDSL {
	key := vpp_nat.GlobalNAT44Key
	d.parent.Values[key] = nil
	return d
}

// DNAT44 adds a request to delete a DNAT configuration identified by label
func (d *MockDeleteDSL) DNAT44(label string) linuxclient.DeleteDSL {
	key := vpp_nat.DNAT44Key(label)
	d.parent.Values[key] = nil
	return d
}

// LinuxInterface adds a mock request to delete an existing Linux network
// interface.
func (d *MockDeleteDSL) LinuxInterface(ifName string) linuxclient.DeleteDSL {
	key := linux_intf.InterfaceKey(ifName)
	d.parent.Values[key] = nil
	return d
}

func (d *MockDeleteDSL) LinuxArpEntry(ifaceName string, ipAddr string) linuxclient.DeleteDSL {
	key := linux_l3.StaticArpKey(ifaceName, ipAddr)
	d.parent.Values[key] = nil
	return d
}

func (d *MockDeleteDSL) LinuxRoute(dstAddr, outIfaceName string) linuxclient.DeleteDSL {
	key := linux_l3.StaticRouteKey(dstAddr, outIfaceName)
	d.parent.Values[key] = nil
	return d
}

// Put changes the DSL mode to allow configuration editing.
func (d *MockDeleteDSL) Put() linuxclient.PutDSL {
	return &MockPutDSL{d.parent}
}

// Send commits the transaction into the mock DB.
func (d *MockDeleteDSL) Send() vppclient.Reply {
	return d.parent.Send()
}
