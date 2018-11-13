package linux

import (
	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/contiv/vpp/mock/localclient/dsl"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	vpp_stn "github.com/ligato/vpp-agent/plugins/vpp/model/stn"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/acl"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	vpp_nat "github.com/ligato/vpp-agent/plugins/vppv2/model/nat"
)

// MockDataResyncDSL is mock for DataResyncDSL.
type MockDataResyncDSL struct {
	dsl.CommonMockDSL
}

// NewMockDataResyncDSL is a constructor for MockDataResyncDSL.
func NewMockDataResyncDSL(commitFunc dsl.CommitFunc) *MockDataResyncDSL {
	return &MockDataResyncDSL{CommonMockDSL: dsl.NewCommonMockDSL(commitFunc)}
}

// LinuxInterface adds Linux interface to the mock RESYNC request.
func (d *MockDataResyncDSL) LinuxInterface(val *linux_intf.LinuxInterface) linuxclient.DataResyncDSL {
	key := linux_intf.InterfaceKey(val.Name)
	d.Values[key] = val
	return d
}

func (d *MockDataResyncDSL) LinuxArpEntry(val *linux_l3.LinuxStaticARPEntry) linuxclient.DataResyncDSL {
	key := linux_l3.StaticArpKey(val.Interface, val.IpAddress)
	d.Values[key] = val
	return d
}

func (d *MockDataResyncDSL) LinuxRoute(val *linux_l3.LinuxStaticRoute) linuxclient.DataResyncDSL {
	key := linux_l3.StaticRouteKey(val.DstNetwork, val.OutgoingInterface)
	d.Values[key] = val
	return d
}

// VppInterface adds VPP interface to the mock RESYNC request.
func (d *MockDataResyncDSL) VppInterface(val *vpp_intf.Interface) linuxclient.DataResyncDSL {
	key := vpp_intf.InterfaceKey(val.Name)
	d.Values[key] = val
	return d
}

// BfdSession adds VPP bidirectional forwarding detection session to the mock
// RESYNC request.
func (d *MockDataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) linuxclient.DataResyncDSL {
	key := bfd.SessionKey(val.Interface)
	d.Values[key] = val
	return d
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the mock RESYNC
// request.
func (d *MockDataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linuxclient.DataResyncDSL {
	key := bfd.AuthKeysKey(string(val.Id))
	d.Values[key] = val
	return d
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// mock to the RESYNC request.
func (d *MockDataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linuxclient.DataResyncDSL {
	key := bfd.EchoFunctionKey(val.EchoSourceInterface)
	d.Values[key] = val
	return d
}

// BD adds VPP Bridge Domain to the mock RESYNC request.
func (d *MockDataResyncDSL) BD(val *vpp_l2.BridgeDomain) linuxclient.DataResyncDSL {
	key := vpp_l2.BridgeDomainKey(val.Name)
	d.Values[key] = val
	return d
}

// BDFIB adds VPP L2 FIB to the mock RESYNC request.
func (d *MockDataResyncDSL) BDFIB(val *vpp_l2.FIBEntry) linuxclient.DataResyncDSL {
	key := vpp_l2.FIBKey(val.BridgeDomain, val.PhysAddress)
	d.Values[key] = val
	return d
}

// XConnect adds VPP Cross Connect to the mock RESYNC request.
func (d *MockDataResyncDSL) XConnect(val *vpp_l2.XConnectPair) linuxclient.DataResyncDSL {
	key := vpp_l2.XConnectKey(val.ReceiveInterface)
	d.Values[key] = val
	return d
}

// StaticRoute adds VPP L3 Static Route to the mock RESYNC request.
func (d *MockDataResyncDSL) StaticRoute(val *vpp_l3.StaticRoute) linuxclient.DataResyncDSL {
	key := vpp_l3.RouteKey(val.VrfId, val.DstNetwork, val.NextHopAddr)
	d.Values[key] = val
	return d
}

// ACL adds VPP Access Control List to the mock RESYNC request.
func (d *MockDataResyncDSL) ACL(val *acl.Acl) linuxclient.DataResyncDSL {
	key := acl.Key(val.Name)
	d.Values[key] = val
	return d
}

// L4Features adds L4Features to the RESYNC request
func (d *MockDataResyncDSL) L4Features(val *vpp_l4.L4Features) linuxclient.DataResyncDSL {
	key := vpp_l4.FeatureKey()
	d.Values[key] = val
	return d
}

// AppNamespace adds Application Namespace to the RESYNC request
func (d *MockDataResyncDSL) AppNamespace(val *vpp_l4.AppNamespaces_AppNamespace) linuxclient.DataResyncDSL {
	key := vpp_l4.AppNamespacesKey(val.NamespaceId)
	d.Values[key] = val
	return d
}

// Arp adds L3 ARP entry to the RESYNC request.
func (d *MockDataResyncDSL) Arp(val *vpp_l3.ARPEntry) linuxclient.DataResyncDSL {
	key := vpp_l3.ArpEntryKey(val.Interface, val.IpAddress)
	d.Values[key] = val
	return d
}

// ProxyArp adds L3 proxy ARP to the RESYNC request.
func (d *MockDataResyncDSL) ProxyArp(val *vpp_l3.ProxyARP) linuxclient.DataResyncDSL {
	key := vpp_l3.ProxyARPKey
	d.Values[key] = val
	return d
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (d *MockDataResyncDSL) IPScanNeighbor(val *vpp_l3.IPScanNeighbor) linuxclient.DataResyncDSL {
	key := vpp_l3.IPScanNeighborKey
	d.Values[key] = val
	return d
}

// StnRule adds Stn rule to the RESYNC request.
func (d *MockDataResyncDSL) StnRule(val *vpp_stn.STN_Rule) linuxclient.DataResyncDSL {
	key := vpp_stn.Key(val.RuleName)
	d.Values[key] = val
	return d
}

// NAT44Global adds a request to RESYNC global configuration for NAT44
func (d *MockDataResyncDSL) NAT44Global(val *vpp_nat.Nat44Global) linuxclient.DataResyncDSL {
	key := vpp_nat.GlobalNAT44Key
	d.Values[key] = val
	return d
}

// DNAT44 adds a request to RESYNC a new DNAT configuration
func (d *MockDataResyncDSL) DNAT44(val *vpp_nat.DNat44) linuxclient.DataResyncDSL {
	key := vpp_nat.DNAT44Key(val.Label)
	d.Values[key] = val
	return d
}

// Send commits the transaction into the mock DB.
func (d *MockDataResyncDSL) Send() vppclient.Reply {
	err := d.CommitFunc(d.Values)
	return &dsl.Reply{Err: err}
}
