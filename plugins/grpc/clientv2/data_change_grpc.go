// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clientv2

import (
	"golang.org/x/net/context"

	"github.com/contiv/vpp/plugins/grpc/rpc"
	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/clientv2/vpp"

	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/acl"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/ipsec"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/nat"
	"github.com/ligato/vpp-agent/api/models/vpp/punt"
	"github.com/ligato/vpp-agent/api/models/vpp/stn"
	"github.com/ligato/vpp-agent/plugins/vpp/model/bfd"
	"github.com/ligato/vpp-agent/plugins/vpp/model/l4"
)

const (
	notImplemented = "not implemented in v.2 yet"
	deprecated     = "deprecated in v.2"
)

// NewDataChangeDSL is a constructor
func NewDataChangeDSL(client rpc.DataChangeServiceClient) *DataChangeDSL {
	return &DataChangeDSL{
		client: client,
		putReq: &rpc.DataRequest{},
		delReq: &rpc.DataRequest{},
	}
}

// DataChangeDSL is used to conveniently assign all the data that are needed for the DataChange.
// This is an implementation of Domain Specific Language (DSL) for a change of the VPP/Linux configuration.
type DataChangeDSL struct {
	client  rpc.DataChangeServiceClient
	withPut bool
	withDel bool
	putReq  *rpc.DataRequest
	delReq  *rpc.DataRequest
}

// PutDSL allows to add or edit configuration via GRPC.
type PutDSL struct {
	parent *DataChangeDSL
}

// DeleteDSL allows to remove configuration via GRPC.
type DeleteDSL struct {
	parent *DataChangeDSL
}

// Put enables creating Interface/BD...
func (dsl *DataChangeDSL) Put() linuxclient.PutDSL {
	return &PutDSL{dsl}
}

// Delete enables deleting Interface/BD...
func (dsl *DataChangeDSL) Delete() linuxclient.DeleteDSL {
	return &DeleteDSL{dsl}
}

// LinuxInterface adds a request to create or update Linux network interface.
func (dsl *PutDSL) LinuxInterface(val *linux_interfaces.Interface) linuxclient.PutDSL {
	dsl.parent.putReq.LinuxInterfaces = append(dsl.parent.putReq.LinuxInterfaces, val)
	dsl.parent.withPut = true
	return dsl
}

// LinuxArpEntry adds a request to crete or update Linux ARP entry
func (dsl *PutDSL) LinuxArpEntry(val *linux_l3.ARPEntry) linuxclient.PutDSL {
	dsl.parent.putReq.LinuxArpEntries = append(dsl.parent.putReq.LinuxArpEntries, val)
	dsl.parent.withPut = true
	return dsl
}

// LinuxRoute adds a request to crete or update Linux route
func (dsl *PutDSL) LinuxRoute(val *linux_l3.Route) linuxclient.PutDSL {
	dsl.parent.putReq.LinuxRoutes = append(dsl.parent.putReq.LinuxRoutes, val)
	dsl.parent.withPut = true
	return dsl
}

// VppInterface adds a request to create or update VPP network interface.
func (dsl *PutDSL) VppInterface(val *vpp_interfaces.Interface) linuxclient.PutDSL {
	dsl.parent.putReq.Interfaces = append(dsl.parent.putReq.Interfaces, val)
	dsl.parent.withPut = true
	return dsl
}

// ACL adds a request to create or update VPP Access Control List.
func (dsl *PutDSL) ACL(val *vpp_acl.ACL) linuxclient.PutDSL {
	dsl.parent.putReq.AccessLists = append(dsl.parent.putReq.AccessLists, val)
	dsl.parent.withPut = true
	return dsl
}

// BfdSession adds a request to create or update VPP bidirectional
// forwarding detection session.
func (dsl *PutDSL) BfdSession(val *bfd.SingleHopBFD_Session) linuxclient.PutDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BfdAuthKeys adds a request to create or update VPP bidirectional
// forwarding detection key.
func (dsl *PutDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linuxclient.PutDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BfdEchoFunction adds a request to create or update VPP bidirectional
// forwarding detection echo function.
func (dsl *PutDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linuxclient.PutDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BD adds a request to create or update VPP Bridge Domain.
func (dsl *PutDSL) BD(val *vpp_l2.BridgeDomain) linuxclient.PutDSL {
	dsl.parent.putReq.BridgeDomains = append(dsl.parent.putReq.BridgeDomains, val)
	dsl.parent.withPut = true
	return dsl
}

// BDFIB adds a request to create or update VPP L2 Forwarding Information Base.
func (dsl *PutDSL) BDFIB(val *vpp_l2.FIBEntry) linuxclient.PutDSL {
	dsl.parent.putReq.FIBs = append(dsl.parent.putReq.FIBs, val)
	dsl.parent.withPut = true
	return dsl
}

// XConnect adds a request to create or update VPP Cross Connect.
func (dsl *PutDSL) XConnect(val *vpp_l2.XConnectPair) linuxclient.PutDSL {
	dsl.parent.putReq.XCons = append(dsl.parent.putReq.XCons, val)
	dsl.parent.withPut = true
	return dsl
}

// StaticRoute adds a request to create or update VPP L3 Static Route.
func (dsl *PutDSL) StaticRoute(val *vpp_l3.Route) linuxclient.PutDSL {
	dsl.parent.putReq.StaticRoutes = append(dsl.parent.putReq.StaticRoutes, val)
	dsl.parent.withPut = true
	return dsl
}

// Arp adds a request to create or update VPP L3 ARP.
func (dsl *PutDSL) Arp(val *vpp_l3.ARPEntry) linuxclient.PutDSL {
	dsl.parent.putReq.ArpEntries = append(dsl.parent.putReq.ArpEntries, val)
	dsl.parent.withPut = true
	return dsl
}

// ProxyArp adds a request to create or update VPP L3 proxy ARP.
func (dsl *PutDSL) ProxyArp(val *vpp_l3.ProxyARP) linuxclient.PutDSL {
	dsl.parent.putReq.ProxyArp = val
	dsl.parent.withPut = true
	return dsl
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (dsl *PutDSL) IPScanNeighbor(val *vpp_l3.IPScanNeighbor) linuxclient.PutDSL {
	dsl.parent.putReq.IPScanNeighbor = val
	dsl.parent.withPut = true
	return dsl
}

// L4Features adds a request to enable or disable L4 features
func (dsl *PutDSL) L4Features(val *l4.L4Features) linuxclient.PutDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// AppNamespace adds a request to create or update VPP Application namespace
func (dsl *PutDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) linuxclient.PutDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// StnRule adds a request to create or update VPP Stn rule.
func (dsl *PutDSL) StnRule(val *vpp_stn.Rule) linuxclient.PutDSL {
	defer func() { panic(deprecated) }()
	return dsl
}

// NAT44Global adds a request to set global configuration for NAT44
func (dsl *PutDSL) NAT44Global(val *vpp_nat.Nat44Global) linuxclient.PutDSL {
	dsl.parent.putReq.NatGlobal = val
	dsl.parent.withPut = true
	return dsl
}

// DNAT44 adds a request to create or update DNAT44 configuration
func (dsl *PutDSL) DNAT44(val *vpp_nat.DNat44) linuxclient.PutDSL {
	dsl.parent.putReq.DNATs = append(dsl.parent.putReq.DNATs, val)
	dsl.parent.withPut = true
	return dsl
}

// IPSecSA adds request to create a new Security Association
func (dsl *PutDSL) IPSecSA(val *vpp_ipsec.SecurityAssociation) linuxclient.PutDSL {
	dsl.parent.putReq.SAs = append(dsl.parent.putReq.SAs, val)
	dsl.parent.withPut = true
	return dsl
}

// IPSecSPD adds request to create a new Security Policy Database
func (dsl *PutDSL) IPSecSPD(val *vpp_ipsec.SecurityPolicyDatabase) linuxclient.PutDSL {
	dsl.parent.putReq.SPDs = append(dsl.parent.putReq.SPDs, val)
	dsl.parent.withPut = true
	return dsl
}

// PuntIPRedirect adds request to create or update rule to punt L3 traffic via interface.
func (dsl *PutDSL) PuntIPRedirect(val *vpp_punt.IPRedirect) linuxclient.PutDSL {
	dsl.parent.putReq.IPRedirectPunts = append(dsl.parent.putReq.IPRedirectPunts, val)
	dsl.parent.withPut = true
	return dsl
}

// PuntToHost adds request to create or update rule to punt L4 traffic to a host.
func (dsl *PutDSL) PuntToHost(val *vpp_punt.ToHost) linuxclient.PutDSL {
	dsl.parent.putReq.ToHostPunts = append(dsl.parent.putReq.ToHostPunts, val)
	dsl.parent.withPut = true
	return dsl
}

// Delete enables deleting Interface/BD...
func (dsl *PutDSL) Delete() linuxclient.DeleteDSL {
	return &DeleteDSL{dsl.parent}
}

// Send propagates changes to the channels.
func (dsl *PutDSL) Send() vppclient.Reply {
	return dsl.parent.Send()
}

// LinuxInterface adds a request to delete an existing Linux network
// interface.
func (dsl *DeleteDSL) LinuxInterface(ifaceName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.LinuxInterfaces = append(dsl.parent.delReq.LinuxInterfaces,
		&linux_interfaces.Interface{
			Name: ifaceName,
		})
	dsl.parent.withDel = true
	return dsl
}

// LinuxArpEntry adds a request to delete Linux ARP entry
func (dsl *DeleteDSL) LinuxArpEntry(ifaceName string, ipAddr string) linuxclient.DeleteDSL {
	dsl.parent.delReq.LinuxArpEntries = append(dsl.parent.delReq.LinuxArpEntries,
		&linux_l3.ARPEntry{
			Interface: ifaceName,
			IpAddress: ipAddr,
		})
	dsl.parent.withDel = true
	return dsl
}

// LinuxRoute adds a request to delete Linux route
func (dsl *DeleteDSL) LinuxRoute(dstNet, outIfaceName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.LinuxRoutes = append(dsl.parent.delReq.LinuxRoutes,
		&linux_l3.Route{
			DstNetwork:        dstNet,
			OutgoingInterface: outIfaceName,
		})
	dsl.parent.withDel = true
	return dsl
}

// VppInterface adds a request to delete an existing VPP network interface.
func (dsl *DeleteDSL) VppInterface(ifaceName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.Interfaces = append(dsl.parent.delReq.Interfaces,
		&vpp_interfaces.Interface{
			Name: ifaceName,
		})
	dsl.parent.withDel = true
	return dsl
}

// ACL adds a request to delete an existing VPP Access Control List.
func (dsl *DeleteDSL) ACL(aclName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.AccessLists = append(dsl.parent.delReq.AccessLists,
		&vpp_acl.ACL{
			Name: aclName,
		})
	dsl.parent.withDel = true
	return dsl
}

// BfdSession adds a request to delete an existing VPP bidirectional
// forwarding detection session.
func (dsl *DeleteDSL) BfdSession(bfdSessionIfaceName string) linuxclient.DeleteDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BfdAuthKeys adds a request to delete an existing VPP bidirectional
// forwarding detection key.
func (dsl *DeleteDSL) BfdAuthKeys(bfdKey string) linuxclient.DeleteDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BfdEchoFunction adds a request to delete an existing VPP bidirectional
// forwarding detection echo function.
func (dsl *DeleteDSL) BfdEchoFunction(bfdEchoName string) linuxclient.DeleteDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// BD adds a request to delete an existing VPP Bridge Domain.
func (dsl *DeleteDSL) BD(bdName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.BridgeDomains = append(dsl.parent.delReq.BridgeDomains,
		&vpp_l2.BridgeDomain{
			Name: bdName,
		})
	dsl.parent.withDel = true
	return dsl
}

// BDFIB adds a request to delete an existing VPP L2 Forwarding Information
// Base.
func (dsl *DeleteDSL) BDFIB(bdName string, mac string) linuxclient.DeleteDSL {
	dsl.parent.delReq.FIBs = append(dsl.parent.delReq.FIBs,
		&vpp_l2.FIBEntry{
			BridgeDomain: bdName,
			PhysAddress:  mac,
		})
	dsl.parent.withDel = true
	return dsl
}

// XConnect adds a request to delete an existing VPP Cross Connect.
func (dsl *DeleteDSL) XConnect(rxIfaceName string) linuxclient.DeleteDSL {
	dsl.parent.delReq.XCons = append(dsl.parent.delReq.XCons,
		&vpp_l2.XConnectPair{
			ReceiveInterface: rxIfaceName,
		})
	dsl.parent.withDel = true
	return dsl
}

// StaticRoute adds a request to delete an existing VPP L3 Static Route.
func (dsl *DeleteDSL) StaticRoute(vrf uint32, dstNet string, nextHopAddr string) linuxclient.DeleteDSL {
	dsl.parent.delReq.StaticRoutes = append(dsl.parent.delReq.StaticRoutes,
		&vpp_l3.Route{
			VrfId:       vrf,
			DstNetwork:  dstNet,
			NextHopAddr: nextHopAddr,
		})
	dsl.parent.withDel = true
	return dsl
}

// Arp adds a request to delete an existing VPP L3 ARP.
func (dsl *DeleteDSL) Arp(ifaceName string, ipAddr string) linuxclient.DeleteDSL {
	dsl.parent.delReq.ArpEntries = append(dsl.parent.delReq.ArpEntries,
		&vpp_l3.ARPEntry{
			Interface: ifaceName,
			IpAddress: ipAddr,
		})
	dsl.parent.withDel = true
	return dsl
}

// ProxyArp adds a request to delete an existing VPP L3 proxy ARP
func (dsl *DeleteDSL) ProxyArp() linuxclient.DeleteDSL {
	dsl.parent.delReq.ProxyArp = &vpp_l3.ProxyARP{}
	dsl.parent.withDel = true
	return dsl
}

// IPScanNeighbor adds a request to delete an existing VPP L3 IP Scan Neighbor.
func (dsl *DeleteDSL) IPScanNeighbor() linuxclient.DeleteDSL {
	dsl.parent.delReq.IPScanNeighbor = &vpp_l3.IPScanNeighbor{}
	dsl.parent.withDel = true
	return dsl
}

// L4Features adds a request to enable or disable L4 features
func (dsl *DeleteDSL) L4Features() linuxclient.DeleteDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// AppNamespace adds a request to delete VPP Application namespace
func (dsl *DeleteDSL) AppNamespace(id string) linuxclient.DeleteDSL {
	defer func() { panic(notImplemented) }()
	return dsl
}

// StnRule adds a request to delete an existing VPP Stn rule.
func (dsl *DeleteDSL) StnRule(ruleName string) linuxclient.DeleteDSL {
	defer func() { panic(deprecated) }()
	return dsl
}

// NAT44Global adds a request to remove global configuration for NAT44
func (dsl *DeleteDSL) NAT44Global() linuxclient.DeleteDSL {
	dsl.parent.delReq.NatGlobal = &vpp_nat.Nat44Global{}
	dsl.parent.withDel = true
	return dsl
}

// DNAT44 adds a request to delete an existing DNAT-44 configuration
func (dsl *DeleteDSL) DNAT44(label string) linuxclient.DeleteDSL {
	dsl.parent.delReq.DNATs = append(dsl.parent.delReq.DNATs,
		&vpp_nat.DNat44{
			Label: label,
		})
	dsl.parent.withDel = true
	return dsl
}

// IPSecSA adds request to delete a Security Association
func (dsl *DeleteDSL) IPSecSA(saIndex string) linuxclient.DeleteDSL {
	dsl.parent.delReq.SAs = append(dsl.parent.delReq.SAs,
		&vpp_ipsec.SecurityAssociation{
			Index: saIndex,
		})
	dsl.parent.withDel = true
	return dsl
}

// IPSecSPD adds request to delete a Security Policy Database
func (dsl *DeleteDSL) IPSecSPD(spdIndex string) linuxclient.DeleteDSL {
	dsl.parent.delReq.SPDs = append(dsl.parent.delReq.SPDs,
		&vpp_ipsec.SecurityPolicyDatabase{
			Index: spdIndex,
		})
	dsl.parent.withDel = true
	return dsl
}

// PuntIPRedirect adds request to delete a rule used to punt L3 traffic via interface.
func (dsl *DeleteDSL) PuntIPRedirect(l3Proto vpp_punt.L3Protocol, txInterface string) linuxclient.DeleteDSL {
	dsl.parent.delReq.IPRedirectPunts = append(dsl.parent.delReq.IPRedirectPunts,
		&vpp_punt.IPRedirect{
			L3Protocol:  l3Proto,
			TxInterface: txInterface,
		})
	dsl.parent.withDel = true
	return dsl
}

// PuntToHost adds request to delete a rule used to punt L4 traffic to a host.
func (dsl *DeleteDSL) PuntToHost(l3Proto vpp_punt.L3Protocol, l4Proto vpp_punt.L4Protocol, port uint32) linuxclient.DeleteDSL {
	dsl.parent.delReq.ToHostPunts = append(dsl.parent.delReq.ToHostPunts,
		&vpp_punt.ToHost{
			L3Protocol: l3Proto,
			L4Protocol: l4Proto,
			Port:       port,
		})
	dsl.parent.withDel = true
	return dsl
}

// Put enables creating Interface/BD...
func (dsl *DeleteDSL) Put() linuxclient.PutDSL {
	return &PutDSL{dsl.parent}
}

// Send propagates changes to the channels.
func (dsl *DeleteDSL) Send() vppclient.Reply {
	return dsl.parent.Send()
}

// Send propagates changes to the channels.
func (dsl *DataChangeDSL) Send() vppclient.Reply {
	var wasErr error

	ctx := context.Background()

	if dsl.withDel {
		if _, err := dsl.client.Del(ctx, dsl.delReq); err != nil {
			wasErr = err
		}
	}
	if dsl.withPut {
		if _, err := dsl.client.Put(ctx, dsl.putReq); err != nil {
			wasErr = err
		}
	}

	return &Reply{wasErr}
}

// Reply enables waiting for the reply and getting result (success/error).
type Reply struct {
	err error
}

// ReceiveReply returns error or nil.
func (dsl Reply) ReceiveReply() error {
	return dsl.err
}
