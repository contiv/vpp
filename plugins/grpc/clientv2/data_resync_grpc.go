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

	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/clientv2/vpp"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
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

	"github.com/contiv/vpp/plugins/grpc/rpc"
)

// NewDataResyncDSL is a constructor.
func NewDataResyncDSL(client rpc.DataResyncServiceClient) *DataResyncDSL {
	return &DataResyncDSL{
		client: client,
		req:    &rpc.DataRequest{},
	}
}

// DataResyncDSL is used to conveniently assign all the data that are needed for the RESYNC.
// This is implementation of Domain Specific Language (DSL) for data RESYNC of the VPP configuration.
type DataResyncDSL struct {
	client rpc.DataResyncServiceClient
	req    *rpc.DataRequest
}

// LinuxInterface adds Linux interface to the RESYNC request.
func (dsl *DataResyncDSL) LinuxInterface(val *linux_interfaces.Interface) linuxclient.DataResyncDSL {
	dsl.req.LinuxInterfaces = append(dsl.req.LinuxInterfaces, val)
	return dsl
}

// LinuxInterface adds Linux ARP entry to the RESYNC request.
func (dsl *DataResyncDSL) LinuxArpEntry(val *linux_l3.StaticARPEntry) linuxclient.DataResyncDSL {
	dsl.req.LinuxArpEntries = append(dsl.req.LinuxArpEntries, val)
	return dsl
}

// LinuxInterface adds Linux route to the RESYNC request.
func (dsl *DataResyncDSL) LinuxRoute(val *linux_l3.StaticRoute) linuxclient.DataResyncDSL {
	dsl.req.LinuxRoutes = append(dsl.req.LinuxRoutes, val)
	return dsl
}

// VppInterface adds VPP interface to the RESYNC request.
func (dsl *DataResyncDSL) VppInterface(val *interfaces.Interface) linuxclient.DataResyncDSL {
	dsl.req.Interfaces = append(dsl.req.Interfaces, val)
	return dsl
}

// ACL adds VPP Access Control List to the RESYNC request.
func (dsl *DataResyncDSL) ACL(val *acl.Acl) linuxclient.DataResyncDSL {
	dsl.req.AccessLists = append(dsl.req.AccessLists, val)
	return dsl
}

// BfdSession adds VPP bidirectional forwarding detection session
// to the RESYNC request.
func (dsl *DataResyncDSL) BfdSession(val *bfd.SingleHopBFD_Session) linuxclient.DataResyncDSL {
	panic(notImplementedPanic)
	return dsl
}

// BfdAuthKeys adds VPP bidirectional forwarding detection key to the RESYNC
// request.
func (dsl *DataResyncDSL) BfdAuthKeys(val *bfd.SingleHopBFD_Key) linuxclient.DataResyncDSL {
	panic(notImplementedPanic)
	return dsl
}

// BfdEchoFunction adds VPP bidirectional forwarding detection echo function
// to the RESYNC request.
func (dsl *DataResyncDSL) BfdEchoFunction(val *bfd.SingleHopBFD_EchoFunction) linuxclient.DataResyncDSL {
	panic(notImplementedPanic)
	return dsl
}

// BD adds VPP Bridge Domain to the RESYNC request.
func (dsl *DataResyncDSL) BD(val *l2.BridgeDomain) linuxclient.DataResyncDSL {
	dsl.req.BridgeDomains = append(dsl.req.BridgeDomains, val)
	return dsl
}

// BDFIB adds VPP L2 FIB to the RESYNC request.
func (dsl *DataResyncDSL) BDFIB(val *l2.FIBEntry) linuxclient.DataResyncDSL {
	dsl.req.FIBs = append(dsl.req.FIBs, val)
	return dsl
}

// XConnect adds VPP Cross Connect to the RESYNC request.
func (dsl *DataResyncDSL) XConnect(val *l2.XConnectPair) linuxclient.DataResyncDSL {
	dsl.req.XCons = append(dsl.req.XCons, val)
	return dsl
}

// StaticRoute adds VPP L3 Static Route to the RESYNC request.
func (dsl *DataResyncDSL) StaticRoute(val *l3.StaticRoute) linuxclient.DataResyncDSL {
	dsl.req.StaticRoutes = append(dsl.req.StaticRoutes, val)
	return dsl
}

// Arp adds VPP L3 ARP to the RESYNC request.
func (dsl *DataResyncDSL) Arp(val *l3.ARPEntry) linuxclient.DataResyncDSL {
	dsl.req.ArpEntries = append(dsl.req.ArpEntries, val)
	return dsl
}

// ProxyArp adds L3 proxy ARP interfaces to the RESYNC request.
func (dsl *DataResyncDSL) ProxyArp(val *l3.ProxyARP) linuxclient.DataResyncDSL {
	dsl.req.ProxyArp = val
	return dsl
}

// IPScanNeighbor adds L3 IP Scan Neighbor to the RESYNC request.
func (dsl *DataResyncDSL) IPScanNeighbor(val *l3.IPScanNeighbor) linuxclient.DataResyncDSL {
	dsl.req.IPScanNeighbor = val
	return dsl
}

// L4Features adds L4 features to the RESYNC request
func (dsl *DataResyncDSL) L4Features(val *l4.L4Features) linuxclient.DataResyncDSL {
	panic(notImplementedPanic)
	return dsl
}

// AppNamespace adds VPP Application namespaces to the RESYNC request
func (dsl *DataResyncDSL) AppNamespace(val *l4.AppNamespaces_AppNamespace) linuxclient.DataResyncDSL {
	panic(notImplementedPanic)
	return dsl
}

// StnRule adds Stn rule to the RESYNC request.
func (dsl *DataResyncDSL) StnRule(val *stn.STN_Rule) linuxclient.DataResyncDSL {
	panic(deprecatedPanic)
	return dsl
}

// NAT44Global adds global NAT44 configuration to the RESYNC request.
func (dsl *DataResyncDSL) NAT44Global(val *nat.Nat44Global) linuxclient.DataResyncDSL {
	dsl.req.NatGlobal = val
	return dsl
}

// DNAT44 adds DNAT44 configuration to the RESYNC request
func (dsl *DataResyncDSL) DNAT44(val *nat.DNat44) linuxclient.DataResyncDSL {
	dsl.req.DNATs = append(dsl.req.DNATs, val)
	return dsl
}

// IPSecSA adds request to RESYNC a new Security Association
func (dsl *DataResyncDSL) IPSecSA(val *ipsec.SecurityAssociation) linuxclient.DataResyncDSL {
	dsl.req.SAs = append(dsl.req.SAs, val)
	return dsl
}

// IPSecSPD adds request to RESYNC a new Security Policy Database
func (dsl *DataResyncDSL) IPSecSPD(val *ipsec.SecurityPolicyDatabase) linuxclient.DataResyncDSL {
	dsl.req.SPDs = append(dsl.req.SPDs, val)
	return dsl
}

// PuntIPRedirect adds request to RESYNC a rule used to punt L3 traffic via interface.
func (dsl *DataResyncDSL) PuntIPRedirect(val *punt.IpRedirect) linuxclient.DataResyncDSL {
	dsl.req.IPRedirectPunts = append(dsl.req.IPRedirectPunts, val)
	return dsl
}

// PuntToHost adds request to RESYNC a rule used to punt L4 traffic to a host.
func (dsl *DataResyncDSL) PuntToHost(val *punt.ToHost) linuxclient.DataResyncDSL {
	dsl.req.ToHostPunts = append(dsl.req.ToHostPunts, val)
	return dsl
}

// Send propagates the request to the plugins. It deletes obsolete keys if listKeys() function is not null.
// The listkeys() function is used to list all current keys.
func (dsl *DataResyncDSL) Send() vppclient.Reply {
	var wasErr error

	ctx := context.Background()

	if _, err := dsl.client.Resync(ctx, dsl.req); err != nil {
		wasErr = err
	}

	return &Reply{err: wasErr}
}
