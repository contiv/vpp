//  Copyright (c) 2018 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vpp1901

import (
	"fmt"
	"net"

	l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	l3binapi "github.com/ligato/vpp-agent/plugins/vpp/binapi/vpp1901/ip"
	"github.com/ligato/vpp-agent/plugins/vpp/l3plugin/vppcalls"
)

// DumpArpEntries implements arp handler.
func (h *ArpVppHandler) DumpArpEntries() ([]*vppcalls.ArpDetails, error) {
	arpV4Entries, err := h.dumpArpEntries(false)
	if err != nil {
		return nil, err
	}
	arpV6Entries, err := h.dumpArpEntries(true)
	if err != nil {
		return nil, err
	}
	return append(arpV4Entries, arpV6Entries...), nil
}

func (h *ArpVppHandler) dumpArpEntries(isIPv6 bool) ([]*vppcalls.ArpDetails, error) {
	var entries []*vppcalls.ArpDetails
	reqCtx := h.callsChannel.SendMultiRequest(&l3binapi.IPNeighborDump{
		SwIfIndex: 0xffffffff, // Send multirequest to get all ARP entries for given IP version
		IsIPv6:    boolToUint(isIPv6),
	})

	for {
		arpDetails := &l3binapi.IPNeighborDetails{}
		stop, err := reqCtx.ReceiveReply(arpDetails)
		if stop {
			break
		}
		if err != nil {
			h.log.Error(err)
			return nil, err
		}

		// ARP interface
		ifName, _, exists := h.ifIndexes.LookupBySwIfIndex(arpDetails.SwIfIndex)
		if !exists {
			h.log.Warnf("ARP dump: interface name not found for index %d", arpDetails.SwIfIndex)
		}
		// IP & MAC address
		var ip string
		if arpDetails.IsIPv6 == 1 {
			ip = fmt.Sprintf("%s", net.IP(arpDetails.IPAddress).To16().String())
		} else {
			ip = fmt.Sprintf("%s", net.IP(arpDetails.IPAddress[:4]).To4().String())
		}

		// ARP entry
		arp := &l3.ARPEntry{
			Interface:   ifName,
			IpAddress:   ip,
			PhysAddress: net.HardwareAddr(arpDetails.MacAddress).String(),
			Static:      uintToBool(arpDetails.IsStatic),
		}
		// ARP meta
		meta := &vppcalls.ArpMeta{
			SwIfIndex: arpDetails.SwIfIndex,
		}

		entries = append(entries, &vppcalls.ArpDetails{
			Arp:  arp,
			Meta: meta,
		})
	}

	return entries, nil
}
