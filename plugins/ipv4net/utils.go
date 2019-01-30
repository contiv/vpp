// Copyright (c) 2018 Cisco and/or its affiliates.
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

package ipv4net

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-binapi/binapi/ip"
	"github.com/ligato/vpp-binapi/binapi/vpe"
)

// getHostLinkIPs returns all IP addresses assigned to physical interfaces in the host
// network stack.
func (n *IPv4Net) getHostLinkIPs() (hostIPs []net.IP, err error) {
	links, err := netlink.LinkList()
	if err != nil {
		n.Log.Error("Unable to list host links:", err)
		return hostIPs, err
	}

	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") && !strings.HasPrefix(l.Attrs().Name, "docker") &&
			!strings.HasPrefix(l.Attrs().Name, "virbr") && !strings.HasPrefix(l.Attrs().Name, "vpp") {
			// not a virtual interface, list its IP addresses
			addrList, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				n.Log.Error("Unable to list link IPs:", err)
				return hostIPs, err
			}
			// return all IPs
			for _, addr := range addrList {
				hostIPs = append(hostIPs, addr.IP)
			}
		}
	}
	return hostIPs, nil
}

// executeDebugCLI executes VPP CLI command
func (n *IPv4Net) executeDebugCLI(cmd string) (string, error) {
	n.Log.Infof("Executing debug CLI: %s", cmd)

	req := &vpe.CliInband{
		Cmd: cmd,
	}
	reply := &vpe.CliInbandReply{}

	err := n.govppCh.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		n.Log.Error("Error by executing debug CLI:", err)
		return "", err
	}
	return string(reply.Reply), err
}

// createVrf creates provided VRF using binary API
func (n *IPv4Net) createVrf(vrfID uint32) error {
	n.Log.Info("Creating VRF 1")

	req := &ip.IPTableAddDel{
		TableID: vrfID,
		IsIPv6:  0,
		IsAdd:   1,
	}
	reply := &ip.IPTableAddDelReply{}

	err := n.govppCh.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		n.Log.Error("Error by creating VRF 1:", err)
	}
	return err
}

// hwAddrForNodeInterface generates hardware address for interface based on node ID.
func hwAddrForNodeInterface(nodeID uint32, prefix []byte) string {
	var res [6]byte
	copy(res[:], prefix)

	// the last four bytes are equal to nodeID
	binary.BigEndian.PutUint32(res[2:], nodeID)

	return net.HardwareAddr(res[:]).String()
}

// trimInterfaceName trims interface name to not exceed the given length limit.
func trimInterfaceName(ifName string, maxLen int) string {
	if len(ifName) > maxLen {
		return ifName[:maxLen]
	}
	return ifName
}

// combineAddrWithNet combines provided IP address with the mask from the provided network.
func combineAddrWithNet(addr net.IP, network *net.IPNet) *net.IPNet {
	if len(addr) == 0 {
		return nil
	}
	return &net.IPNet{IP: addr, Mask: network.Mask}
}

// ipNetToString convert IP network to string, also handling <nil> pointer.
func ipNetToString(ipNet *net.IPNet) string {
	if ipNet == nil {
		return ""
	}
	return ipNet.String()
}

// ipv4ToUint32 is a simple utility function for conversion from IPv4 to uint32.
func ipv4ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("IP address %v is not ipv4 address (or ipv6 convertible to ipv4 address)", ip)
	}
	var tmp uint32
	for _, bytePart := range ip {
		tmp = tmp<<8 + uint32(bytePart)
	}
	return tmp, nil
}

// uint32ToIpv4 is a simple utility function for conversion from uint32 to IPv4.
func uint32ToIpv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4()
}

// interfaceRxModeType returns interface rx-mode type from provided string.
func interfaceRxModeType(rxMode string) vpp_interfaces.Interface_RxModeSettings_RxModeType {
	switch rxMode {
	case "polling":
		return vpp_interfaces.Interface_RxModeSettings_POLLING
	case "interrupt":
		return vpp_interfaces.Interface_RxModeSettings_INTERRUPT
	case "adaptive":
		return vpp_interfaces.Interface_RxModeSettings_ADAPTIVE
	default:
		return vpp_interfaces.Interface_RxModeSettings_DEFAULT
	}
}
