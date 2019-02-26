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
	"net"
	"strings"

	"git.fd.io/govpp.git/api"
	"github.com/vishvananda/netlink"

	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpp1810/ip"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpp1810/stats"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpp1810/vpe"
)

const (
	ipv6AddrDelimiter = ":"

	// any IPv4 address
	ipv4AddrAny = "0.0.0.0"
	ipv4NetAny  = ipv4AddrAny + "/0"

	// any IPv6 address
	ipv6AddrAny = "::"
	ipv6NetAny  = ipv6AddrAny + "/0"

	// host prefixes
	ipv4HostPrefix = "/32"
	ipv6HostPrefix = "/128"
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
			family := netlink.FAMILY_V4
			if n.ContivConf.GetIPAMConfig().UseIPv6 {
				family = netlink.FAMILY_V6
			}
			addrList, err := netlink.AddrList(l, family)
			if err != nil {
				n.Log.Error("Unable to list link IPs:", err)
				return hostIPs, err
			}
			// return all IPs
			for _, addr := range addrList {
				if family == netlink.FAMILY_V6 && addr.Scope == int(netlink.SCOPE_LINK) {
					// skip link-local IPv6 addresses
					continue
				}
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
		Cmd: []byte(cmd),
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

func (n *IPv4Net) subscribeVnetFibCounters() error {
	notifChan := make(chan api.Message, 1)
	_, err := n.govppCh.SubscribeNotification(notifChan, &stats.VnetIP4FibCounters{})

	if err != nil {
		n.Log.Error("Error by subscribing to NewVnetIP4FibCounters:", err)
	}

	// read from the notif channel in a go routine to not block once the channel is full
	go func() {
		for {
			<-notifChan
		}
	}()

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

// isIPv6 returns true if the IP address is an IPv6 address, false otherwise.
func isIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return strings.Contains(ip.String(), ipv6AddrDelimiter)
}

// hostPrefixForAF returns prefix length string to address a host
// for address family determined from given IP address.
func hostPrefixForAF(ip net.IP) string {
	if isIPv6(ip) {
		return ipv6HostPrefix
	}
	return ipv4HostPrefix
}

// anyAddrForAF returns IP address identifying "any" node
// for address family determined from given IP address.
func anyAddrForAF(ip net.IP) string {
	if isIPv6(ip) {
		return ipv6AddrAny
	}
	return ipv4AddrAny
}

// anyNetAddrForAF returns address + prefix identifying "any" node
// for address family determined from given IP address (can be used e.g. for default routes).
func anyNetAddrForAF(ip net.IP) string {
	if isIPv6(ip) {
		return ipv6NetAny
	}
	return ipv4NetAny
}
