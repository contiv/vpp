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

package ipnet

import (
	"encoding/binary"
	"net"
	"strings"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	nslinuxcalls "github.com/ligato/vpp-agent/plugins/linux/nsplugin/linuxcalls"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpp1908/vpe"
	"github.com/vishvananda/netlink"
)

const (
	ipv6AddrDelimiter = ":"

	// any IPv4 address
	ipv4AddrAny = "0.0.0.0"
	ipv4NetAny  = ipv4AddrAny + "/0"

	// any IPv6 address
	ipv6AddrAny = "::"
	ipv6NetAny  = ipv6AddrAny + "/0"

	// full prefixes for different IP address families
	ipv4FullPrefix = "/32"
	ipv6FullPrefix = "/128"

	// host prefixes
	ipv4HostPrefix = ipv4FullPrefix
	ipv6HostPrefix = ipv6FullPrefix
)

// getHostLinkIPs returns all IP addresses assigned to physical interfaces in the host
// network stack.
func (n *IPNet) getHostLinkIPs() (hostIPs []net.IP, err error) {
	// make sure we are in the default namespace
	nsCtx := nslinuxcalls.NewNamespaceMgmtCtx()
	nsRevert, err := n.LinuxNsPlugin.SwitchToNamespace(nsCtx, nil)
	if err != nil {
		n.Log.Error(err)
		return nil, err
	}
	defer nsRevert()

	// list all links
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
func (n *IPNet) executeDebugCLI(cmd string) (string, error) {
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
func interfaceRxModeType(rxMode string) vpp_interfaces.Interface_RxMode_Type {
	switch rxMode {
	case "polling":
		return vpp_interfaces.Interface_RxMode_POLLING
	case "interrupt":
		return vpp_interfaces.Interface_RxMode_INTERRUPT
	case "adaptive":
		return vpp_interfaces.Interface_RxMode_ADAPTIVE
	default:
		return vpp_interfaces.Interface_RxMode_DEFAULT
	}
}

// isIPv6 returns true if the IP address is an IPv6 address, false otherwise.
func isIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return strings.Contains(ip.String(), ipv6AddrDelimiter)
}

// isIPv6Str returns true if the string contains IPv6 address, false otherwise.
func isIPv6Str(ip string) bool {
	if ip == "" {
		return false
	}
	return strings.Contains(ip, ipv6AddrDelimiter)
}

// hostPrefixForAF returns prefix length string to address a host
// for address family determined from given IP address.
func hostPrefixForAF(ip net.IP) string {
	if isIPv6(ip) {
		return ipv6HostPrefix
	}
	return ipv4HostPrefix
}

// fullPrefixForAF returns prefix length string to address fully prefixed
// IP address for address family determined from given IP address.
func fullPrefixForAF(ip net.IP) string {
	if isIPv6(ip) {
		return ipv6FullPrefix
	}
	return ipv4FullPrefix
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

// addFullPrefixToIP creates from given IP address IPNet by applying full IP prefix.
// The full IP prefix used is determined from address family of given IP address.
func addFullPrefixToIP(ip net.IP) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(ip.String() + fullPrefixForAF(ip))
	return ipnet, err
}

// mergeConfiguration merges configuration from sourceConf to destConf.
func mergeConfiguration(destConf, sourceConf controller.KeyValuePairs) {
	if destConf == nil {
		return
	}
	for k, v := range sourceConf {
		destConf[k] = v
	}
}

// sliceContains returns true if provided slice contains provided value, false otherwise.
func sliceContains(slice []string, value string) bool {
	for _, i := range slice {
		if i == value {
			return true
		}
	}
	return false
}

// sliceAppendIfNotExists adds an item into the provided slice (if it does not already exists in the slice).
func sliceAppendIfNotExists(slice []string, value string) []string {
	if !sliceContains(slice, value) {
		slice = append(slice, value)
	}
	return slice
}

// sliceRemove removes an item from provided slice (if it exists in the slice).
func sliceRemove(slice []string, value string) []string {
	for i, val := range slice {
		if val == value {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
