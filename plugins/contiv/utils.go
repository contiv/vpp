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

package contiv

import (
	"encoding/binary"
	"fmt"
	"net"

	"git.fd.io/govpp.git/api"

	"github.com/ligato/vpp-agent/plugins/vpp/binapi/stats"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpe"
)

// executeDebugCLI executes VPP CLI command
func (s *remoteCNIserver) executeDebugCLI(cmd string) (string, error) {
	s.Logger.Infof("Executing debug CLI: %s", cmd)

	req := &vpe.CliInband{
		Cmd: []byte(cmd),
	}
	reply := &vpe.CliInbandReply{}

	err := s.govppChan.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		s.Logger.Error("Error by executing debug CLI:", err)
		return "", err
	}
	return string(reply.Reply), err
}

func (s *remoteCNIserver) subscribeVnetFibCounters() error {
	notifChan := make(chan api.Message, 1)
	_, err := s.govppChan.SubscribeNotification(notifChan, &stats.VnetIP4FibCounters{})

	if err != nil {
		s.Logger.Error("Error by subscribing to NewVnetIP4FibCounters:", err)
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
