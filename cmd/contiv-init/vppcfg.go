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

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/vishvananda/netlink"

	"github.com/ligato/cn-infra/servicelabel"

	"git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	if_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxv2/ifplugin/linuxcalls"
	l3_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxv2/l3plugin/linuxcalls"
	if_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"
	l3_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/l3plugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/dhcp"
	if_binapi "github.com/ligato/vpp-agent/plugins/vpp/binapi/interfaces"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv"
)

const (
	vppConnectTimeout  = 20 * time.Second // timeout for connection to VPP
	dhcpConnectTimeout = 20 * time.Second // timeout to wait for a DHCP offer after configuring DHCP on the interface

	tapHostEndMacAddr       = "00:00:00:00:00:02" // requirement of the VPP STN plugin
	defaultRouteDestination = "0.0.0.0/0"         // destination IP address used for default routes on VPP
)

// configureVpp configures main interface and vpp-host interconnect based on provided STN information.
func configureVpp(contivCfg *contiv.Config, stnData *stn.STNReply, useDHCP bool) error {
	var (
		err error
		mainIfIdx  uint32
		mainIfName string
		mainIPNet  *net.IPNet
		mainIP     *net.IPNet
	)

	// connect to VPP
	conn, connChan, err := govpp.AsyncConnect(govppmux.NewVppAdapter(""))
	if err != nil {
		logger.Errorf("Error by connecting to VPP: %v", err)
		return err
	}
	defer func() {
		// async disconnect to not block further execution
		go conn.Disconnect()
	}()

	// wait until connected or until timeout expires
	select {
	case ev := <-connChan:
		if ev.State == govpp.Connected {
			logger.Debug("Connected to VPP.")
		} else {
			logger.Error("Error by connecting to VPP: disconnected")
			return fmt.Errorf("VPP connection error")
		}
	case <-time.After(vppConnectTimeout):
		logger.Errorf("Error by connecting to VPP, not able to connect within %d seconds.", vppConnectTimeout/time.Second)
		return fmt.Errorf("VPP connection timeout")
	}

	// create an API channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		logger.Errorf("Error by creating GoVPP API channel: %v", err)
		return err
	}
	defer ch.Close()

	ifVppHandler := if_vppcalls.NewIfVppHandler(ch, logger)
	ifVppIdx := ifaceidx.NewIfaceIndex(logger, "sw-if-index")

	// TODO: support STN in ifplugin v.2
	//stnVppHandler := if_vppcalls.NewStnVppHandler(ch, nil, logger)

	routeHandler := l3_vppcalls.NewRouteVppHandler(ch, ifVppIdx, logger)

	// determine hardware NIC interface index
	mainIfIdx, mainIfName, err = findHwInterfaceIdx(ch)
	if err != nil {
		logger.Errorf("Error by listing HW interfaces: %v", err)
		return err
	}
	ifVppIdx.Put(mainIfName, ifaceidx.IfaceMetadata{SwIfIndex: mainIfIdx})

	// interface tag
	err = ifVppHandler.SetInterfaceTag(mainIfName, mainIfIdx)
	if err != nil {
		logger.Errorf("Error by setting the interface %s tag: %v", mainIfName, err)
		return err
	}

	// interface MTU
	err = ifVppHandler.SetInterfaceMtu(mainIfIdx, contivCfg.MTUSize)
	if err != nil {
		logger.Errorf("Error by setting the interface %s MTU: %v", mainIfName, err)
		return err
	}

	// interface up
	err = ifVppHandler.InterfaceAdminUp(mainIfIdx)
	if err != nil {
		logger.Errorf("Error by enabling the interface %s: %v", mainIfName, err)
		return err
	}

	// save main interface IP
	if len(stnData.IpAddresses) > 0 {
		ip, addr, _ := net.ParseCIDR(stnData.IpAddresses[0])
		mainIPNet = &net.IPNet{IP: addr.IP, Mask: addr.Mask} // deep copy
		addr.IP = ip
		mainIP = addr
	}

	if useDHCP {
		// DHCP-based interface configuration

		// configure DHCP on the interface
		ipChan, err := configureDHCP(ch, mainIfIdx)
		if err != nil {
			logger.Errorf("Error by configuring DHCP on the interface %s: %v", mainIfName, err)
			return err
		}

		// wait for the IP address retrieval
		var ip string
		select {
		case ip = <-ipChan:
			logger.Debugf("IP retrieved from DHCP: %s", ip)
		case <-time.After(dhcpConnectTimeout):
			logger.Errorf("Error by configuring DHCP on the interface %s: No address retrieved within %d seconds", mainIfName, dhcpConnectTimeout/time.Second)
			return fmt.Errorf("DHCP timeout")
		}

		// if there was no IP on the interface previously, use DHCP one
		if mainIP == nil {
			ip, addr, _ := net.ParseCIDR(ip)
			mainIPNet = &net.IPNet{IP: addr.IP, Mask: addr.Mask} // deep copy
			addr.IP = ip
			mainIP = addr
		}

		// the retrieved address must match with the original one
		if ip != mainIP.String() {
			logger.Errorf("The address retrieved from DHCP (%s) does not match with original address (%s)", ip, mainIP.String())
			return fmt.Errorf("IP address mismatch")
		}
	} else {
		// static IP-based interface configuration

		// interface IPs
		for _, stnAddr := range stnData.IpAddresses {
			ip, addr, _ := net.ParseCIDR(stnAddr)
			addr.IP = ip

			err = ifVppHandler.AddInterfaceIP(mainIfIdx, addr)
			if err != nil {
				logger.Errorf("Error by configuring interface IP: %v", err)
				return err
			}
		}

		// interface routes
		for _, stnRoute := range stnData.Routes {
			if stnRoute.NextHopIp == "" {
				continue // skip routes with no next hop IP (link-local)
			}
			var dstIP net.IP
			var dstAddr *net.IPNet
			if stnRoute.DestinationSubnet != "" {
				dstIP, dstAddr, _ = net.ParseCIDR(stnRoute.DestinationSubnet)
				dstAddr.IP = dstIP
			} else {
				_, dstAddr, _ = net.ParseCIDR(defaultRouteDestination)
			}
			nextHopIP := net.ParseIP(stnRoute.NextHopIp).To4()

			sRoute := &l3.StaticRoute{
				DstNetwork:        dstAddr.String(),
				NextHopAddr:       nextHopIP.String(),
				OutgoingInterface: mainIfName,
			}
			logger.Debug("Configuring static route: ", sRoute)
			err = routeHandler.VppAddRoute(sRoute)
			if err != nil {
				logger.Errorf("Error by configuring route: %v", err)
				return err
			}
		}
	}

	// interconnect TAP (AF-Packet + VETH not supported in the STN mode)
	tapIdx, err := ifVppHandler.AddTapInterface(
		contiv.HostInterconnectTAPinVPPLogicalName,
		&interfaces.Interface_TapLink{
			HostIfName: contiv.HostInterconnectTAPinLinuxHostName,
			Version:    uint32(contivCfg.TAPInterfaceVersion),
		})
	if err != nil {
		logger.Errorf("Error by adding TAP interface: %v", err)
		return err
	}
	ifVppIdx.Put(
		contiv.HostInterconnectTAPinVPPLogicalName,
		ifaceidx.IfaceMetadata{SwIfIndex: tapIdx})

	/* TODO: is this necessary already in this phase?
	err = ifVppHandler.SetInterfaceMac(tapIdx, contiv.HostInterconnectMAC)
	if err != nil {
		logger.Errorf("Error by setting the MAC for TAP: %v", err)
		return err
	}
	*/

	err = ifVppHandler.SetInterfaceMtu(tapIdx, contivCfg.MTUSize)
	if err != nil {
		logger.Errorf("Error by setting the MTU on TAP interface: %v", err)
		return err
	}

	err = ifVppHandler.InterfaceAdminUp(tapIdx)
	if err != nil {
		logger.Errorf("Error by enabling the TAP interface: %v", err)
		return err
	}

	ifVppHandler.SetUnnumberedIP(tapIdx, mainIfIdx)
	if err != nil {
		logger.Errorf("Error by setting the TAP interface as unnumbered: %v", err)
		return err
	}

	// interconnect STN
	/* TODO: not supported by v2 vpp-agent yet
	stnVppHandler.AddStnRule(tapIdx, &mainIP.IP)
	if err != nil {
		logger.Errorf("Error by adding STN rule: %v", err)
		return nil, err
	}
	*/

	// host-end TAP config
	ifNetlinkHandler := if_linuxcalls.NewNetLinkHandler()
	err = ifNetlinkHandler.AddInterfaceIP(contiv.HostInterconnectTAPinLinuxHostName,
		&net.IPNet{IP: mainIP.IP, Mask: mainIP.Mask})
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface IP: %v", err)
		return err
	}
	err = ifNetlinkHandler.SetInterfaceMac(contiv.HostInterconnectTAPinLinuxHostName,
		tapHostEndMacAddr)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface MAC: %v", err)
		return err
	}
	err = ifNetlinkHandler.SetInterfaceMTU(contiv.HostInterconnectTAPinLinuxHostName,
		int(contivCfg.MTUSize))
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface MTU: %v", err)
		return err
	}
	err = ifNetlinkHandler.SetInterfaceAlias(contiv.HostInterconnectTAPinLinuxHostName,
		getAgentPrefix() +
		contiv.HostInterconnectTAPinLinuxLogicalName + "/" +
		contiv.HostInterconnectTAPinVPPLogicalName + "/" +
		contiv.HostInterconnectTAPinLinuxHostName)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface alias: %v", err)
		return err
	}

	// configure proxy-ARP
	proxyARPHandler := l3_vppcalls.NewProxyArpVppHandler(ch, ifVppIdx, logger)
	firstIP, lastIP := cidr.AddressRange(mainIPNet)
	// If larger than a /31, remove network and broadcast addresses
	// from address range.
	if cidr.AddressCount(mainIPNet) > 2 {
		firstIP = cidr.Inc(firstIP)
		lastIP = cidr.Dec(lastIP)
	}
	err = proxyARPHandler.EnableProxyArpInterface(contiv.HostInterconnectTAPinVPPLogicalName)
	if err != nil {
		logger.Errorf("Error by configuring proxy ARP interface: %v", err)
		return err
	}
	err = proxyARPHandler.AddProxyArpRange(firstIP, lastIP)
	if err != nil {
		logger.Errorf("Error by configuring proxy ARP IP range: %v", err)
		return err
	}

	// host routes
	l3NetlinkHandler := l3_linuxcalls.NewNetLinkHandler()
	link, err := netlink.LinkByName(contiv.HostInterconnectTAPinLinuxHostName)
	if err != nil {
		logger.Errorf("Unable to find link %s: %v", contiv.HostInterconnectTAPinLinuxHostName, err)
		return err
	}
	for _, stnRoute := range stnData.Routes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		var dstIP net.IP
		var dstAddr *net.IPNet
		if stnRoute.DestinationSubnet != "" {
			dstIP, dstAddr, _ = net.ParseCIDR(stnRoute.DestinationSubnet)
			dstAddr.IP = dstIP
		} else {
			_, dstAddr, _ = net.ParseCIDR(defaultRouteDestination)
		}
		nextHopIP := net.ParseIP(stnRoute.NextHopIp)

		err = l3NetlinkHandler.AddStaticRoute(
			&netlink.Route{
				Dst:       dstAddr,
				Gw:        nextHopIP,
				LinkIndex: link.Attrs().Index,
			})
		if err != nil {
			logger.Errorf("Error by configuring host route to %s: %v", dstAddr.String(), err)
			return err
		}
	}

	return nil
}

// findHwInterfaceIdx finds index & name of the first available hardware NIC.
func findHwInterfaceIdx(ch api.Channel) (uint32, string, error) {
	req := &if_binapi.SwInterfaceDump{}
	reqCtx := ch.SendMultiRequest(req)

	ifName := ""
	ifIdx := uint32(0)
	for {
		msg := &if_binapi.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(msg)
		if stop {
			break // break out of the loop
		}
		if err != nil {
			logger.Errorf("Error by listing interfaces: %v", err)
			return 0, "", err
		}
		name := string(bytes.Trim(msg.InterfaceName, "\x00"))
		if !strings.HasPrefix(name, "local") && !strings.HasPrefix(name, "loop") &&
			!strings.HasPrefix(name, "host") && !strings.HasPrefix(name, "tap") {
			ifName = name
			ifIdx = msg.SwIfIndex
			logger.Debugf("Found HW interface %s, idx=%d", ifName, ifIdx)
			// do not break the loop, we need read till the end
		}
	}

	if ifName == "" {
		return 0, "", fmt.Errorf("no HW interface found")
	}
	return ifIdx, ifName, nil
}

// configureDHCP configures DHCP on an interface on VPP. Returns Go channel where assigned IP will be delivered.
func configureDHCP(ch api.Channel, ifIdx uint32) (chan string, error) {
	dhcpNotifChan := make(chan api.Message)
	dhcpIPChan := make(chan string)

	logger.Debugf("Enabling DHCP on the interface idx %d", ifIdx)

	// subscribe for the DHCP notifications from VPP
	_, err := ch.SubscribeNotification(dhcpNotifChan, &dhcp.DHCPComplEvent{})
	if err != nil {
		return nil, err
	}

	req := &dhcp.DHCPClientConfig{
		IsAdd: 1,
		Client: dhcp.DHCPClient{
			SwIfIndex:     ifIdx,
			WantDHCPEvent: 1,
		},
	}
	reply := &dhcp.DHCPClientConfigReply{}

	// configure DHCP on the interface
	err = ch.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return nil, err
	}

	// asynchronously handle DHCP notifications
	go handleDHCPNotifications(dhcpNotifChan, dhcpIPChan)
	return dhcpIPChan, nil
}

// handleDHCPNotifications handles DHCP state change notifications.
func handleDHCPNotifications(notifCh chan api.Message, dhcpIPChan chan string) {
	for {
		select {
		case msg := <-notifCh:
			switch notif := msg.(type) {
			case *dhcp.DHCPComplEvent:
				var ipAddr string
				lease := notif.Lease
				if lease.IsIPv6 == 1 {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(lease.HostAddress).To16().String(), lease.MaskWidth)
				} else {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(lease.HostAddress[:4]).To4().String(), lease.MaskWidth)
				}
				logger.Infof("DHCP event: %v, IP: %s", *notif, ipAddr)
				// send the IP via channel
				dhcpIPChan <- ipAddr
				// we can return the go routine, we do not support later changes of the IP
				return
			}
		}
	}
}

func getAgentPrefix() string {
	return servicelabel.GetDifferentAgentPrefix(os.Getenv(servicelabel.MicroserviceLabelEnvVar))
}
