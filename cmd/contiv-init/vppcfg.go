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

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/servicelabel"

	"git.fd.io/govpp.git/api"
	govpp "git.fd.io/govpp.git/core"

	if_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/vppcalls"
	l3_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	if_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/linuxcalls"
	l3_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/linuxcalls"

	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	stn_nb "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/stn"
	if_linux "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/interfaces"
	l3_linux "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/l3"

	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/dhcp"
	if_binapi "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/interfaces"
	ip_binapi "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/ip"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vpe"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv"
	"github.com/vishvananda/netlink"
)

const (
	etcdConnectionRetries = 20               // number of retries to connect to ETCD once STN is configured
	vppConnectTimeout     = 20 * time.Second // timeout for connection to VPP
	dhcpConnectTimeout    = 20 * time.Second // timeout to wait for a DHCP offer after configuring DHCP on the interface

	tapHostEndMacAddr       = "00:00:00:00:00:02" // requirement of the VPP STN plugin
	defaultRouteDestination = "0.0.0.0/0"         // destination IP address used for default routes on VPP
)

type vppCfgCtx struct {
	mainIfIdx  uint32
	mainIfName string
	mainIPNet  *net.IPNet
	mainIP     *net.IPNet
}

// configureVpp configures main interface and vpp-host interconnect based on provided STN information.
func configureVpp(contivCfg *contiv.Config, stnData *stn.STNReply, useDHCP bool) (*vppCfgCtx, error) {
	var err error

	// connect to VPP
	govpp.SetControlPingMessages(&vpe.ControlPing{}, &vpe.ControlPingReply{})
	conn, connChan, err := govpp.AsyncConnect(govppmux.NewVppAdapter())
	if err != nil {
		logger.Errorf("Error by connecting to VPP: %v", err)
		return nil, err
	}
	defer conn.Disconnect()

	// wait until connected or until timeout expires
	select {
	case ev := <-connChan:
		if ev.State == govpp.Connected {
			logger.Debug("Connected to VPP.")
		} else {
			logger.Error("Error by connecting to VPP: disconnected")
			return nil, fmt.Errorf("VPP connection error")
		}
	case <-time.After(vppConnectTimeout):
		logger.Errorf("Error by connecting to VPP, not able to connect within %d seconds.", vppConnectTimeout/time.Second)
		return nil, fmt.Errorf("VPP connection timeout")
	}

	// create an API channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		logger.Errorf("Error by creating GoVPP API channel: %v", err)
		return nil, err
	}
	defer ch.Close()

	cfg := &vppCfgCtx{}

	// determine hardware NIC interface index
	cfg.mainIfIdx, cfg.mainIfName, err = findHwInterfaceIdx(ch)
	if err != nil {
		logger.Errorf("Error by listing HW interfaces: %v", err)
		return nil, err
	}

	// interface tag
	err = if_vppcalls.SetInterfaceTag(cfg.mainIfName, cfg.mainIfIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the interface %s tag: %v", cfg.mainIfName, err)
		return nil, err
	}

	// interface MTU
	err = if_vppcalls.SetInterfaceMtu(cfg.mainIfIdx, contivCfg.MTUSize, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the interface %s MTU: %v", cfg.mainIfName, err)
		return nil, err
	}

	// interface up
	err = if_vppcalls.InterfaceAdminUp(cfg.mainIfIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by enabling the interface %s: %v", cfg.mainIfName, err)
		return nil, err
	}

	// save main interface IP
	if len(stnData.IpAddresses) > 0 {
		ip, addr, _ := net.ParseCIDR(stnData.IpAddresses[0])
		cfg.mainIPNet = &net.IPNet{IP: addr.IP, Mask: addr.Mask} // deep copy
		addr.IP = ip
		cfg.mainIP = addr
	}

	if useDHCP {
		// DHCP-based interface configuration

		// configure DHCP on the interface
		ipChan, err := configureDHCP(ch, cfg.mainIfIdx)
		if err != nil {
			logger.Errorf("Error by configuring DHCP on the interface %s: %v", cfg.mainIfName, err)
			return nil, err
		}

		// wait for the IP address retrieval
		var ip string
		select {
		case ip = <-ipChan:
			logger.Debugf("IP retrieved from DHCP: %s", ip)
		case <-time.After(dhcpConnectTimeout):
			logger.Errorf("Error by configuring DHCP on the interface %s: No address retrieved within %d seconds", cfg.mainIfName, dhcpConnectTimeout/time.Second)
			return nil, fmt.Errorf("DHCP timeout")
		}

		// if there was no IP on the interface previously, use DHCP one
		if cfg.mainIP == nil {
			ip, addr, _ := net.ParseCIDR(ip)
			cfg.mainIPNet = &net.IPNet{IP: addr.IP, Mask: addr.Mask} // deep copy
			addr.IP = ip
			cfg.mainIP = addr
		}

		// the retrieved address must match with the original one
		if ip != cfg.mainIP.String() {
			logger.Errorf("The address retrieved from DHCP (%s) does not match with original address (%s)", ip, cfg.mainIP.String())
			return nil, fmt.Errorf("IP address mismatch")
		}
	} else {
		// static IP -based interface configuration

		// interface IPs
		for _, stnAddr := range stnData.IpAddresses {
			ip, addr, _ := net.ParseCIDR(stnAddr)
			addr.IP = ip

			err = if_vppcalls.AddInterfaceIP(cfg.mainIfIdx, addr, ch, nil)
			if err != nil {
				logger.Errorf("Error by configuring interface IP: %v", err)
				return nil, err
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

			sRoute := &l3_vppcalls.Route{
				DstAddr:     *dstAddr,
				NextHopAddr: nextHopIP,
				OutIface:    cfg.mainIfIdx,
			}
			logger.Debug("Configuring static route: ", sRoute)
			err = l3_vppcalls.VppAddRoute(sRoute, ch, nil)
			if err != nil {
				logger.Errorf("Error by configuring route: %v", err)
				return nil, err
			}
		}
	}

	// interconnect TAP
	tapIdx, err := if_vppcalls.AddTapInterface(
		contiv.TapVPPEndLogicalName,
		&interfaces.Interfaces_Interface_Tap{
			HostIfName: contiv.TapHostEndName,
			Version:    uint32(contivCfg.TAPInterfaceVersion),
		}, ch, nil)
	if err != nil {
		logger.Errorf("Error by adding TAP intrerface: %v", err)
		return nil, err
	}

	err = if_vppcalls.SetInterfaceMac(tapIdx, contiv.HostInterconnectMAC, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the MAC for TAP: %v", err)
		return nil, err
	}

	err = if_vppcalls.SetInterfaceMtu(tapIdx, contivCfg.MTUSize, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the MTU for TAP: %v", cfg.mainIfName, err)
		return nil, err
	}

	err = if_vppcalls.InterfaceAdminUp(tapIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by enabling the TAP intrerface: %v", err)
		return nil, err
	}

	if_vppcalls.SetUnnumberedIP(tapIdx, cfg.mainIfIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the TAP intrerface as unnumbered: %v", err)
		return nil, err
	}

	// interconnect STN
	if_vppcalls.AddStnRule(tapIdx, &cfg.mainIP.IP, ch, nil)
	if err != nil {
		logger.Errorf("Error by adding STN rule: %v", err)
		return nil, err
	}

	// host-end TAP config
	err = if_linuxcalls.AddInterfaceIP(logger, contiv.TapHostEndName, &net.IPNet{IP: cfg.mainIP.IP, Mask: cfg.mainIP.Mask}, nil)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface IP: %v", err)
		return nil, err
	}
	err = if_linuxcalls.SetInterfaceMac(contiv.TapHostEndName, tapHostEndMacAddr, nil)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface MAC: %v", err)
		return nil, err
	}
	err = if_linuxcalls.SetInterfaceMTU(contiv.TapHostEndName, int(contivCfg.MTUSize), nil)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface MTU: %v", err)
		return nil, err
	}

	// TODO: do this using linuxcalls once supported in vpp-agent
	firstIP, lastIP := cidr.AddressRange(cfg.mainIPNet)
	err = enableArpProxy(ch, cidr.Inc(firstIP), cidr.Dec(lastIP), tapIdx)
	if err != nil {
		logger.Errorf("Error by configuring proxy ARP: %v", err)
		return nil, err
	}

	// host routes
	link, err := netlink.LinkByName(contiv.TapHostEndName)
	if err != nil {
		logger.Errorf("Unable to find link %s: %v", contiv.TapHostEndName, err)
		return nil, err
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

		err = l3_linuxcalls.AddStaticRoute(
			fmt.Sprintf("route-to-%s", dstAddr.String()),
			&netlink.Route{
				Dst:       dstAddr,
				Gw:        nextHopIP,
				LinkIndex: link.Attrs().Index,
			},
			logger,
			nil)
		if err != nil {
			logger.Errorf("Error by configuring host route to %s: %v", dstAddr.String(), err)
			return nil, err
		}
	}

	return cfg, nil
}

// persistVppConfig persists VPP configuration in ETCD.
func persistVppConfig(contivCfg *contiv.Config, stnData *stn.STNReply, cfg *vppCfgCtx, useDHCP bool) error {
	etcdConfig := &etcdv3.Config{}

	// parse ETCD config file
	err := config.ParseConfigFromYamlFile(*etcdCfgFile, etcdConfig)
	if err != nil {
		logger.Errorf("Error by parsing config YAML file: %v", err)
		return err
	}

	// prepare ETCD config
	etcdCfg, err := etcdv3.ConfigToClientv3(etcdConfig)
	if err != nil {
		logger.Errorf("Error by constructing ETCD config: %v", err)
		return err
	}

	// connect in retry loop
	var conn *etcdv3.BytesConnectionEtcd
	for i := 0; i < etcdConnectionRetries; i++ {
		conn, err = etcdv3.NewEtcdConnectionWithBytes(*etcdCfg, logger)
		if err != nil {
			if i == etcdConnectionRetries-1 {
				logger.Errorf("Error by connecting to ETCD: %v", err)
				return err
			}
			logger.Debugf("ETCD connection retry n. %d", i+1)
		} else {
			// connected
			break
		}
	}

	protoDb := kvproto.NewProtoWrapperWithSerializer(conn, &keyval.SerializerJSON{})
	pb := protoDb.NewBroker(servicelabel.GetDifferentAgentPrefix(os.Getenv(servicelabel.MicroserviceLabelEnvVar)))
	defer protoDb.Close()

	// persist interface config
	ifCfg := &interfaces.Interfaces_Interface{
		Name:    cfg.mainIfName,
		Type:    interfaces.InterfaceType_ETHERNET_CSMACD,
		Enabled: true,
		Mtu:     contivCfg.MTUSize,
	}
	for _, stnAddr := range stnData.IpAddresses {
		ifCfg.IpAddresses = append(ifCfg.IpAddresses, stnAddr)
	}
	// TODO: re-enable after fixing of resync in vpp-agent
	//if useDHCP {
	//	ifCfg.SetDhcpClient = true
	//}
	err = pb.Put(interfaces.InterfaceKey(ifCfg.Name), ifCfg)
	if err != nil {
		logger.Errorf("Error by persisting the main interface config: %v", err)
		return err
	}

	// persist routes
	for _, stnRoute := range stnData.Routes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		r := &l3.StaticRoutes_Route{
			DstIpAddr:         stnRoute.DestinationSubnet,
			NextHopAddr:       stnRoute.NextHopIp,
			OutgoingInterface: ifCfg.Name,
		}
		if r.DstIpAddr == "" {
			r.DstIpAddr = defaultRouteDestination
		}
		err = pb.Put(l3.RouteKey(r.VrfId, r.DstIpAddr, r.NextHopAddr), r)
		if err != nil {
			logger.Errorf("Error by persisting route config: %v", err)
			return err
		}
	}

	// host interconnect TAP
	tap := &interfaces.Interfaces_Interface{
		Name:    contiv.TapVPPEndLogicalName,
		Type:    interfaces.InterfaceType_TAP_INTERFACE,
		Enabled: true,
		Mtu:     contivCfg.MTUSize,
		Tap: &interfaces.Interfaces_Interface_Tap{
			HostIfName: contiv.TapHostEndName,
			Version:    uint32(contivCfg.TAPInterfaceVersion),
		},
		PhysAddress: contiv.HostInterconnectMAC,
		Unnumbered: &interfaces.Interfaces_Interface_Unnumbered{
			IsUnnumbered:    true,
			InterfaceWithIP: cfg.mainIfName,
		},
	}
	err = pb.Put(interfaces.InterfaceKey(tap.Name), tap)
	if err != nil {
		logger.Errorf("Error by persisting TAP interface config %v", err)
		return err
	}

	// host interconnect STN
	stnRule := &stn_nb.StnRule{
		RuleName:  "VPP-host-STN",
		Interface: contiv.TapVPPEndLogicalName,
		IpAddress: cfg.mainIP.IP.String(),
	}
	err = pb.Put(stn_nb.Key(stnRule.RuleName), stnRule)
	if err != nil {
		logger.Errorf("Error by persisting STN interface config %v", err)
		return err
	}

	// host-end TAP config
	hostTap := &if_linux.LinuxInterfaces_Interface{
		Name:        contiv.TapHostEndLogicalName,
		HostIfName:  contiv.TapHostEndName,
		Type:        if_linux.LinuxInterfaces_AUTO_TAP,
		Enabled:     true,
		Mtu:         contivCfg.MTUSize,
		PhysAddress: tapHostEndMacAddr,
		IpAddresses: []string{cfg.mainIP.String()},
	}
	err = pb.Put(if_linux.InterfaceKey(hostTap.Name), hostTap)
	if err != nil {
		logger.Errorf("Error by persisting host-end TAP interface config %v", err)
		return err
	}

	// host routes
	for _, stnRoute := range stnData.Routes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		route := &l3_linux.LinuxStaticRoutes_Route{
			Name:      fmt.Sprintf("route-to-%s", stnRoute.DestinationSubnet),
			DstIpAddr: stnRoute.DestinationSubnet,
			GwAddr:    stnRoute.NextHopIp,
			Interface: contiv.TapHostEndName, // in case of linux interface, this needs to be HostIfName
		}
		if route.DstIpAddr == "" {
			route.Name = fmt.Sprintf("route-to-%s", defaultRouteDestination)
			route.DstIpAddr = defaultRouteDestination
			route.Default = true
		}
		err = pb.Put(l3_linux.StaticRouteKey(route.Name), route)
		if err != nil {
			logger.Errorf("Error by persisting TAP interface config %v", err)
			return err
		}
	}

	return nil
}

// findHwInterfaceIdx finds index & name of the first available hardware NIC.
func findHwInterfaceIdx(ch *api.Channel) (uint32, string, error) {
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

// enableArpProxy enables ARP proxy on specified interface on VPP.
func enableArpProxy(ch *api.Channel, loAddr net.IP, hiAddr net.IP, ifIdx uint32) error {

	logger.Debugf("Enabling ARP proxy for IP range %s - %s, ifIdx %d", loAddr.String(), hiAddr.String(), ifIdx)

	// configure proxy arp pool
	req := &ip_binapi.ProxyArpAddDel{
		VrfID:      0,
		IsAdd:      1,
		LowAddress: []byte(loAddr.To4()),
		HiAddress:  []byte(hiAddr.To4()),
	}
	reply := &ip_binapi.ProxyArpAddDelReply{}

	err := ch.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return err
	}

	// enable proxy ARP on the interface
	req2 := &ip_binapi.ProxyArpIntfcEnableDisable{
		SwIfIndex:     ifIdx,
		EnableDisable: 1,
	}
	reply2 := &ip_binapi.ProxyArpIntfcEnableDisableReply{}

	err = ch.SendRequest(req2).ReceiveReply(reply2)
	if err != nil {
		return err
	}

	return nil
}

// configureDHCP configures DHCP on an interface on VPP. Returns Go channel where assigned IP will be delivered.
func configureDHCP(ch *api.Channel, ifIdx uint32) (chan string, error) {
	dhcpNotifChan := make(chan api.Message)
	dhcpIPChan := make(chan string)

	logger.Debugf("Enabling DHCP on the interface idx %d", ifIdx)

	// subscribe for the DHCP notifications from VPP
	_, err := ch.SubscribeNotification(dhcpNotifChan, dhcp.NewDhcpComplEvent)
	if err != nil {
		return nil, err
	}

	req := &dhcp.DhcpClientConfig{
		SwIfIndex:     ifIdx,
		IsAdd:         1,
		WantDhcpEvent: 1,
	}
	reply := &dhcp.DhcpClientConfigReply{}

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
			case *dhcp.DhcpComplEvent:
				var ipAddr string
				if notif.IsIpv6 == 1 {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(notif.HostAddress).To16().String(), notif.MaskWidth)
				} else {
					ipAddr = fmt.Sprintf("%s/%d", net.IP(notif.HostAddress[:4]).To4().String(), notif.MaskWidth)
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
