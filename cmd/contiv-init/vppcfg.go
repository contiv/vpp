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

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/servicelabel"

	govpp "git.fd.io/govpp.git"
	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv"
	if_binapi "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/interfaces"
	ip_binapi "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/ip"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	stn_nb "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/stn"
	if_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/vppcalls"
	l3_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/vppcalls"
	if_linux "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/interfaces"
	l3_linux "github.com/ligato/vpp-agent/plugins/linuxplugin/common/model/l3"
	if_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/linuxcalls"
	l3_linuxcalls "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/linuxcalls"
	"github.com/vishvananda/netlink"
)

const (
	tapHostEndName        = "vpp1"
	tapHostEndLogicalName = "tap-vpp1"
	tapHostEndMacAddr     = "00:00:00:00:00:02" // requirement of the VPP STN plugin

	tapVPPEndName        = "vpp2"
	tapVPPEndLogicalName = "tap-vpp2"
)

type vppCfgCtx struct {
	mainIfIdx  uint32
	mainIfName string
	mainIPNet  *net.IPNet
	mainIP     *net.IPNet
}

// configureVpp configures main interface and vpp-host interconnect based on provided STN information.
func configureVpp(contivCfg *contiv.Config, stnData *stn.STNReply, vppIfName string) (*vppCfgCtx, error) {
	var err error

	// connect to VPP
	conn, err := govpp.Connect()
	if err != nil {
		logger.Errorf("Error by connecting to VPP: %v", err)
		return nil, err
	}
	defer conn.Disconnect()

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

	// interface up
	err = if_vppcalls.InterfaceAdminUp(cfg.mainIfIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by enabling the interface %s: %v", cfg.mainIfName, err)
		return nil, err
	}

	// interface IPs
	for _, stnAddr := range stnData.IpAddresses {
		ip, addr, _ := net.ParseCIDR(stnAddr)
		cfg.mainIPNet = &net.IPNet{IP: addr.IP, Mask: addr.Mask} // deep copy
		addr.IP = ip
		cfg.mainIP = addr

		err = if_vppcalls.AddInterfaceIP(cfg.mainIfIdx, addr, logger, ch, nil)
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
		dstIP, dstAddr, _ := net.ParseCIDR(stnRoute.DestinationSubnet)
		dstAddr.IP = dstIP
		nextHopIP := net.ParseIP(stnRoute.NextHopIp)

		err = l3_vppcalls.VppAddRoute(&l3_vppcalls.Route{
			DstAddr:     *dstAddr,
			NextHopAddr: nextHopIP,
			OutIface:    cfg.mainIfIdx,
		}, ch, nil)
		if err != nil {
			logger.Errorf("Error by configuring route: %v", err)
			return nil, err
		}
	}

	// interconnect TAP
	tapIdx, err := if_vppcalls.AddTapInterface(
		tapVPPEndLogicalName,
		&interfaces.Interfaces_Interface_Tap{
			HostIfName: tapHostEndName,
			Version:    uint32(contivCfg.TAPInterfaceVersion),
		}, ch, nil)
	if err != nil {
		logger.Errorf("Error by adding TAP intrerface: %v", err)
		return nil, err
	}

	err = if_vppcalls.InterfaceAdminUp(tapIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by enabling the TAP intrerface: %v", err)
		return nil, err
	}

	if_vppcalls.SetUnnumberedIP(tapIdx, cfg.mainIfIdx, logger, ch, nil)
	if err != nil {
		logger.Errorf("Error by setting the TAP intrerface as unnumbered: %v", err)
		return nil, err
	}

	// interconnect STN
	if_vppcalls.AddStnRule(tapIdx, &cfg.mainIP.IP, logger, ch, nil)
	if err != nil {
		logger.Errorf("Error by adding STN rule: %v", err)
		return nil, err
	}

	// host-end TAP config
	err = if_linuxcalls.AddInterfaceIP(logger, tapHostEndName, &net.IPNet{IP: cfg.mainIP.IP, Mask: cfg.mainIP.Mask}, nil)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface IP: %v", err)
		return nil, err
	}
	err = if_linuxcalls.SetInterfaceMac(tapHostEndName, tapHostEndMacAddr, nil)
	if err != nil {
		logger.Errorf("Error by configuring host-end TAP interface MAC: %v", err)
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
	link, err := netlink.LinkByName(tapHostEndName)
	if err != nil {
		logger.Errorf("Unable to find link %s: %v", tapHostEndName, err)
		return nil, err
	}
	for _, stnRoute := range stnData.Routes {
		if stnRoute.NextHopIp == "" {
			continue // skip routes with no next hop IP (link-local)
		}
		dstIP, dstAddr, _ := net.ParseCIDR(stnRoute.DestinationSubnet)
		dstAddr.IP = dstIP
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
func persistVppConfig(contivCfg *contiv.Config, stnData *stn.STNReply, cfg *vppCfgCtx) error {
	etcdConfig := &etcdv3.Config{}

	// parse ETCD config file
	err := config.ParseConfigFromYamlFile(*etcdCfgFile, etcdConfig)
	if err != nil {
		logger.Errorf("Error by parsing config YAML file: %v", err)
		return err
	}

	// connect to ETCD
	etcdCfg, err := etcdv3.ConfigToClientv3(etcdConfig)
	if err != nil {
		logger.Errorf("Error by constructing ETCD config: %v", err)
		return err
	}
	db, err := etcdv3.NewEtcdConnectionWithBytes(*etcdCfg, logger)
	if err != nil {
		logger.Errorf("Error by connecting to ETCD: %v", err)
		return err
	}
	protoDb := kvproto.NewProtoWrapperWithSerializer(db, &keyval.SerializerJSON{})
	pb := protoDb.NewBroker(servicelabel.GetDifferentAgentPrefix(os.Getenv(servicelabel.MicroserviceLabelEnvVar)))
	defer protoDb.Close()

	// persist interface config
	ifCfg := &interfaces.Interfaces_Interface{
		Name:    cfg.mainIfName,
		Type:    interfaces.InterfaceType_ETHERNET_CSMACD,
		Enabled: true,
	}
	for _, stnAddr := range stnData.IpAddresses {
		ifCfg.IpAddresses = append(ifCfg.IpAddresses, stnAddr)
	}
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
		err = pb.Put(l3.RouteKey(r.VrfId, r.DstIpAddr, r.NextHopAddr), r)
		if err != nil {
			logger.Errorf("Error by persisting route config: %v", err)
			return err
		}
	}

	// host interconnect TAP
	tap := &interfaces.Interfaces_Interface{
		Name:    tapVPPEndLogicalName,
		Type:    interfaces.InterfaceType_TAP_INTERFACE,
		Enabled: true,
		Tap: &interfaces.Interfaces_Interface_Tap{
			HostIfName: tapHostEndName,
			Version:    uint32(contivCfg.TAPInterfaceVersion),
		},
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
		Interface: tapVPPEndLogicalName,
		IpAddress: cfg.mainIP.IP.String(),
	}
	err = pb.Put(stn_nb.Key(stnRule.RuleName), stnRule)
	if err != nil {
		logger.Errorf("Error by persisting STN interface config %v", err)
		return err
	}

	// host-end TAP config
	hostTap := &if_linux.LinuxInterfaces_Interface{
		Name:        tapHostEndLogicalName,
		HostIfName:  tapHostEndName,
		Type:        if_linux.LinuxInterfaces_AUTO_TAP,
		Enabled:     true,
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
			Interface: tapHostEndLogicalName,
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
