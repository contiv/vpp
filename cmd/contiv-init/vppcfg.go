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
	"net"
	"os"
	"strings"

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/servicelabel"

	if_binapi "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	if_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/vppcalls"
	l3_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/vppcalls"

	govpp "git.fd.io/govpp.git"
	"git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

type vppCfgCtx struct {
	mainIfIdx  uint32
	mainIfName string
}

// configureVpp configures main interface and vpp-host interconnect based on provided STN information.
func configureVpp(stnData *stn.STNReply, vppIfName string) (*vppCfgCtx, error) {
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

	// interface up
	err = if_vppcalls.InterfaceAdminUp(cfg.mainIfIdx, ch, nil)
	if err != nil {
		logger.Errorf("Error by enabling the intrerface %s: %v", cfg.mainIfName, err)
		return nil, err
	}

	// interface IPs
	for _, stnAddr := range stnData.IpAddresses {
		ip, addr, _ := net.ParseCIDR(stnAddr)
		addr.IP = ip

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

	// TODO: host interconnect + STN + host config + host routes

	return cfg, nil
}

// persistVppConfig persists VPP configuration in ETCD.
func persistVppConfig(stnData *stn.STNReply, cfg *vppCfgCtx) error {
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
		logger.Errorf("Error by configuring the main interface on VPP: %v", err)
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
			logger.Errorf("Error by configuring route on VPP: %v", err)
			return err
		}
	}

	// TODO: host interconnect + STN

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
