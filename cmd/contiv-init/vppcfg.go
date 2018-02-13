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
	"fmt"
	"net"
	"os"

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
	if_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/vppcalls"
	l3_vppcalls "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/vppcalls"

	govpp "git.fd.io/govpp.git"
	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

func configureVpp(stnData *stn.STNReply, vppIfName string) error {
	// connect to VPP
	conn, err := govpp.Connect()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer conn.Disconnect()

	// create an API channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer ch.Close()

	// TODO: determine if idx
	ifIdx := uint32(1)

	// interface up
	err = if_vppcalls.InterfaceAdminUp(ifIdx, ch, nil)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// interface IPs
	for _, stnAddr := range stnData.IpAddresses {
		ip, addr, _ := net.ParseCIDR(stnAddr)
		addr.IP = ip

		err = if_vppcalls.AddInterfaceIP(ifIdx, addr, logger, ch, nil)
		if err != nil {
			fmt.Println("Error:", err)
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
			OutIface:    ifIdx,
		}, ch, nil)
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	// TODO: host interconnect + STN + host config + host routes

	return nil
}

func persistVppConfig(stnData *stn.STNReply) error {
	etcdConfig := &etcdv3.Config{}

	err := config.ParseConfigFromYamlFile(*etcdCfgFile, etcdConfig)
	if err != nil {
		fmt.Println("Error:", err)
	}

	cfg, err := etcdv3.ConfigToClientv3(etcdConfig)
	if err != nil {
		fmt.Println("Error:", err)
	}
	db, err := etcdv3.NewEtcdConnectionWithBytes(*cfg, logger)
	if err != nil {
		fmt.Println("Error:", err)
	}
	protoDb := kvproto.NewProtoWrapperWithSerializer(db, &keyval.SerializerJSON{})
	defer protoDb.Close()

	pb := protoDb.NewBroker(servicelabel.GetDifferentAgentPrefix(os.Getenv(servicelabel.MicroserviceLabelEnvVar)))

	// persist interface config
	ifCfg := &interfaces.Interfaces_Interface{
		Name:    "GigabitEthernet0/9/0", // TODO
		Type:    interfaces.InterfaceType_ETHERNET_CSMACD,
		Enabled: true,
	}
	for _, stnAddr := range stnData.IpAddresses {
		ifCfg.IpAddresses = append(ifCfg.IpAddresses, stnAddr)
	}
	err = pb.Put(interfaces.InterfaceKey(ifCfg.Name), ifCfg)
	if err != nil {
		fmt.Println("Error:", err)
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
			fmt.Println("Error:", err)
		}
	}

	// TODO: host interconnect + STN

	return nil
}
