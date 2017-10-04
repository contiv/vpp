// Copyright (c) 2017 Cisco and/or its affiliates.
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
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"

	cnisb "github.com/containernetworking/cni/pkg/types/current"
	cninb "github.com/contiv/vpp/plugins/contiv/model/cni"
)

type CNIConfig struct {
	// common CNI config
	types.NetConf

	// previous result, when called in the context of a chained plugin
	PrevResult *map[string]interface{} `json:"prevResult"`

	// plugin-specific config
	GrpcServer string `json:"grpcServer"`
}

func loadCNIConfig(bytes []byte) (*CNIConfig, error) {
	// unmarshall the config
	conf := &CNIConfig{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to load plugin config: %v", err)
	}

	// CNI chaining is not supported by this plugin, print out an error in case it was chained
	if conf.PrevResult != nil {
		return nil, fmt.Errorf("CNI chaining is not supported by this plugin")
	}

	// grpcServer is mandatory
	if conf.GrpcServer == "" {
		return nil, fmt.Errorf(`"grpcServer" field is required. It specifies where the CNI requests should be forwarded to`)
	}

	return conf, nil
}

func grpcConnect(grpcServer string) (*grpc.ClientConn, cninb.RemoteCNIClient, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(grpcServer, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	return conn, cninb.NewRemoteCNIClient(conn), nil
}

func cmdAdd(args *skel.CmdArgs) error {
	// load CNI config
	cfg, err := loadCNIConfig(args.StdinData)
	if err != nil {
		return err
	}

	// connect to remote CNI handler over gRPC
	conn, c, err := grpcConnect(cfg.GrpcServer)
	if err != nil {
		return err
	}
	defer conn.Close()

	// execute the ADD request
	r, err := c.Add(context.Background(), &cninb.CNIRequest{
		Version:          cfg.CNIVersion,
		ContainerId:      args.ContainerID,
		InterfaceName:    args.IfName,
		NetworkNamespace: args.Netns,
	})
	if err != nil {
		return err
	}

	// process the reply from the remote CNI handler
	result := &cnisb.Result{
		CNIVersion: cfg.CNIVersion,
	}

	// process interfaces
	for ifidx, iface := range r.Interfaces {
		// append interface info
		result.Interfaces = append(result.Interfaces, &cnisb.Interface{
			Name:    iface.Name,
			Mac:     iface.Mac,
			Sandbox: iface.Sandbox,
		})
		for _, ip := range iface.IpAddresses {
			// append interface ip address info
			_, ipAddr, err := net.ParseCIDR(ip.Address)
			if err != nil {
				return err
			}
			var gwAddr net.IP
			if ip.Gateway != "" {
				gwAddr = net.ParseIP(ip.Gateway)
				if err != nil {
					return err
				}
			}
			version := "4"
			if ip.Version == cninb.CNIReply_Interface_IP_IPV6 {
				version = "6"
			}
			result.IPs = append(result.IPs, &cnisb.IPConfig{
				Address:   *ipAddr,
				Version:   version,
				Interface: &ifidx,
				Gateway:   gwAddr,
			})
		}
	}

	// process routes
	for _, route := range r.Routes {
		_, dstIP, err := net.ParseCIDR(route.Dst)
		if err != nil {
			return err
		}
		gwAddr := net.ParseIP(route.Gw)
		if err != nil {
			return err
		}
		result.Routes = append(result.Routes, &types.Route{
			Dst: *dstIP,
			GW:  gwAddr,
		})
	}

	// process DNS entry
	for _, dns := range r.Dns {
		result.DNS.Nameservers = dns.Nameservers
		result.DNS.Domain = dns.Domain
		result.DNS.Search = dns.Search
		result.DNS.Options = dns.Options
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	// load CNI config
	n, err := loadCNIConfig(args.StdinData)
	if err != nil {
		return err
	}

	// connect to remote CNI handler over gRPC
	conn, c, err := grpcConnect(n.GrpcServer)
	if err != nil {
		return err
	}
	defer conn.Close()

	// execute the DELETE request
	_, err = c.Delete(context.Background(), &cninb.CNIRequest{
		Version:          n.CNIVersion,
		ContainerId:      args.ContainerID,
		InterfaceName:    args.IfName,
		NetworkNamespace: args.Netns,
	})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// execute the CNI plugin
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
