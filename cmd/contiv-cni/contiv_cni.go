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
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"

	cnisb "github.com/containernetworking/cni/pkg/types/current"
	cninb "github.com/contiv/vpp/plugins/contiv/model/cni"
)

// cniConfig represents the CNI configuration, usually located in the /etc/cni/net.d/
// folder, automatically picked by the executor of the CNI plugin and passed in via the standard input.
type cniConfig struct {
	// common CNI config
	types.NetConf

	// PrevResult contains previous plugin's result, used only when called in the context of a chained plugin.
	PrevResult *map[string]interface{} `json:"prevResult"`

	// GrpcServer is a plugin-specific config, contains location of the gRPC server
	// where the CNI requests are being forwarded to (server:port tuple, e.g. "localhost:9111")
	// or unix-domain socket path (e.g. "/run/cni.sock").
	GrpcServer string `json:"grpcServer"`
}

// parseCNIConfig parses CNI config from JSON (in bytes) to cniConfig struct.
func parseCNIConfig(bytes []byte) (*cniConfig, error) {
	// unmarshal the config
	conf := &cniConfig{}
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

// grpcConnect sets up a connection to the gRPC server specified in grpcServer argument
// as a server:port tuple (e.g. "localhost:9111") or unix-domain socket path (e.g. "/run/cni.sock").
func grpcConnect(grpcServer string) (conn *grpc.ClientConn, cni cninb.RemoteCNIClient, err error) {

	if grpcServer != "" && grpcServer[0] == '/' {
		// unix-domain socket connection
		conn, err = grpc.Dial(
			grpcServer,
			grpc.WithInsecure(),
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
		)
	} else {
		// TCP socket connection
		conn, err = grpc.Dial(grpcServer, grpc.WithInsecure())
	}

	if err != nil {
		return
	}
	cni = cninb.NewRemoteCNIClient(conn)
	return
}

// cmdAdd implements the CNI request to add a container to network.
// It forwards the request to he remote gRPC server and prints the result received from gRPC.
func cmdAdd(args *skel.CmdArgs) error {
	// parse CNI config
	cfg, err := parseCNIConfig(args.StdinData)
	if err != nil {
		return err
	}

	// connect to the remote CNI handler over gRPC
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
		ExtraArguments:   args.Args,
		ExtraNwConfig:    string(args.StdinData),
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
			ver := "4"
			if ip.Version == cninb.CNIReply_Interface_IP_IPV6 {
				ver = "6"
			}
			result.IPs = append(result.IPs, &cnisb.IPConfig{
				Address:   *ipAddr,
				Version:   ver,
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

// cmdDel implements the CNI request to delete a container from network.
// It forwards the request to he remote gRPC server and returns the result received from gRPC.
func cmdDel(args *skel.CmdArgs) error {
	// parse CNI config
	n, err := parseCNIConfig(args.StdinData)
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
		ExtraArguments:   args.Args,
		ExtraNwConfig:    string(args.StdinData),
	})
	if err != nil {
		return err
	}

	return nil
}

// main routine of the CNI plugin
func main() {
	// execute the CNI plugin logic
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
