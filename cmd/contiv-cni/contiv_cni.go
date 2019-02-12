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
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"

	cnisb "github.com/containernetworking/cni/pkg/types/current"
	cninb "github.com/contiv/vpp/plugins/podmanager/cni"
	log "github.com/sirupsen/logrus"
)

const defaultLogFile = "/tmp/contiv-cni.log"

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

	// LogFile is a plugin-specific config, specifies location of the CNI plugin log file.
	// If empty, plugin logs into defaultLogFile.
	LogFile string `json:"logFile"`

	// EtcdEndpoints is a plugin-specific config, may contain comma-separated list of ETCD endpoints
	// required for specific for the CNI / IPAM plugin.
	EtcdEndpoints string `json:"etcdEndpoints"`
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

// initLog initializes logging into the specified file
func initLog(fileName string) error {
	if fileName == "" {
		fileName = defaultLogFile
	}
	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	log.SetOutput(f)
	log.SetLevel(log.DebugLevel)
	return nil
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
	start := time.Now()

	// parse CNI config
	cfg, err := parseCNIConfig(args.StdinData)
	if err != nil {
		log.Errorf("Unable to parse CNI config: %v", err)
		return err
	}

	// init the logger
	err = initLog(cfg.LogFile)
	if err != nil {
		log.Errorf("Unable to initialize logging: %v", err)
		return err
	}
	log.WithFields(log.Fields{
		"ContainerID": args.ContainerID,
		"Netns":       args.Netns,
		"IfName":      args.IfName,
		"Args":        args.Args,
	}).Debug("CNI ADD request")

	// prepare CNI request
	cniRequest := &cninb.CNIRequest{
		Version:          cfg.CNIVersion,
		ContainerId:      args.ContainerID,
		InterfaceName:    args.IfName,
		NetworkNamespace: args.Netns,
		ExtraArguments:   args.Args,
		ExtraNwConfig:    string(args.StdinData),
	}
	cniResult := &cnisb.Result{
		CNIVersion: cfg.CNIVersion,
	}

	// call external IPAM if provided
	if cfg.IPAM.Type != "" {
		cniRequest.IpamType = cfg.IPAM.Type
		cniRequest.IpamData, err = execIPAMAdd(cfg, args.StdinData)
		if err != nil {
			log.Errorf("IPAM plugin %s ADD returned an error: %v", cfg.IPAM.Type, err)
			return err
		}

		// Invoke IPAM DEL in case of error to avoid IP leak
		defer func() {
			if cniResult.Interfaces == nil || len(cniResult.Interfaces) == 0 {
				execIPAMDel(cfg, args.StdinData)
			}
		}()
	}

	// connect to the remote CNI handler over gRPC
	conn, c, err := grpcConnect(cfg.GrpcServer)
	if err != nil {
		log.Errorf("Unable to connect to GRPC server %s: %v", cfg.GrpcServer, err)
		return err
	}
	defer conn.Close()

	// execute the remote ADD request
	r, err := c.Add(context.Background(), cniRequest)
	if err != nil {
		log.Errorf("Error by executing remote CNI Add request: %v", err)
		return err
	}

	// process interfaces
	for ifidx, iface := range r.Interfaces {
		// append interface info
		cniResult.Interfaces = append(cniResult.Interfaces, &cnisb.Interface{
			Name:    iface.Name,
			Mac:     iface.Mac,
			Sandbox: iface.Sandbox,
		})
		for _, ip := range iface.IpAddresses {
			// append interface ip address info
			_, ipAddr, err := net.ParseCIDR(ip.Address)
			if err != nil {
				log.Error(err)
				return err
			}
			var gwAddr net.IP
			if ip.Gateway != "" {
				gwAddr = net.ParseIP(ip.Gateway)
				if err != nil {
					log.Error(err)
					return err
				}
			}
			ver := "4"
			if ip.Version == cninb.CNIReply_Interface_IP_IPV6 {
				ver = "6"
			}
			cniResult.IPs = append(cniResult.IPs, &cnisb.IPConfig{
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
			log.Error(err)
			return err
		}
		gwAddr := net.ParseIP(route.Gw)
		if err != nil {
			log.Error(err)
			return err
		}
		cniResult.Routes = append(cniResult.Routes, &types.Route{
			Dst: *dstIP,
			GW:  gwAddr,
		})
	}

	// process DNS entry
	for _, dns := range r.Dns {
		cniResult.DNS.Nameservers = dns.Nameservers
		cniResult.DNS.Domain = dns.Domain
		cniResult.DNS.Search = dns.Search
		cniResult.DNS.Options = dns.Options
	}

	log.WithFields(log.Fields{"Result": cniResult}).Debugf("CNI ADD request OK, took %s", time.Since(start))

	return cniResult.Print()
}

// cmdDel implements the CNI request to delete a container from network.
// It forwards the request to he remote gRPC server and returns the result received from gRPC.
func cmdDel(args *skel.CmdArgs) error {
	start := time.Now()

	// parse CNI config
	cfg, err := parseCNIConfig(args.StdinData)
	if err != nil {
		log.Errorf("Unable to parse CNI config: %v", err)
		return err
	}

	err = initLog(cfg.LogFile)
	if err != nil {
		log.Errorf("Unable to initialize logging: %v", err)
		return err
	}
	log.WithFields(log.Fields{
		"ContainerID": args.ContainerID,
		"Netns":       args.Netns,
		"IfName":      args.IfName,
		"Args":        args.Args,
	}).Debug("CNI DEL request")

	// connect to remote CNI handler over gRPC
	conn, c, err := grpcConnect(cfg.GrpcServer)
	if err != nil {
		log.Errorf("Unable to connect to GRPC server %s: %v", cfg.GrpcServer, err)
		return err
	}
	defer conn.Close()

	// execute the DELETE request
	_, err = c.Delete(context.Background(), &cninb.CNIRequest{
		Version:          cfg.CNIVersion,
		ContainerId:      args.ContainerID,
		InterfaceName:    args.IfName,
		NetworkNamespace: args.Netns,
		ExtraArguments:   args.Args,
		ExtraNwConfig:    string(args.StdinData),
	})
	if err != nil {
		log.Errorf("Error by executing remote CNI Delete request: %v", err)
		return err
	}

	// execute DELETE on external IPAM plugin, if provided
	if cfg.IPAM.Type != "" {
		err = execIPAMDel(cfg, args.StdinData)
		if err != nil {
			log.Errorf("IPAM plugin %s: DEL returned an error: %v", cfg.IPAM.Type, err)
			return err
		}
	}

	log.Debugf("CNI DEL request OK, took %s", time.Since(start))

	return nil
}

// main routine of the CNI plugin
func main() {
	// execute the CNI plugin logic
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
