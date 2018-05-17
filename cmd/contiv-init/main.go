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
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghodss/yaml"
	"github.com/nerdtakula/supervisor"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv"
	"strings"
)

const (
	defaultContivCfgFile  = "/etc/agent/contiv.yaml"
	defaultEtcdCfgFile    = "/etc/etcd/etcd.conf"
	defaultSupervisorPort = 9001
	defaultStnServerPort  = 50051

	vppProcessName         = "vpp"
	contivAgentProcessName = "contiv-agent"
)

var (
	contivCfgFile  = flag.String("contiv-config", defaultContivCfgFile, "location of the contiv-agent config file")
	etcdCfgFile    = flag.String("etcd-config", defaultEtcdCfgFile, "location of the ETCD config file")
	supervisorPort = flag.Int("supervisor-port", defaultSupervisorPort, "management port of the supervisor process")
	stnServerPort  = flag.Int("stn-server-port", defaultStnServerPort, "port where STN GRPC server listens for connections")
)

var logger logging.Logger // global logger

// init initializes the global logger
func init() {
	logger = logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
}

// stealNIC requests stealing the specified NIC from the STN GRPC server.
func stealNIC(nicName string, useDHCP bool) (*stn.STNReply, error) {
	logger.Debugf("Stealing the NIC: %s", nicName)

	// connect to STN GRPC server
	conn, err := grpc.Dial(fmt.Sprintf(":%d", *stnServerPort), grpc.WithInsecure())
	if err != nil {
		logger.Errorf("Unable to connect to STN GRPC: %v", err)
		return nil, err
	}
	defer conn.Close()
	c := stn.NewSTNClient(conn)

	// request stealing the interface
	reply, err := c.StealInterface(context.Background(), &stn.STNRequest{
		InterfaceName: nicName,
		DhcpEnabled:   useDHCP,
	})
	if err != nil {
		logger.Errorf("Error by executing STN GRPC: %v", err)
		return nil, err
	}

	logger.Debug(reply)
	return reply, nil
}

// releaseNIC requests reverting the specified NIC to its original state using the STN GRPC server.
func releaseNIC(nicName string, useDHCP bool) error {
	logger.Debugf("Releasing the NIC: %s", nicName)

	// connect to STN GRPC server
	conn, err := grpc.Dial(fmt.Sprintf(":%d", *stnServerPort), grpc.WithInsecure())
	if err != nil {
		logger.Errorf("Unable to connect to STN GRPC: %v", err)
		return err
	}
	defer conn.Close()
	c := stn.NewSTNClient(conn)

	// request release of the interface
	reply, err := c.ReleaseInterface(context.Background(), &stn.STNRequest{
		InterfaceName: nicName,
		DhcpEnabled:   useDHCP,
	})
	if err != nil {
		logger.Errorf("Error by executing STN GRPC: %v", err)
		return err
	}

	logger.Debug(reply)
	return nil
}

// parseSTNConfig parses the config file and looks up for STN configuration.
// In case that STN was requested for this node, returns the interface to be stolen and optionally its name on VPP.
func parseSTNConfig() (config *contiv.Config, nicToSteal string, useDHCP bool, err error) {

	// read config YAML
	yamlFile, err := ioutil.ReadFile(*contivCfgFile)
	if err != nil {
		logger.Errorf("Error by reading config file %s: %v", *contivCfgFile, err)
		return
	}

	// unmarshal the YAML
	config = &contiv.Config{}
	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		logger.Errorf("Error by unmarshalling YAML: %v", err)
		return
	}
	if config.TAPInterfaceVersion == 0 {
		config.TAPInterfaceVersion = 2 // default
	}

	// try to find node config and return STN interface name if found
	nodeName := os.Getenv(servicelabel.MicroserviceLabelEnvVar)
	logger.Debugf("Looking for node '%s' specific config", nodeName)

	if config.IPAMConfig.NodeInterconnectDHCP == true {
		useDHCP = true
	}

	// look for node-specific config first
	for _, nc := range config.NodeConfig {
		if nc.NodeName == nodeName {
			nicToSteal = nc.StealInterface
			if nicToSteal != "" {
				logger.Debugf("Found interface to be stolen: %s", nc.StealInterface)
				if nc.MainVPPInterface.UseDHCP == true {
					useDHCP = true
				}
			}
			break
		}
	}

	// global config - interface name
	if nicToSteal == "" && config.StealInterface != "" {
		nicToSteal = config.StealInterface
		logger.Debugf("Found interface to be stolen: %s", nicToSteal)
	}

	// global config - first interface
	if nicToSteal == "" && config.StealFirstNIC {
		// the first NIC will be stolen
		nicToSteal = getFirstInterfaceName()
		if nicToSteal != "" {
			logger.Infof("No specific NIC to steal specified, stealing the first one: %s", nicToSteal)
		}
	}

	return
}

// getFirstInterfaceName returns the name of the first non-virtual Linux interface
func getFirstInterfaceName() string {
	// list existing links
	links, err := netlink.LinkList()
	if err != nil {
		logger.Error("Unable to list links:", err)
		return ""
	}

	// find link to steal
	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") &&
			!strings.HasPrefix(l.Attrs().Name, "vir") &&
			!strings.HasPrefix(l.Attrs().Name, "docker") {
			return l.Attrs().Name
		}
	}
	return ""
}

func main() {
	flag.Parse()

	logger.Debugf("Starting contiv-init process")

	// check whether STN is required and get NIC name
	contivCfg, nicToSteal, useDHCP, err := parseSTNConfig()
	if err != nil {
		logger.Errorf("Error by parsing STN config: %v", err)
		os.Exit(-1)
	}

	var stnData *stn.STNReply
	if nicToSteal != "" {
		// steal the NIC
		stnData, err = stealNIC(nicToSteal, useDHCP)
		if err != nil {
			logger.Warnf("Error by stealing the NIC %s: %v", nicToSteal, err)
			// do not fail of STN was not successful
			nicToSteal = ""
		}
	} else {
		logger.Debug("STN not requested")
	}

	// connect to supervisor API
	client := supervisor.New("localhost", *supervisorPort, "", "")

	// start VPP
	logger.Debug("Starting VPP")
	_, err = client.StartProcess(vppProcessName, false)
	if err != nil {
		logger.Errorf("Error by starting VPP process: %v", err)
		os.Exit(-1)
	}

	if nicToSteal != "" {
		// configure connectivity on VPP
		vppCfg, err := configureVpp(contivCfg, stnData, useDHCP)
		if err != nil {
			logger.Errorf("Error by configuring VPP: %v", err)
			client.StopProcess(vppProcessName, false)
			os.Exit(-1)
		}

		// persist VPP config in ETCD
		err = persistVppConfig(contivCfg, stnData, vppCfg, useDHCP)
		if err != nil {
			logger.Errorf("Error by persisting VPP config in ETCD: %v", err)
			client.StopProcess(vppProcessName, false)
			os.Exit(-1)
		}
	}

	// start contiv-agent
	logger.Debugf("Starting contiv-agent")
	_, err = client.StartProcess(contivAgentProcessName, false)
	if err != nil {
		logger.Errorf("Error by starting contiv-agent process: %v", err)
		client.StopProcess(vppProcessName, false)
		os.Exit(-1)
	}

	// wait until SIGINT/SIGTERM signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	logger.Debugf("%v signal received, exiting", sig)

	// request releasing the NIC
	if nicToSteal != "" {
		releaseNIC(nicToSteal, useDHCP)
	}
}
