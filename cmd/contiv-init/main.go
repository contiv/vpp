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
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/namsral/flag"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/bolt"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/processmanager"
	"github.com/ligato/cn-infra/processmanager/status"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/pkg/pci"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/controller"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/nodesync/vppnode"
)

const (
	vppProcessName       = "vpp"
	defaultVppBinaryPath = "/usr/bin/vpp"
	vppStartupConfigPath = "/etc/vpp/contiv-vswitch.conf"

	agentProcessName       = "contiv-agent"
	defaultAgentBinaryPath = "/usr/bin/contiv-agent"

	defaultEtcdCfgFile     = "/etc/etcd/etcd.conf"
	defaultBoltCfgFile     = "/etc/vpp-agent/bolt.conf"
	defaultStnServerSocket = "/var/run/contiv/stn.sock"
	defaultCNISocketFile   = "/var/run/contiv/cni.sock"

	etcdConnectionRetries = 2 // number of retries to connect to ETCD

	vmxnet3PreferredDriver = "vfio-pci" // driver required for vmxnet3 interfaces
)

var (
	vppBinaryPath   = flag.String("vpp-bin", defaultVppBinaryPath, "location of the VPP binary")
	agentBinaryPath = flag.String("agent-bin", defaultAgentBinaryPath, "location of the Contiv Agent binary")

	etcdCfgFile     = flag.String("etcd-config", defaultEtcdCfgFile, "location of the ETCD config file")
	boltCfgFile     = flag.String("bolt-config", defaultBoltCfgFile, "location of the Bolt config file")
	stnServerSocket = flag.String("stn-server-socket", defaultStnServerSocket, "socket file where STN GRPC server listens for connections")
)

var logger logging.Logger // global logger

// init initializes the global logger
func init() {
	logger = logrus.NewLogger("contiv-init")
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logging.DebugLevel)
}

// stealNIC requests stealing the specified NIC from the STN GRPC server.
func stealNIC(nicName string, useDHCP bool) (*stn.STNReply, error) {
	logger.Debugf("Stealing the NIC: %s", nicName)

	// connect to STN GRPC server
	conn, err := stnGrpcConnect()
	if err != nil {
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
	conn, err := stnGrpcConnect()
	if err != nil {
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

// grpcConnect connects to STN GRPC server.
func stnGrpcConnect() (*grpc.ClientConn, error) {
	dialer := grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("unix", addr, timeout)
	})

	conn, err := grpc.Dial(*stnServerSocket, grpc.WithInsecure(), dialer)
	if err != nil {
		logger.Errorf("Unable to connect to STN GRPC: %v", err)
		return nil, err
	}

	return conn, nil
}

// etcdWithAtomicPut augments ProtoWrapper with atomic Put operation.
type etcdWithAtomicPut struct {
	*kvproto.ProtoWrapper
	conn *etcd.BytesConnectionEtcd
}

// PutIfNotExists implements the atomic Put operation.
func (etcd *etcdWithAtomicPut) PutIfNotExists(key string, value []byte) (succeeded bool, err error) {
	return etcd.conn.PutIfNotExists(key, value)
}

// OnConnect immediately calls the callback - etcdConnect() returns etcd client
// in the connected state (or as nil).
func (etcd *etcdWithAtomicPut) OnConnect(callback func() error) {
	callback()
}

// etcdConnect connects to ETCD db.
func etcdConnect() (etcdConn nodesync.ClusterWideDB, err error) {
	etcdConfig := &etcd.Config{}

	// parse ETCD config file
	err = config.ParseConfigFromYamlFile(*etcdCfgFile, etcdConfig)
	if err != nil {
		logger.Errorf("Error by parsing config YAML file: %v", err)
		return nil, err
	}

	// prepare ETCD config
	etcdCfg, err := etcd.ConfigToClient(etcdConfig)
	if err != nil {
		logger.Errorf("Error by constructing ETCD config: %v", err)
		return nil, err
	}

	// connect in retry loop
	var conn *etcd.BytesConnectionEtcd
	for i := 0; i < etcdConnectionRetries; i++ {
		conn, err = etcd.NewEtcdConnectionWithBytes(*etcdCfg, logger)
		if err != nil {
			if i == etcdConnectionRetries-1 {
				logger.Errorf("Error by connecting to ETCD: %v", err)
				return nil, err
			}
			logger.Debugf("ETCD connection retry n. %d", i+1)
		} else {
			// connected
			break
		}
	}

	protoDb := kvproto.NewProtoWrapper(conn, &keyval.SerializerJSON{})
	etcdConn = &etcdWithAtomicPut{
		ProtoWrapper: protoDb,
		conn:         conn,
	}
	return etcdConn, nil
}

// boltOpen opens local Bolt db.
// If delete is true, the database file is deleted before opening.
func boltOpen(delete bool) (protoDb *kvproto.ProtoWrapper, err error) {
	boltConfig := &bolt.Config{}

	// parse Bolt config file
	err = config.ParseConfigFromYamlFile(*boltCfgFile, boltConfig)
	if err != nil {
		logger.Errorf("Error by parsing config YAML file: %v", err)
		return nil, err
	}

	if delete {
		// delete the DB file before creating the client if requested
		os.Remove(boltConfig.DbPath)
	}

	// create bolt client
	client, err := bolt.NewClient(boltConfig)
	if err != nil {
		logger.Errorf("Error by creating Bolt client: %v", err)
		return nil, err
	}

	protoDb = kvproto.NewProtoWrapper(client, &keyval.SerializerJSON{})
	return protoDb, nil
}

// prepareForLocalResync re-synchronizes Bolt against Etcd for STN case,
// so that when agent starts without connectivity, it will execute local resync
// against relatively up-to-date data that contains at least node ID.
// Steps:
//   1. if etcd is available, allocate/retrieve node ID from there
//   2. if etcd is available, resync bolt against etcd
//   3. check that node ID is in bolt
func prepareForLocalResync(nodeName string, boltDB contivconf.KVBrokerFactory, etcdDB nodesync.ClusterWideDB) error {
	var err error

	// if etcd is available, allocate/retrieve ID from there
	if etcdDB != nil {
		// try to obtain snapshot of Kubernetes state data
		resyncEv, _, err := controller.LoadKubeStateForResync(etcdDB.NewBroker(""), logger)
		if err != nil {
			return err
		}

		// allocate or retrieve ID from etcd
		nodeSync := nodesync.NewPlugin()
		nodeSync.DB = etcdDB
		nodeSync.Init()
		kubeState := resyncEv.KubeState
		err = nodeSync.Resync(resyncEv, kubeState, 1, nil)
		if err == nil {
			// update kube state to handle newly allocated ID
			nodeID := nodeSync.GetNodeID()
			if _, hadID := kubeState[vppnode.Keyword][vppnode.Key(nodeID)]; !hadID {
				kubeState[vppnode.Keyword][vppnode.Key(nodeID)] = &vppnode.VppNode{
					Id:   nodeID,
					Name: nodeName,
				}
			}
		}

		// resync bolt against etcd
		err = controller.ResyncDatabase(boltDB.NewBroker(""), kubeState)
		if err != nil {
			return err
		}
	}

	// check that node ID is in bolt
	resyncEv, _, err := controller.LoadKubeStateForResync(boltDB.NewBroker(""), logger)
	if err != nil {
		return err
	}
	nodeSync := nodesync.NewPlugin()
	nodeSync.DB = nil
	nodeSync.Init()
	err = nodeSync.Resync(resyncEv, resyncEv.KubeState, 1, nil)
	return err
}

func main() {
	logger.Debugf("Starting contiv-init process")

	// init and parse flags
	contivConf := contivconf.NewPlugin()
	config.DefineFlagsFor(contivConf.String())
	flag.Parse()

	// get microservice label
	nodeName := os.Getenv(servicelabel.MicroserviceLabelEnvVar)
	servicelabel.DefaultPlugin.MicroserviceLabel = nodeName

	// try to connect to ETCD db
	etcdDB, err := etcdConnect()
	if err == nil {
		defer etcdDB.Close()
	}

	// try to open local Bolt db
	boltDB, err := boltOpen(false)
	if err != nil {
		logger.Warnf("Failed to open Bolt DB: %v, will retry with DB file delete", err)

		// try to re-open after deleting the DB file
		// This may be needed upon non-backward-compatible bolt version change.
		boltDB, err = boltOpen(true)
		if err != nil {
			logger.Warnf("Failed to open Bolt DB: %v, Bolt will not be used", err)
		} else {
			logger.Debugf("Bolt open successful after DB file delete")
		}
	}
	defer func() {
		if boltDB != nil {
			// if Bolt DB was not closed properly (exiting with error), close it now
			boltDB.Close()
		}
	}()

	// use ContivConf plugin to load the configuration
	contivConf.ContivInitDeps = &contivconf.ContivInitDeps{
		LocalDB:  boltDB,
		RemoteDB: etcdDB,
	}
	err = contivConf.Init()
	if err != nil {
		logger.Errorf("Failed to initialize ContivConf plugin: %v", err)
		os.Exit(-1)
	}

	// check whether STN is required and get NIC name
	var nicToSteal string
	if contivConf.InSTNMode() {
		nicToSteal = contivConf.GetSTNConfig().StealInterface
	}
	useDHCP := contivConf.UseDHCP()

	var stnData *stn.STNReply
	if nicToSteal != "" {
		// prepare for local resync
		err := prepareForLocalResync(nodeName, boltDB, etcdDB)
		if err != nil {
			logger.Errorf("Failed to prepare for local resync: %v", err)
			os.Exit(-1)
		}
		// steal the NIC
		stnData, err = stealNIC(nicToSteal, useDHCP)
		if err != nil {
			logger.Warnf("Error by stealing the NIC %s: %v", nicToSteal, err)
			// do not fail if STN was not successful
			nicToSteal = ""
		}
		// Check if the STN Daemon has been initialized
		if stnData == nil {
			logger.Errorf("STN configured in vswitch, but STN Daemon not initialized")
			os.Exit(-1)
		}
	} else {
		logger.Debug("STN not requested")
	}

	// check whether vmxnet3 interface bind is required
	if !contivConf.InSTNMode() && contivConf.UseVmxnet3() {

		vmxnet3Cfg, err := contivConf.GetVmxnet3Config()
		if err != nil {
			logger.Errorf("Error by getting vmxnet3 config: %v", err)
			os.Exit(-1)
		}
		err = pci.DriverBind(vmxnet3Cfg.MainInterfacePCIAddress, vmxnet3PreferredDriver)
		if err != nil {
			logger.Errorf("Error binding to vfio-pci: %v", err)
			os.Exit(-1)
		}
	}

	// release bolt DB before starting the Contiv agent
	if boltDB != nil {
		boltDB.Close()
		boltDB = nil
	}

	// init process manager
	procmgr := processmanager.NewPlugin()

	// start VPP
	logger.Debug("Starting VPP")
	vppLogger := newVPPLogger()
	vppStat := make(chan status.ProcessStatus)
	vpp := procmgr.NewProcess(vppProcessName, *vppBinaryPath, processmanager.Args("-c", vppStartupConfigPath),
		processmanager.Writer(vppLogger, vppLogger), processmanager.Notify(vppStat), processmanager.AutoTerminate())
	err = vpp.Start()
	if err != nil {
		logger.Errorf("Error by starting VPP process: %v", err)
		os.Exit(-1)
	}

	// start contiv-agent
	logger.Debugf("Starting contiv-agent")
	// remove CNI server socket file
	os.Remove(defaultCNISocketFile)
	agentStat := make(chan status.ProcessStatus)
	agent := procmgr.NewProcess(agentProcessName, *agentBinaryPath,
		processmanager.Writer(os.Stdout, os.Stdout), processmanager.Notify(agentStat), processmanager.AutoTerminate())
	err = agent.Start()
	if err != nil {
		logger.Errorf("Error by starting contiv-agent process: %v", err)
		vpp.Stop()
		os.Exit(-1)
	}

	// subscribe to SIGTERM signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	// loop until SIGTERM / process termination
eventLoop:
	for {
		select {
		case sig := <-sigChan:
			logger.Debugf("%v signal received, stopping contiv-agent & VPP", sig)
			agent.Stop()
			vpp.Stop()
			agent.Wait()
			vpp.Wait()
			break eventLoop

		case stat := <-vppStat:
			if stat == status.Terminated {
				logger.Error("VPP terminated, stopping contiv-agent")
				agent.StopAndWait()
				break eventLoop
			}

		case stat := <-agentStat:
			if stat == status.Terminated {
				logger.Error("contiv-agent terminated, stopping VPP")
				vpp.StopAndWait()
				break eventLoop
			}
		}
	}
	logger.Debugf("exiting")

	// request releasing the NIC
	if nicToSteal != "" {
		releaseNIC(nicToSteal, useDHCP)
	}
}
