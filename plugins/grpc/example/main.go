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
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/namsral/flag"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/contiv/vpp/plugins/grpc/clientv2"
	"github.com/contiv/vpp/plugins/grpc/rpc"
)

const (
	defaultHostName = "localhost"
	grpcPort        = "9111"
)

var hostname = defaultHostName

// init sets the default logging level
func init() {
	logrus.DefaultLogger().SetOutput(os.Stdout)
	logrus.DefaultLogger().SetLevel(logging.DebugLevel)
}

/********
 * Main *
 ********/

// Start Agent plugins selected for this example.
func main() {
	flag.StringVar(&hostname, "hostname", defaultHostName, "Contiv node hostname")

	// Init close channel to stop the example.
	exampleFinished := make(chan struct{}, 1)
	// End when the localhost example is finished.
	go closeExample("localhost example finished", exampleFinished)

	// Inject dependencies to example plugin
	ep := &ExamplePlugin{}
	// Start Agent
	a := agent.NewAgent(
		agent.AllPlugins(ep),
		agent.QuitOnClose(exampleFinished),
	)
	if err := a.Run(); err != nil {
		log.Fatal()
	}
}

// Stop the agent with desired info message.
func closeExample(message string, exampleFinished chan struct{}) {
	time.Sleep(30 * time.Second)
	logrus.DefaultLogger().Info(message)
	close(exampleFinished)
}

/******************
 * Example plugin *
 ******************/

// PluginName represents name of plugin.
const PluginName = "grpc-config-example"

// ExamplePlugin demonstrates the use of the remoteclient to locally transport example configuration into the default VPP plugins.
type ExamplePlugin struct {
	wg     sync.WaitGroup
	cancel context.CancelFunc
	conn   *grpc.ClientConn
}

// Init initializes example plugin.
func (plugin *ExamplePlugin) Init() (err error) {
	// Set up connection to the server.
	plugin.conn, err = grpc.Dial(hostname+":"+grpcPort, grpc.WithInsecure())
	if err != nil {
		return err
	}

	// Apply initial VPP configuration.
	plugin.resyncVPP()

	// Schedule reconfiguration.
	var ctx context.Context
	ctx, plugin.cancel = context.WithCancel(context.Background())
	plugin.wg.Add(1)
	go plugin.reconfigureVPP(ctx)

	logrus.DefaultLogger().Info("Initialization of the example plugin has completed")
	return nil
}

// Close cleans up the resources.
func (plugin *ExamplePlugin) Close() error {
	plugin.cancel()
	plugin.wg.Wait()

	err := safeclose.Close(plugin.conn)
	if err != nil {
		return err
	}

	logrus.DefaultLogger().Info("Closed example plugin")
	return nil
}

// String returns plugin name
func (plugin *ExamplePlugin) String() string {
	return PluginName
}

// resyncVPP propagates snapshot of the whole initial configuration to VPP plugins.
func (plugin *ExamplePlugin) resyncVPP() {
	err := clientv2.NewDataResyncDSL(rpc.NewDataResyncServiceClient(plugin.conn)).
		VppInterface(&memif1AsMaster).
		VppInterface(&tap1Disabled).
		VppInterface(&loopback1).
		LinuxInterface(&tap1LinuxSide).
		StaticRoute(&routeThroughMemif1).
		Send().ReceiveReply()
	if err != nil {
		logrus.DefaultLogger().Errorf("Failed to apply initial VPP configuration: %v", err)
	} else {
		logrus.DefaultLogger().Info("Successfully applied initial VPP configuration")
	}
}

// reconfigureVPP simulates a set of changes in the configuration related to VPP plugins.
func (plugin *ExamplePlugin) reconfigureVPP(ctx context.Context) {
	_, dstNetAddr, err := net.ParseCIDR("192.168.2.1/32")
	if err != nil {
		return
	}
	nextHopAddr := net.ParseIP("192.168.1.1")

	select {
	case <-time.After(10 * time.Second):
		// Simulate configuration change 10 seconds after resync.
		err := clientv2.NewDataChangeDSL(rpc.NewDataChangeServiceClient(plugin.conn)).
			Put().
			VppInterface(&memif1AsSlave).     // turn memif1 into slave, remove the IP address
			VppInterface(&memif2).            // newly added memif interface
			VppInterface(&tap1Enabled).       // enable tap1 interface
			VppInterface(&loopback1WithAddr). // assign IP address to loopback1 interface
			NAT44Global(&natGlobal).          // enable nat-output feature on tap1 interface
			ACL(&acl1).                       // declare ACL for the traffic leaving tap1 interface
			XConnect(&XConMemif1ToMemif2).    // xconnect memif interfaces
			BD(&BDLoopback1ToTap1).           // put loopback and tap1 into the same bridge domain
			Delete().
			StaticRoute(0, dstNetAddr.String(), nextHopAddr.String()). // remove the route going through memif1
			Send().ReceiveReply()
		if err != nil {
			logrus.DefaultLogger().Errorf("Failed to reconfigure VPP: %v", err)
		} else {
			logrus.DefaultLogger().Info("Successfully reconfigured VPP")
		}
	case <-ctx.Done():
		// Cancel the scheduled re-configuration.
		logrus.DefaultLogger().Info("Planned VPP re-configuration was canceled")
	}
	plugin.wg.Done()
}
