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

	"github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/acl"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/nat"

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

/*************************
 * Example plugin config *
 *************************/

/*****************************************************
 * After Resync (apart from Contiv config)           *
 *                                                   *
 *  +---------------------------------------------+  *
 *  |                                             |  *
 *  +-----------+           +---------------------+  *
 *  | tap1      |           |  memif1             |  *
 *  | DISABLED  |      +--> |  MASTER             |  *
 *  +-----------+      |    |  IP: 192.168.1.1/24 |  *
 *  |                  |    +---------------------+  *
 *  |  +-----------+   |                          |  *
 *  |  | loopback1 |   +                          |  *
 *  |  +-----------+   route for 192.168.2.1      |  *
 *  |                                             |  *
 *  +---------------------------------------------+  *
 *                                                   *
 *****************************************************/

/********************************************************
 * After Data Change Request (apart from Contiv config) *
 *                                                      *
 *  +------------------------------------------------+  *
 *  |                                                |  *
 *  +---------+ +------+                  +----------+  *
 *  | tap1    |-| acl1 |-+         +------| memif1   |  *
 *  | ENABLED | +------+ |         |      | SLAVE    |  *
 *  | nat-out |          |         |      +----------+  *
 *  +---------+        Bridge   xconnect             |  *
 *  |                  domain      |      +----------+  *
 *  |                    |         |      | memif2   |  *
 *  |  +------------+    |         +------| SLAVE    |  *
 *  |  | loopback1  |----+                +----------|  *
 *  |  +------------+                                |  *
 *  |                                                |  *
 *  +------------------------------------------------+  *
 *                                                      *
 ********************************************************/

var (
	// memif1AsMaster is an example of a memory interface configuration. (Master=true, with IPv4 address).
	memif1AsMaster = interfaces.Interface{
		Name:    "memif1",
		Type:    interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &interfaces.Interface_Memif{
			Memif: &interfaces.MemifLink{
				Id:             1,
				Master:         true,
				SocketFilename: "/tmp/memif1.sock",
			},
		},
		Mtu:         1500,
		IpAddresses: []string{"192.168.1.1/24"},
	}

	// memif1AsSlave is the original memif1 turned into slave and stripped of the IP address.
	memif1AsSlave = interfaces.Interface{
		Name:    "memif1",
		Type:    interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &interfaces.Interface_Memif{
			Memif: &interfaces.MemifLink{
				Id:             1,
				Master:         false,
				SocketFilename: "/tmp/memif1.sock",
			},
		},
		Mtu: 1500,
	}

	// Memif2 is a slave memif without IP address and to be xconnected with memif1.
	memif2 = interfaces.Interface{
		Name:    "memif2",
		Type:    interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &interfaces.Interface_Memif{
			Memif: &interfaces.MemifLink{
				Id:             2,
				Master:         false,
				SocketFilename: "/tmp/memif2.sock",
			},
		},
		Mtu: 1500,
	}
	// XConMemif1ToMemif2 defines xconnect between memifs.
	XConMemif1ToMemif2 = l2.XConnectPair{
		ReceiveInterface:  memif1AsSlave.GetName(),
		TransmitInterface: memif2.GetName(),
	}

	// tap1Disabled is a disabled tap interface.
	tap1Disabled = interfaces.Interface{
		Name:    "tap1",
		Type:    interfaces.Interface_TAP,
		Enabled: false,
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{
				Version: 1,
			},
		},
		Mtu: 1500,
	}

	// tap1Enabled is an enabled tap1 interface.
	tap1Enabled = interfaces.Interface{
		Name:    "tap1",
		Type:    interfaces.Interface_TAP,
		Enabled: true,
		Link: &interfaces.Interface_Tap{
			Tap: &interfaces.TapLink{
				Version: 1,
			},
		},
		Mtu: 1500,
	}

	tap1LinuxSide = linux_interfaces.Interface{
		Name:       "linux-tap1",
		Type:       linux_interfaces.Interface_TAP_TO_VPP,
		Enabled:    true,
		HostIfName: "tap-to-vpp",
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: tap1Enabled.GetName(),
			},
		},
		Mtu: 1500,
	}

	acl1 = acl.Acl{
		Name: "acl1",
		Rules: []*acl.Acl_Rule{
			{
				Action: acl.Acl_Rule_DENY,
				IpRule: &acl.Acl_Rule_IpRule{
					Ip: &acl.Acl_Rule_IpRule_Ip{
						DestinationNetwork: "10.1.1.0/24",
						SourceNetwork:      "10.1.2.0/24",
					},
					Tcp: &acl.Acl_Rule_IpRule_Tcp{
						DestinationPortRange: &acl.Acl_Rule_IpRule_PortRange{
							LowerPort: 50,
							UpperPort: 150,
						},
						SourcePortRange: &acl.Acl_Rule_IpRule_PortRange{
							LowerPort: 1000,
							UpperPort: 2000,
						},
					},
				},
			},
		},
		Interfaces: &acl.Acl_Interfaces{
			Egress: []string{tap1Enabled.GetName()},
		},
	}

	// loopback1 is an example of a loopback interface configuration (without IP address assigned).
	loopback1 = interfaces.Interface{
		Name:    "loopback1",
		Type:    interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Mtu:     1500,
	}

	// loopback1WithAddr extends loopback1 definition with an IP address.
	loopback1WithAddr = interfaces.Interface{
		Name:        "loopback1",
		Type:        interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		Mtu:         1500,
		IpAddresses: []string{"10.0.0.1/24"},
	}

	// BDLoopback1ToTap1 is a bridge domain with tap1 and loopback1 interfaces in it.
	// Loopback is set to be BVI.
	BDLoopback1ToTap1 = l2.BridgeDomain{
		Name:                "br1",
		Flood:               false,
		UnknownUnicastFlood: false,
		Forward:             true,
		Learn:               true,
		ArpTermination:      false,
		MacAge:              0, /* means disable aging */
		Interfaces: []*l2.BridgeDomain_Interface{
			{
				Name:                    loopback1.GetName(),
				BridgedVirtualInterface: true,
			}, {
				Name:                    tap1Enabled.GetName(),
				BridgedVirtualInterface: false,
			},
		},
	}

	// this gets merged with the Contiv's NAT global configuration
	natGlobal = nat.Nat44Global{
		NatInterfaces: []*nat.Nat44Global_Interface{
			{
				Name:     tap1Enabled.GetName(),
				IsInside: false,
			},
		},
	}

	// routeThroughMemif1 is an example route configuration, with memif1 being the next hop.
	routeThroughMemif1 = l3.StaticRoute{
		VrfId:       0,
		DstNetwork:  "192.168.2.1/32",
		NextHopAddr: "192.168.1.1", // Memif1AsMaster
		Weight:      5,
	}
)
