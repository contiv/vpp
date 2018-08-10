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

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	noError        = iota
	inject404Error = iota
	injectDelay    = iota
	testAgentPort  = ":8080"
)

type processorTestVars struct {
	srv         *http.Server
	injectError int
	log         *logrus.Logger
	client      *http.Client
	processor   *ContivTelemetryProcessor
	tickerChan  chan time.Time

	// Mock data
	nodeLiveness      *telemetrymodel.NodeLiveness
	nodeInterfaces    map[int]telemetrymodel.NodeInterface
	nodeBridgeDomains map[int]telemetrymodel.NodeBridgeDomain
	nodeL2Fibs        map[string]telemetrymodel.NodeL2FibEntry
	nodeIPArps        []telemetrymodel.NodeIPArpEntry
}

var ptv processorTestVars

func (ptv *processorTestVars) startMockHTTPServer() {
	ptv.srv = &http.Server{Addr: testAgentPort}

	go func() {
		if err := ptv.srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			ptv.log.Error("Httpserver: ListenAndServe() error: %s", err)
			gomega.Expect(err).To(gomega.BeNil())
		}
	}()
}

func registerHTTPHandlers() {
	// Register handler for all test data
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if ptv.injectError == inject404Error {
			w.WriteHeader(404)
			w.Write([]byte("page not found - invalid path: " + r.URL.Path))
			return
		}

		if ptv.injectError == injectDelay {
			time.Sleep(3 * time.Second)
		}

		var data interface{}

		switch r.URL.Path {
		case livenessURL:
			data = ptv.nodeLiveness
		case interfaceURL:
			data = ptv.nodeInterfaces
		case l2FibsURL:
			data = ptv.nodeL2Fibs
		case bridgeDomainURL:
			data = ptv.nodeBridgeDomains
		case arpURL:
			data = ptv.nodeIPArps
		default:
			ptv.log.Error("unknown URL: ", r.URL)
			w.WriteHeader(404)
			w.Write([]byte("Unknown path" + r.URL.Path))
			return
		}

		buf, err := json.Marshal(data)
		if err != nil {
			ptv.log.Error("Error marshalling NodeInfo data, err: ", err)
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "application/json")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	})

}

func (ptv *processorTestVars) shutdownMockHTTPServer() {
	if err := ptv.srv.Shutdown(context.TODO()); err != nil {
		panic(err)
	}
}

func newMockTicker() *time.Ticker {
	return &time.Ticker{
		C: ptv.tickerChan,
	}
}

func TestProcessor(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	ptv.log = logrus.DefaultLogger()
	ptv.log.SetLevel(logging.DebugLevel)

	ptv.tickerChan = make(chan time.Time)

	// Init the mock HTTP Server
	ptv.startMockHTTPServer()
	registerHTTPHandlers()
	ptv.injectError = noError

	ptv.client = &http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       clientTimeout,
	}

	// Init & populate the test data
	ptv.initTestData()

	// Init the cache and the processor (object under test)
	ptv.processor = &ContivTelemetryProcessor{
		Deps: Deps{
			Log: ptv.log,
		},
		ContivTelemetryCache: &ContivTelemetryCache{
			Deps: Deps{
				Log: ptv.log,
			},
			Synced: false,
		},
	}
	ptv.processor.ContivTelemetryCache.Init()
	ptv.processor.Init()

	// Override default processor behavior
	ptv.processor.ticker.Stop() // Do not periodically poll agents
	ptv.processor.ticker = newMockTicker()
	ptv.processor.agentPort = testAgentPort // Override agentPort

	// Do the testing
	t.Run("collectAgentInfoNoError", testCollectAgentInfoNoError)
	t.Run("collectAgentInfoWithHTTPError", testCollectAgentInfoWithHTTPError)
	t.Run("collectAgentInfoWithTimeout", testCollectAgentInfoWithTimeout)

	// Shutdown the mock HTTP server
	// ptv.shutdownMockHTTPServer()
}

func testCollectAgentInfoNoError(t *testing.T) {
	ptv.processor.ContivTelemetryCache.AddVppNode(1, "k8s-master", "10.20.0.2", "localhost")

	node, err := ptv.processor.ContivTelemetryCache.VppCache.retrieveNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())

	ptv.tickerChan <- time.Time{}

	cycles := 0
	for {
		if node.NodeLiveness != nil && node.NodeInterfaces != nil &&
			node.NodeBridgeDomains != nil && node.NodeL2Fibs != nil && node.NodeIPArp != nil {
			break
		}
		time.Sleep(1 * time.Millisecond)
		cycles++
	}

	gomega.Expect(node.NodeLiveness).To(gomega.BeEquivalentTo(ptv.nodeLiveness))
	gomega.Expect(node.NodeInterfaces).To(gomega.BeEquivalentTo(ptv.nodeInterfaces))
	gomega.Expect(node.NodeBridgeDomains).To(gomega.BeEquivalentTo(ptv.nodeBridgeDomains))
	gomega.Expect(node.NodeL2Fibs).To(gomega.BeEquivalentTo(ptv.nodeL2Fibs))
	gomega.Expect(node.NodeIPArp).To(gomega.BeEquivalentTo(ptv.nodeIPArps))
}

func testCollectAgentInfoWithHTTPError(t *testing.T) {
	ptv.processor.ContivTelemetryCache.ReinitializeCache()
	ptv.processor.ContivTelemetryCache.AddVppNode(1, "k8s-master", "10.20.0.2", "localhost")

	nodes := ptv.processor.ContivTelemetryCache.LookupNode([]string{"k8s-master"})
	gomega.Expect(len(nodes)).To(gomega.Equal(1))
	ptv.injectError = inject404Error

	ptv.tickerChan <- time.Time{}
	time.Sleep(10 * time.Millisecond)

	numHTTPErrs := 0
	for _, r := range ptv.processor.ContivTelemetryCache.report {
		if strings.Contains(r, "404 Not Found") {
			numHTTPErrs++
		}
	}
	gomega.Expect(numHTTPErrs).To(gomega.Equal(numDTOs))
}

func testCollectAgentInfoWithTimeout(t *testing.T) {
	ptv.processor.ContivTelemetryCache.ReinitializeCache()
	ptv.processor.httpClientTimeout = 1
	ptv.processor.ContivTelemetryCache.AddVppNode(1, "k8s-master", "10.20.0.2", "localhost")

	nodes := ptv.processor.ContivTelemetryCache.LookupNode([]string{"k8s-master"})
	gomega.Expect(len(nodes)).To(gomega.Equal(1))
	ptv.injectError = injectDelay

	ptv.tickerChan <- time.Time{}
	time.Sleep(1 * time.Second)

	numTimeoutErrs := 0
	for _, r := range ptv.processor.ContivTelemetryCache.report {
		if strings.Contains(r, "Timeout exceeded") {
			numTimeoutErrs++
		}
	}
	gomega.Expect(numTimeoutErrs).To(gomega.Equal(numDTOs))
}

func printErrorReport(report []string) {
	fmt.Println("Error Report")
	fmt.Println("============")
	for _, rl := range report {
		fmt.Println(rl)
	}
}

func (ptv *processorTestVars) initTestData() {
	// Initialize NodeLiveness response
	ptv.nodeLiveness = &telemetrymodel.NodeLiveness{
		BuildVersion: "v1.2-alpha-179-g4e2d712",
		BuildDate:    "2018-07-19T09:54+00:00",
		State:        1,
		StartTime:    1532891958,
		LastChange:   1532891971,
		LastUpdate:   1532997235,
		CommitHash:   "v1.2-alpha-179-g4e2d712",
	}

	// Initialize interfaces data
	ptv.nodeInterfaces = map[int]telemetrymodel.NodeInterface{
		0: {
			VppInternalName: "local0",
			Name:            "local0",
		},
		1: {
			VppInternalName: "GigabitEthernet0/8",
			Name:            "GigabitEthernet0/8",
			IfType:          1,
			Enabled:         true,
			PhysAddress:     "08:00:27:c1:dd:42",
			Mtu:             9202,
			IPAddresses:     []string{"192.168.16.3"},
		},
		2: {
			VppInternalName: "tap0",
			Name:            "tap-vpp2",
			IfType:          3,
			Enabled:         true,
			PhysAddress:     "01:23:45:67:89:42",
			Mtu:             1500,
			IPAddresses:     []string{"172.30.3.1/24"},
			Tap:             telemetrymodel.Tap{Version: 2},
		},
		3: {
			VppInternalName: "tap1",
			Name:            "tap3aa4d77d27d0bf3",
			IfType:          3,
			Enabled:         true,
			PhysAddress:     "02:fe:fc:07:21:82",
			Mtu:             1500,
			IPAddresses:     []string{"10.2.1.7/32"},
			Tap:             telemetrymodel.Tap{Version: 2},
		},
		4: {
			VppInternalName: "loop0",
			Name:            "vxlanBVI",
			Enabled:         true,
			PhysAddress:     "1a:2b:3c:4d:5e:03",
			Mtu:             1500,
			IPAddresses:     []string{"192.168.30.3/24"},
		},
		5: {
			VppInternalName: "vxlan_tunnel0",
			Name:            "vxlan1",
			IfType:          5,
			Enabled:         true,
			Vxlan: telemetrymodel.Vxlan{
				SrcAddress: "192.168.16.3",
				DstAddress: "192.168.16.1",
				Vni:        10,
			},
		},
		6: {
			VppInternalName: "vxlan_tunnel1",
			Name:            "vxlan2",
			IfType:          5,
			Enabled:         true,
			Vxlan: telemetrymodel.Vxlan{
				SrcAddress: "192.168.16.3",
				DstAddress: "192.168.16.2",
				Vni:        10,
			},
		},
	}

	// Initialize bridge domains data
	ptv.nodeBridgeDomains = map[int]telemetrymodel.NodeBridgeDomain{
		1: {
			Name:       "vxlanBD",
			Forward:    true,
			Interfaces: []telemetrymodel.BDinterfaces{},
		},
		2: {
			Name:    "vxlanBD",
			Forward: true,
			Interfaces: []telemetrymodel.BDinterfaces{
				{SwIfIndex: 4},
				{SwIfIndex: 5},
				{SwIfIndex: 6},
			},
		},
	}

	// Initialize L2 Fib data
	ptv.nodeL2Fibs = map[string]telemetrymodel.NodeL2FibEntry{
		"1a:2b:3c:4d:5e:01": {
			BridgeDomainIdx:          2,
			OutgoingInterfaceSwIfIdx: 5,
			PhysAddress:              "1a:2b:3c:4d:5e:01",
			StaticConfig:             true,
		},
		"1a:2b:3c:4d:5e:02": {
			BridgeDomainIdx:          2,
			OutgoingInterfaceSwIfIdx: 6,
			PhysAddress:              "1a:2b:3c:4d:5e:02",
			StaticConfig:             true,
		},
		"1a:2b:3c:4d:5e:03": {
			BridgeDomainIdx:          2,
			OutgoingInterfaceSwIfIdx: 4,
			PhysAddress:              "1a:2b:3c:4d:5e:03",
			StaticConfig:             true,
			BridgedVirtualInterface:  true,
		},
	}

	// Initialize ARP Table data
	ptv.nodeIPArps = []telemetrymodel.NodeIPArpEntry{
		{
			Interface:  4,
			IPAddress:  "192.168.30.1",
			MacAddress: "1a:2b:3c:4d:5e:01",
			Static:     true,
		},
		{
			Interface:  4,
			IPAddress:  "192.168.30.2",
			MacAddress: "1a:2b:3c:4d:5e:02",
			Static:     true,
		},
		{
			Interface:  2,
			IPAddress:  "172.30.3.2",
			MacAddress: "96:ff:16:6e:60:6f",
			Static:     true,
		},
		{
			Interface:  3,
			IPAddress:  "10.1.3.7",
			MacAddress: "00:00:00:00:00:02",
			Static:     true,
		},
	}
}
