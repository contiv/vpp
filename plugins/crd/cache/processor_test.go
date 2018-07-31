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
	"encoding/json"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
	"context"
)

const (
	testAgentPort = ":8080"
)

type processorTestVars struct {
	srv       *http.Server
	log       *logrus.Logger
	client    *http.Client
	processor *ContivTelemetryProcessor

	// Mock data
	nodeInfo          *NodeLiveness
	nodeInterfaces    map[int]NodeInterface
	nodeBridgeDomains map[int]NodeBridgeDomains
	nodel2fibs        map[string]NodeL2Fib
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
	// Register handler for getting NodeInfo data
	http.HandleFunc(livenessURL, func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(ptv.nodeInfo)
		if err != nil {
			ptv.log.Error("Error marshalling NodeInfo data, err: ", err)
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "application/json")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	// Register handler for getting interface data
	http.HandleFunc(interfaceURL, func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(ptv.nodeInterfaces)
		if err != nil {
			ptv.log.Error("Error marshalling nodeInterfaces, err: ", err)
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "application/json")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

}

func (ptv *processorTestVars) shutdownMockHTTPServer() {
	if err := ptv.srv.Shutdown(context.TODO()); err != nil {
		panic(err)
	}
}

func (ptv *processorTestVars) initTestData() {
	// Initialize NodeLiveness response
	ptv.nodeInfo = &NodeLiveness{
		BuildVersion: "v1.2-alpha-179-g4e2d712",
		BuildDate:    "2018-07-19T09:54+00:00",
		State:        1,
		StartTime:    1532891958,
		LastChange:   1532891971,
		LastUpdate:   1532997235,
		CommitHash:   "v1.2-alpha-179-g4e2d712",
	}

	// Initilize interfaces data
	ptv.nodeInterfaces = map[int]NodeInterface{
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
			Tap:             tap{Version: 2},
		},
		3: {
			VppInternalName: "tap1",
			Name:            "tap3aa4d77d27d0bf3",
			IfType:          3,
			Enabled:         true,
			PhysAddress:     "02:fe:fc:07:21:82",
			Mtu:             1500,
			IPAddresses:     []string{"10.2.1.7/32"},
			Tap:             tap{Version: 2},
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
			Vxlan: vxlan{
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
			Vxlan: vxlan{
				SrcAddress: "192.168.16.3",
				DstAddress: "192.168.16.2",
				Vni:        10,
			},
		},
	}
}

func TestProcessor(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	ptv.log = logrus.DefaultLogger()
	ptv.startMockHTTPServer()
	registerHTTPHandlers()
	ptv.initTestData()

	ptv.client = &http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       timeout,
	}

	ptv.processor = &ContivTelemetryProcessor{}
	ptv.processor.Deps.Log = ptv.log
	ptv.processor.Cache = NewCache(ptv.log)
	ptv.processor.Init()
	ptv.processor.ticker.Stop() // Do not periodically poll agents - we will run updates manually from tests
	ptv.processor.agentPort = testAgentPort
	ptv.processor.Cache.AddNode(1, "k8s-master", "10.20.0.2", "localhost")

	// Do testing
	t.Run("mockClient", testMockClient)
	t.Run("collectAgentInfoNoError", testCollectAgentInfoNoError)

	// Shutdown the mock HTTP server
	// ptv.shutdownMockHTTPServer()
}

func testMockClient(t *testing.T) {
	// Get response from the server
	res, err := ptv.client.Get("http://" + "localhost" + testAgentPort + livenessURL)
	if err != nil {
		ptv.log.Error("Error receiving nodeInfo, err: ", err)
		return
	}

	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodeInfo := &NodeLiveness{}
	json.Unmarshal(b, nodeInfo)
	// Received data should be the same as the data created above
	ptv.log.Info("Received nodeInfo: ", nodeInfo)

	// Modify response
	ptv.nodeInfo.BuildVersion = "v1.55"
	res, err = ptv.client.Get("http://" + "localhost" + testAgentPort + livenessURL)
	if err != nil {
		ptv.log.Error("Error receiving nodeInfo, err: ", err)
		return
	}

	b, _ = ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodeInfo1 := &NodeLiveness{}
	json.Unmarshal(b, nodeInfo1)
	// Received data should be the same as the modified data
	ptv.log.Info("Received nodeInfo: ", nodeInfo1)
}

func testCollectAgentInfoNoError(t *testing.T) {
	node, err := ptv.processor.Cache.GetNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())

	ptv.processor.collectAgentInfo(node)
	time.Sleep(1 * time.Microsecond)
	ptv.log.Info("Cache nodes:", ptv.processor.Cache.nMap)
	ptv.log.Info("Cache report:", ptv.processor.Cache.report)
}
