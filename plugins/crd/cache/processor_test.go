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
)

const (
	testAgentPort = ":8080"
)

type processorTestVars struct {
	srv       *http.Server
	log       *logrus.Logger
	processor *ContivTelemetryProcessor
	nodeInfo  *NodeLiveness
	client    *http.Client
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
}

func (ptv *processorTestVars) shutdownMockHTTPServer() {
	if err := ptv.srv.Shutdown(nil); err != nil {
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
	t.Run("getLivenessInfo", testGetLivenessInfo)

	// Shutdown the mock HTTP server
	ptv.shutdownMockHTTPServer()
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

func testGetLivenessInfo(t *testing.T) {
	node, err := ptv.processor.Cache.GetNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())

	ptv.processor.getLivenessInfo(*ptv.client, node)
	time.Sleep(1 * time.Microsecond)
	ptv.log.Info("DTO Map:", ptv.processor.dtoMap)
}