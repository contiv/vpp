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
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
		"io/ioutil"
	"net/http"
	"testing"
	"encoding/json"
	)

type processorTestVars struct {
	srv      *http.Server
	log      *logrus.Logger
	nodeInfo *NodeLiveness
}

var ptv processorTestVars

func (ptv *processorTestVars) startMockHTTPServer() {
	ptv.srv = &http.Server{Addr: ":8080"}

	go func() {
		if err := ptv.srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			ptv.log.Error("Httpserver: ListenAndServe() error: %s", err)
			gomega.Expect(err).To(gomega.BeNil())
		}
	}()

}

func registerHandlers() {
	// Register handler for getting NodeInfo data
	http.HandleFunc(livenessURL, func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(ptv.nodeInfo)
		if err != nil {
			ptv.log.Error("Error marshalling NodeInfo data, err: ", err)
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

func TestProcessor(t *testing.T) {
	gomega.RegisterTestingT(t)
	// Initialize log
	ptv.log = logrus.DefaultLogger()

	// Start the mock HTTP Server
	ptv.startMockHTTPServer()
	registerHandlers()

	// Do testing
	t.Run("mockClient", testMockClient)

	// Shutdown the mock HTTP server
	ptv.shutdownMockHTTPServer()
}

func testMockClient(t *testing.T) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       timeout,
	}

	// Create NodeLiveness response
	ptv.nodeInfo = &NodeLiveness{
		BuildVersion: "v1.1",
		BuildDate:    "2019-07-30",
		State:        1,
		StartTime:    1,
		LastChange:   10,
		LastUpdate:   10,
		CommitHash:   "1234567890",
	}

	// Get response from the server
	res, err := client.Get("http://" + "localhost" + ":8080" + livenessURL)
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
	ptv.nodeInfo.BuildVersion = "v1.2"
	res, err = client.Get("http://" + "localhost" + ":8080" + livenessURL)
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
