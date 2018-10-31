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
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
	"github.com/contiv/vpp/plugins/crd/testdata"
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

type mockCRDReport struct {
	rep *datastore.SimpleReport
}

func (mcr *mockCRDReport) GenerateCRDReport() {
	mcr.rep.Print()
}

type cacheTestVars struct {
	srv            *http.Server
	injectError    int
	log            *logrus.Logger
	logWriter      *mockLogWriter
	client         *http.Client
	telemetryCache *ContivTelemetryCache
	tickerChan     chan time.Time

	// Mock data
	nodeLiveness      *telemetrymodel.NodeLiveness
	nodeInterfaces    map[int]telemetrymodel.NodeInterface
	nodeBridgeDomains map[int]telemetrymodel.NodeBridgeDomain
	nodeL2Fibs        map[string]telemetrymodel.NodeL2FibEntry
	nodeIPArps        []telemetrymodel.NodeIPArpEntry
	nodeIPRoutes      []telemetrymodel.NodeIPRoute

	report *datastore.SimpleReport
}

var ctv cacheTestVars

func (ptv *cacheTestVars) startMockHTTPServer() {
	ptv.srv = &http.Server{Addr: testAgentPort}

	go func() {
		if err := ptv.srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			ptv.log.Errorf("Httpserver: ListenAndServe() error: %s", err.Error())
			gomega.Expect(err).To(gomega.BeNil())
		}
	}()
}

func registerHTTPHandlers() {
	// Register handler for all test data
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if ctv.injectError == inject404Error {
			w.WriteHeader(404)
			w.Write([]byte("page not found - invalid path: " + r.URL.Path))
			return
		}

		if ctv.injectError == injectDelay {
			time.Sleep(3 * time.Second)
		}

		var data interface{}

		switch r.URL.Path {
		case livenessURL:
			data = ctv.nodeLiveness
		case nodeInterfaceURL:
			data = ctv.nodeInterfaces
		case l2FibsURL:
			data = ctv.nodeL2Fibs
		case bridgeDomainURL:
			data = ctv.nodeBridgeDomains
		case arpURL:
			data = ctv.nodeIPArps
		case staticRouteURL:
			data = ctv.nodeIPRoutes
		default:
			ctv.log.Error("unknown URL: ", r.URL)
			w.WriteHeader(404)
			w.Write([]byte("Unknown path" + r.URL.Path))
			return
		}

		buf, err := json.Marshal(data)
		if err != nil {
			ctv.log.Error("Error marshalling NodeInfo data, err: ", err)
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "application/json")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	})

}

func (ptv *cacheTestVars) shutdownMockHTTPServer() {
	if err := ptv.srv.Shutdown(context.TODO()); err != nil {
		panic(err)
	}
}

func TestTelemetryCache(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize the mock logger
	ctv.logWriter = &mockLogWriter{log: []string{}}
	ctv.log = logrus.DefaultLogger()
	ctv.log.SetLevel(logging.DebugLevel)
	ctv.log.SetOutput(ctv.logWriter)

	// Initialize report
	ctv.report = datastore.NewSimpleReport(ctv.log)
	// Suppress printing of output report to screen during testing
	ctv.report.Output = &nullWriter{}

	// Init the mock HTTP Server
	ctv.startMockHTTPServer()
	registerHTTPHandlers()
	ctv.injectError = noError

	ctv.client = &http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       clientTimeout,
	}

	// Init the cache and the telemetryCache (the objects under test)
	ctv.telemetryCache = NewTelemetryCache(logging.ForPlugin("tc-test"))
	ctv.telemetryCache.Processor = &mockProcessor{}
	ctv.telemetryCache.ControllerReport = &mockCRDReport{rep: ctv.report}

	// Override default telemetryCache behavior
	ctv.tickerChan = make(chan time.Time)
	ctv.telemetryCache.ticker.Stop() // Do not periodically poll agents
	ctv.telemetryCache.ticker = &time.Ticker{C: ctv.tickerChan}

	// Override agentPort
	ctv.telemetryCache.agentPort = testAgentPort

	// override default cache logger
	ctv.telemetryCache.Log = ctv.log

	ctv.report = datastore.NewSimpleReport(ctv.log)
	ctv.report.Output = &nullWriter{}
	ctv.telemetryCache.Report = ctv.report

	// Run cache init
	ctv.telemetryCache.Init()

	// Init & populate the test data
	testdata.CreateNodeTestData(ctv.telemetryCache.VppCache)
	nodeKey := "k8s-master"
	node, err := ctv.telemetryCache.VppCache.RetrieveNode(nodeKey)
	gomega.Expect(err).To(gomega.BeNil())

	ctv.nodeInterfaces = node.NodeInterfaces
	ctv.nodeBridgeDomains = node.NodeBridgeDomains
	ctv.nodeIPArps = node.NodeIPArp
	ctv.nodeL2Fibs = node.NodeL2Fibs
	ctv.nodeLiveness = node.NodeLiveness
	ctv.nodeIPRoutes = node.NodeStaticRoutes

	// Do the testing
	t.Run("collectAgentInfoNoError", testCollectAgentInfoNoError)
	t.Run("collectAgentInfoWithHTTPError", testCollectAgentInfoWithHTTPError)
	t.Run("collectAgentInfoWithTimeout", testCollectAgentInfoWithTimeout)
	t.Run("collectAgentInfoValidationInProgress", testCollectAgentInfoValidationInProgress)

	// Shutdown the mock HTTP server
	// ctv.shutdownMockHTTPServer()
}

func testCollectAgentInfoNoError(t *testing.T) {
	ctv.telemetryCache.VppCache.CreateNode(1, "k8s-master", "10.20.0.2", "localhost")

	node, err := ctv.telemetryCache.VppCache.RetrieveNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())

	// Kick the telemetryCache to collect & validate data, give it an opportunity
	// to run and wait for it to complete
	ctv.tickerChan <- time.Time{}
	ctv.telemetryCache.waitForValidationToFinish()

	gomega.Expect(node.NodeLiveness).To(gomega.BeEquivalentTo(ctv.nodeLiveness))
	gomega.Expect(node.NodeInterfaces).To(gomega.BeEquivalentTo(ctv.nodeInterfaces))
	gomega.Expect(node.NodeBridgeDomains).To(gomega.BeEquivalentTo(ctv.nodeBridgeDomains))
	gomega.Expect(node.NodeL2Fibs).To(gomega.BeEquivalentTo(ctv.nodeL2Fibs))
	gomega.Expect(node.NodeIPArp).To(gomega.BeEquivalentTo(ctv.nodeIPArps))
	gomega.Expect(node.NodeStaticRoutes).To(gomega.BeEquivalentTo(ctv.nodeIPRoutes))
}

func testCollectAgentInfoWithHTTPError(t *testing.T) {
	ctv.logWriter.clearLog()
	ctv.telemetryCache.ReinitializeCache()
	ctv.telemetryCache.VppCache.CreateNode(1, "k8s-master", "10.20.0.2", "localhost")

	_, err := ctv.telemetryCache.VppCache.RetrieveNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	ctv.injectError = inject404Error

	// Kick the telemetryCache to collect & validate data, give it an opportunity
	// to run and wait for it to complete
	// ctv.tickerChan <- time.Time{}
	ctv.tickerChan <- time.Time{}
	ctv.telemetryCache.waitForValidationToFinish()

	gomega.Expect(grep(ctv.report.Data["k8s-master"], "404 Not Found")).To(gomega.Equal(numDTOs))
}

func testCollectAgentInfoWithTimeout(t *testing.T) {
	ctv.logWriter.clearLog()
	ctv.telemetryCache.ReinitializeCache()

	ctv.telemetryCache.httpClientTimeout = 1
	ctv.telemetryCache.VppCache.CreateNode(1, "k8s-master", "10.20.0.2", "localhost")

	_, err := ctv.telemetryCache.VppCache.RetrieveNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	ctv.injectError = injectDelay

	// Kick the telemetryCache to collect & validate data, give it an opportunity
	// to run and wait for it to complete
	ctv.tickerChan <- time.Time{}
	ctv.telemetryCache.waitForValidationToFinish()

	gomega.Expect(grep(ctv.report.Data["k8s-master"], "Timeout exceeded")).
		To(gomega.Equal(numDTOs))
}

func testCollectAgentInfoValidationInProgress(t *testing.T) {
	ctv.logWriter.clearLog()
	ctv.telemetryCache.ReinitializeCache()

	ctv.telemetryCache.validationInProgress = true

	ctv.tickerChan <- time.Time{}
	time.Sleep(1 * time.Millisecond)

	ctv.telemetryCache.validationInProgress = false

	gomega.Expect(grep(ctv.logWriter.log, "Skipping data collection")).To(gomega.Equal(1))
}

func grep(output []string, pattern string) int {
	cnt := 0
	for _, l := range output {
		if strings.Contains(l, pattern) {
			cnt++
		}
	}
	return cnt
}
