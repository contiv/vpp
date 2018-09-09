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
//

package l3

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/datastore"
	"github.com/contiv/vpp/plugins/crd/testdata"
	"github.com/contiv/vpp/plugins/crd/validator/l2"
	"github.com/contiv/vpp/plugins/crd/validator/utils"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"os"
	"strings"
	"testing"
)

type l3ValidatorTestVars struct {
	log         *logrus.Logger
	l2Validator *l2.Validator
	l3Validator *Validator
	logWriter   *mockLogWriter
	nodeKey     string

	// Mock data
	k8sNodeData []*nodemodel.Node
	k8sPodData  []*podmodel.Pod

	vppCache *datastore.VppDataStore
	k8sCache *datastore.K8sDataStore
	report   *datastore.SimpleReport
}

// mockLogWriter collects all error logs into a buffer for analysis
// by gomega assertions.
type mockLogWriter struct {
	log []string
}

func (mlw *mockLogWriter) Write(p []byte) (n int, err error) {
	logStr := string(p)
	mlw.log = append(mlw.log, logStr)
	return len(logStr), nil
}

func (mlw *mockLogWriter) clearLog() {
	mlw.log = []string{}
}

func (mlw *mockLogWriter) printLog() {
	fmt.Println("Error log:")
	fmt.Println("==========")
	for i, l := range mlw.log {
		fmt.Printf("%d: %s", i, l)
	}
}

func (mlw *mockLogWriter) countErrors() int {
	cnt := 0
	for _, logLine := range mlw.log {
		if strings.Contains(logLine, "level=error") {
			cnt++
		}
	}
	return cnt
}

var vtv l3ValidatorTestVars

func TestValidator(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	vtv.logWriter = &mockLogWriter{log: []string{}}
	vtv.log = logrus.DefaultLogger()
	vtv.log.SetLevel(logging.ErrorLevel)
	vtv.log.SetOutput(vtv.logWriter)

	vtv.nodeKey = "k8s-master"
	vtv.vppCache = datastore.NewVppDataStore()
	vtv.k8sCache = datastore.NewK8sDataStore()
	vtv.report = datastore.NewSimpleReport(vtv.log)

	// Initialize the validators
	vtv.l2Validator = &l2.Validator{
		Log:      vtv.log,
		VppCache: vtv.vppCache,
		K8sCache: vtv.k8sCache,
		Report:   vtv.report,
	}

	vtv.l3Validator = &Validator{
		Log:      vtv.log,
		VppCache: vtv.vppCache,
		K8sCache: vtv.k8sCache,
		Report:   vtv.report,
	}

	// Do the testing
	t.Run("testErrorFreeEndToEnd", testErrorFreeEndToEnd)

	t.Run("testValidateRoutesToLocalPods", testValidateRoutesToLocalPods)

}

func testErrorFreeEndToEnd(t *testing.T) {
	resetToInitialErrorFreeState()

	// Perform test
	vtv.report.Clear()
	vtv.l3Validator.Validate()

	checkDataReport(1, 0, 0)
}

func testValidateRoutesToLocalPods(t *testing.T) {
	vrfMap, err := vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	// ----------------------------------
	// INJECT FAULT: Route to Pod missing
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		routes := vtv.vppCache.NodeMap[vtv.nodeKey].NodeStaticRoutes
		for _, rte := range routes {
			if rte.Ipr.DstAddr == pod.IPAddress+"/32" {
				delete(vrfMap[1], rte.Ipr.DstAddr)
				break
			}
		}
		break
	}

	routeMap := make(map[string]bool)
	// Perform test
	vtv.report.Clear()
	numErrs := vtv.l3Validator.validateVrf1PodRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 1, 0)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])

	// ----------------------------------------------------
	// INJECT FAULTS:
	// - Bad next hop in the route for a Pod
	// - Bad outgoing interface name in the route for a Pod
	// - Bad outgoing swIfIndex in the route for a Pod
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		routes := vtv.vppCache.NodeMap[vtv.nodeKey].NodeStaticRoutes
		for _, rte := range routes {
			if rte.Ipr.DstAddr == pod.IPAddress+"/32" {
				rte.Ipr.NextHopAddr = "1.2.3.4"
				rte.IprMeta.OutgoingIfIdx = rte.IprMeta.OutgoingIfIdx + 1
				rte.Ipr.OutIface = "someInterfaceName"
				vrfMap[1][rte.Ipr.DstAddr] = rte
				break
			}
		}
		break
	}

	routeMap = make(map[string]bool)

	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf1PodRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 3, 0)
	gomega.Expect(numErrs).To(gomega.Equal(3))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])

	// ----------------------------------------------------------------
	// INJECT FAULT: Route to vpp-side pod-facing tap interface missing
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		podIfIPAddr, podIfIPMask, err :=
			utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodIfIPCIDR)
		gomega.Expect(err).To(gomega.BeNil())
		podIfIPPrefix := podIfIPAddr &^ podIfIPMask

		routes := vtv.vppCache.NodeMap[vtv.nodeKey].NodeStaticRoutes
		for _, rte := range routes {
			rteIfIPAddr, _, err := utils.Ipv4CidrToAddressAndMask(rte.Ipr.DstAddr)
			gomega.Expect(err).To(gomega.BeNil())

			rteIfIPPrefix := rteIfIPAddr &^ podIfIPMask
			if rteIfIPPrefix == podIfIPPrefix {
				delete(vrfMap[1], rte.Ipr.DstAddr)
				break
			}
		}
		break
	}

	routeMap = make(map[string]bool)
	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf1PodRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 1, 0)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])

	// -----------------------------------------------------------------------
	// INJECT FAULTS:
	// - Bad next hop in the route to pod-facing tqp interface
	// - Bad outgoing interface name in the route to pod-facing tqp interface
	// - Bad outgoing swIfIndex in the route to pod-facing tqp interface
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		podIfIPAddr, podIfIPMask, err :=
			utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodIfIPCIDR)
		gomega.Expect(err).To(gomega.BeNil())
		podIfIPPrefix := podIfIPAddr &^ podIfIPMask

		routes := vtv.vppCache.NodeMap[vtv.nodeKey].NodeStaticRoutes
		for _, rte := range routes {
			rteIfIPAddr, _, err := utils.Ipv4CidrToAddressAndMask(rte.Ipr.DstAddr)
			gomega.Expect(err).To(gomega.BeNil())

			rteIfIPPrefix := rteIfIPAddr &^ podIfIPMask
			if rteIfIPPrefix == podIfIPPrefix {
				rte.Ipr.NextHopAddr = "1.2.3.4"
				rte.IprMeta.OutgoingIfIdx = rte.IprMeta.OutgoingIfIdx + 1
				rte.Ipr.OutIface = "someInterfaceName"
				vrfMap[1][rte.Ipr.DstAddr] = rte
				break
			}
		}
		break
	}

	routeMap = make(map[string]bool)
	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf1PodRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 3, 0)
	gomega.Expect(numErrs).To(gomega.Equal(3))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
}

func resetToInitialErrorFreeState() {
	vtv.vppCache.ReinitializeCache()
	vtv.k8sCache.ReinitializeCache()
	vtv.report.Clear()
	vtv.logWriter.clearLog()

	if err := testdata.CreateNodeTestData(vtv.vppCache); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	if err := testdata.CreateK8sPodTestData(vtv.k8sCache); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	if err := testdata.CreateK8sNodeTestData(vtv.k8sCache); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	for _, node := range vtv.vppCache.RetrieveAllNodes() {
		errReport := vtv.l3Validator.VppCache.SetSecondaryNodeIndices(node)
		for _, r := range errReport {
			vtv.l3Validator.Report.AppendToNodeReport(node.Name, r)
		}

		// Code replicated from ContivTelemetryCache.populateNodeMaps() -
		// need to inject pod data into each node.
		for _, pod := range vtv.k8sCache.RetrieveAllPods() {
			if pod.HostIPAddress == node.ManIPAddr {
				node.PodMap[pod.Name] = pod
			}
		}
	}

	// ValidatePodInfo() will initialize each node's pod structures that are
	// required for L3 validation.
	vtv.l2Validator.ValidatePodInfo()
}

func checkDataReport(globalCnt int, nodeKeyCnt int, defaultCnt int) {
	for k := range vtv.report.Data {
		switch k {
		case api.GlobalMsg:
			gomega.Expect(len(vtv.report.Data[k])).To(gomega.Equal(globalCnt))
		case vtv.nodeKey:
			gomega.Expect(len(vtv.report.Data[k])).To(gomega.Equal(nodeKeyCnt))
		default:
			gomega.Expect(len(vtv.report.Data[k])).To(gomega.Equal(defaultCnt))
		}
	}
}
