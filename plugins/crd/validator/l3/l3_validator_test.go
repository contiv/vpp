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
	t.Run("testMissingIPAM", testMissingIPAM)
	t.Run("testMissingInterfaces", testMissingInterfaces)
	t.Run("testMissingStaticRoutes", testMissingStaticRoutes)
	t.Run("testValidateRoutesToLocalPods", testValidateRoutesToLocalPods)
	t.Run("testValidateVrf0GigERoutes", testValidateVrf0GigERoutes)
	t.Run("testValidateInterfaceLookup", testValidateInterfaceLookup)

}

func testErrorFreeEndToEnd(t *testing.T) {
	resetToInitialErrorFreeState()

	// Perform test
	vtv.report.Clear()
	vtv.l3Validator.Validate()

	// NOTE: Expect one error per node in L3 validation until we can validate
	// static routes configured through Linux
	checkDataReport(1, 3, 3)
}

func testMissingIPAM(t *testing.T) {
	resetToInitialErrorFreeState()

	// ----------------------------------------
	// INJECT FAULT: MISSING IPAM on k8s-master
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam = nil

	// Perform test
	vtv.report.Clear()
	vtv.l3Validator.Validate()

	checkDataReport(1, 1, 8)

	vrfMap, err := vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	routeMap := vtv.l3Validator.createValidationMap(vrfMap)
	numErrs := vtv.l3Validator.validateLocalVppHostNetworkRoute(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))
}

func testMissingInterfaces(t *testing.T) {
	resetToInitialErrorFreeState()

	// ----------------------------------------
	// INJECT FAULT: MISSING IPAM on k8s-master
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces = nil

	// Perform test
	vtv.report.Clear()
	vtv.l3Validator.Validate()

	// NOTE: Expect one error per node in L3 validation until we can validate
	// static routes configured through Linux
	checkDataReport(1, 1, 8)
}

func testMissingStaticRoutes(t *testing.T) {
	resetToInitialErrorFreeState()

	// ----------------------------------------
	// INJECT FAULT: MISSING IPAM on k8s-master
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeStaticRoutes = nil

	// Perform test
	vtv.report.Clear()
	vtv.l3Validator.Validate()

	// NOTE: Expect one error per node in L3 validation until we can validate
	// static routes configured through Linux
	checkDataReport(1, 1, 3)
}

func testValidateRoutesToLocalPods(t *testing.T) {
	resetToInitialErrorFreeState()

	vrfMap, err := vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	routeMap := vtv.l3Validator.createValidationMap(vrfMap)

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

	routeMap = vtv.l3Validator.createValidationMap(vrfMap)

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
			utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodVPPSubnetCIDR)
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

	routeMap = vtv.l3Validator.createValidationMap(vrfMap)
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
			utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodVPPSubnetCIDR)
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
				rte.Ipr.Type = rte.Ipr.Type + 1
				rte.Ipr.ViaVRFID = rte.Ipr.Type + 1
				vrfMap[1][rte.Ipr.DstAddr] = rte
				break
			}
		}
		break
	}

	routeMap = vtv.l3Validator.createValidationMap(vrfMap)
	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf1PodRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 5, 0)
	gomega.Expect(numErrs).To(gomega.Equal(5))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
}

func testValidateVrf0GigERoutes(t *testing.T) {
	vrfMap, err := vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	routeMap := vtv.l3Validator.createValidationMap(vrfMap)
	resetToInitialErrorFreeState()

	// --------------------------------------------------
	// INJECT FAULT: Missing route to local VPP GigE port
	delete(vrfMap[0], vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr)

	// Perform test
	vtv.report.Clear()
	numErrs := vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 1, 0)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	// ------------------------------------------------------------------
	// INJECT FAULTS: mismatched data on the route to local VPP GigE port
	// - Bad DstAddress
	// - Bad outgoing interface name
	// - Bad swIfIndex on the target outgoing interface (an interface problem,
	//   not a route problem
	gigeRoute, ok := vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr]
	gomega.Expect(ok).To(gomega.BeTrue())

	oldNextHop := gigeRoute.Ipr.DstAddr
	gigeRoute.Ipr.DstAddr = "1.2.3.4"

	oldOutIface := gigeRoute.Ipr.OutIface
	gigeRoute.Ipr.OutIface = "SomeInterfaceName"

	vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr] = gigeRoute

	intf, ok := vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(gigeRoute.IprMeta.OutgoingIfIdx)]
	gomega.Expect(ok).To(gomega.BeTrue())

	oldSwIdx := intf.IfMeta.SwIfIndex
	intf.IfMeta.SwIfIndex++
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(gigeRoute.IprMeta.OutgoingIfIdx)] = intf

	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 5, 0)
	gomega.Expect(numErrs).To(gomega.Equal(5))

	// Restore data back to error free state
	gigeRoute.Ipr.DstAddr = oldNextHop
	gigeRoute.Ipr.OutIface = oldOutIface
	vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr] = gigeRoute

	intf.IfMeta.SwIfIndex = oldSwIdx
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(gigeRoute.IprMeta.OutgoingIfIdx)] = intf

	// ------------------------------------------------------------------
	// INJECT FAULT: mismatched data on the route to local VPP GigE port
	gigeRoute, ok = vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr]
	gomega.Expect(ok).To(gomega.BeTrue())

	oldOutgoingIfIdx := gigeRoute.IprMeta.OutgoingIfIdx
	gigeRoute.IprMeta.OutgoingIfIdx++
	vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr] = gigeRoute

	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 1, 0)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	gigeRoute.IprMeta.OutgoingIfIdx = oldOutgoingIfIdx
	vrfMap[0][vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr] = gigeRoute

	// ------------------------------------------------------------------
	// INJECT FAULT: missing route to local VPP GigE port (/32)
	dstAddr := strings.Split(vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr, "/")[0] + "/32"
	delete(vrfMap[0], dstAddr)

	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 1, 0)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	vrfMap, err = vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	// ------------------------------------------------------------------
	// INJECT FAULTS: mismatched data on the route to local or remote node
	// - Bad DstAddress
	// - Bad outgoing interface name
	dstAddr = strings.Split(vtv.vppCache.NodeMap[vtv.nodeKey].IPAddr, "/")[0] + "/32"
	route, ok := vrfMap[0][dstAddr]
	gomega.Expect(ok).To(gomega.BeTrue())

	oldNextHop = gigeRoute.Ipr.DstAddr
	route.Ipr.NextHopAddr = "1.2.3.4"

	oldOutIface = route.Ipr.OutIface
	route.Ipr.OutIface = "SomeInterfaceName"

	vrfMap[0][dstAddr] = route

	// Perform test
	vtv.report.Clear()
	numErrs = vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)

	checkDataReport(0, 2, 0)
	gomega.Expect(numErrs).To(gomega.Equal(2))

	// Restore data back to error free state
	route.Ipr.NextHopAddr = oldNextHop
	route.Ipr.OutIface = oldOutIface
	vrfMap[0][dstAddr] = route

}

func testValidateInterfaceLookup(t *testing.T) {
	vrfMap, err := vtv.l3Validator.createVrfMap(vtv.vppCache.NodeMap[vtv.nodeKey])
	gomega.Expect(err).To(gomega.BeNil())

	routeMap := vtv.l3Validator.createValidationMap(vrfMap)
	resetToInitialErrorFreeState()

	// --------------------------------------------------
	// INJECT FAULT:
	// - Bad GigE interface name
	gigeIfc, err := findInterface(gigENameMatch, vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces)
	oldGigeIfName := gigeIfc.If.Name
	gigeIfc.If.Name = "SomeInterface"
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(gigeIfc.IfMeta.SwIfIndex)] = *gigeIfc

	numErrs := vtv.l3Validator.validateVrf0GigERoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	numErrs = vtv.l3Validator.validateDefaultRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	gigeIfc.If.Name = oldGigeIfName
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(gigeIfc.IfMeta.SwIfIndex)] = *gigeIfc

	// --------------------------------------------------
	// INJECT FAULT:
	// - Bad vlxanBVI interface name
	bviIfc, err := findInterface(vxlanBviName, vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces)
	oldBviIfName := gigeIfc.If.Name
	bviIfc.If.Name = "SomeInterface"
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(bviIfc.IfMeta.SwIfIndex)] = *bviIfc

	numErrs = vtv.l3Validator.validateRouteToLocalVxlanBVI(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	numErrs = vtv.l3Validator.validateRemoteNodeRoutes(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	bviIfc.If.Name = oldBviIfName
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(bviIfc.IfMeta.SwIfIndex)] = *bviIfc

	// --------------------------------------------------
	// INJECT FAULT:
	// - Bad vlxanBVI interface name
	tapIfc, err := findInterface(tap2HostName, vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces)
	oldTapIfName := gigeIfc.If.Name
	tapIfc.If.Name = "SomeInterface"
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(tapIfc.IfMeta.SwIfIndex)] = *tapIfc

	numErrs = vtv.l3Validator.validateLocalVppHostNetworkRoute(vtv.vppCache.NodeMap[vtv.nodeKey], vrfMap, routeMap)
	gomega.Expect(numErrs).To(gomega.Equal(1))

	// Restore data back to error free state
	tapIfc.If.Name = oldTapIfName
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[int(tapIfc.IfMeta.SwIfIndex)] = *tapIfc

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
