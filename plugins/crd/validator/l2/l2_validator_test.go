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

package l2

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
	"github.com/contiv/vpp/plugins/crd/validator/testdata"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/onsi/gomega"
	"os"
	"strings"
	"testing"
)

type l2ValidatorTestVars struct {
	log         *logrus.Logger
	l2Validator *Validator
	logWriter   *mockLogWriter

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

var vtv l2ValidatorTestVars

func TestValidator(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	vtv.logWriter = &mockLogWriter{log: []string{}}
	vtv.log = logrus.DefaultLogger()
	vtv.log.SetLevel(logging.ErrorLevel)
	vtv.log.SetOutput(vtv.logWriter)

	vtv.vppCache = datastore.NewVppDataStore()
	vtv.k8sCache = datastore.NewK8sDataStore()
	vtv.report = datastore.NewSimpleReport(vtv.log)

	// Initialize the validator
	vtv.l2Validator = &Validator{
		Log:      vtv.log,
		VppCache: vtv.vppCache,
		K8sCache: vtv.k8sCache,
		Report:   vtv.report,
	}

	// Do the testing
	t.Run("testErrorFreeTopologyValidation", testErrorFreeTopologyValidation)
	t.Run("testK8sNodeToNodeInfoOkValidation", testK8sNodeToNodeInfoOkValidation)
	t.Run("testK8sNodeToNodeInfoMissingNiValidation", testK8sNodeToNodeInfoMissingNiValidation)
	t.Run("testK8sNodeToNodeInfoMissingK8snValidation", testK8sNodeToNodeInfoMissingK8snValidation)
	t.Run("testNodesDBValidateL2Connections", testNodesDBValidateL2Connections)
	t.Run("testValidateL2FibEntries", testValidateL2FibEntries)
}

func testErrorFreeTopologyValidation(t *testing.T) {
	resetToInitialErrorFreeState()

	vtv.l2Validator.Validate()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(4))
}

func testK8sNodeToNodeInfoOkValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	vtv.l2Validator.ValidateK8sNodeInfo()
	gomega.Expect(len(vtv.report.Data)).To(gomega.Equal(0))
}

func testK8sNodeToNodeInfoMissingNiValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	// INJECT FAULT:: missing vpp node
	vtv.l2Validator.VppCache.DeleteNode("k8s-master")

	vtv.l2Validator.ValidateK8sNodeInfo()
	gomega.Expect(len(vtv.report.Data["k8s-master"])).To(gomega.Equal(1))
}

func testK8sNodeToNodeInfoMissingK8snValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	// INJECT FAULT:: missing K8s node
	vtv.l2Validator.K8sCache.DeleteK8sNode("k8s-master")

	vtv.l2Validator.ValidateK8sNodeInfo()
	gomega.Expect(len(vtv.report.Data["k8s-master"])).To(gomega.Equal(2))
}

func testNodesDBValidateL2Connections(t *testing.T) {
	nodeKey := "k8s-master"
	resetToInitialErrorFreeState()

	// ----------------------------------------------------------------------
	// INJECT FAULT: Add a bogus bridge domain with the same name as VxlanBD.
	bd := vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains
	gomega.Expect(len(bd)).To(gomega.Equal(1))

	bogusBd := telemetrymodel.NodeBridgeDomain{
		Bd: telemetrymodel.BridgeDomain{
			Name: vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains[1].Bd.Name,
		},
		BdMeta: telemetrymodel.BridgeDomainMeta{
			BdID: 2,
			BdID2Name: telemetrymodel.BdID2NameMapping{
				2: vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains[1].Bd.Name,
			},
		},
	}
	bd[2] = bogusBd

	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(2))

	delete(bd, 2)

	// --------------------------------------------------------------------
	// INJECT FAULT: No Bridge Domain present on node;
	// NOTE: This TC MUST be executed after the previous one, it depends on
	// the same setup
	delete(bd, 1)

	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(2))

	resetToInitialErrorFreeState()

	// INJECT FAULT: Set node/k8s-master interface/5 vxlan_vni to 11
	k, ifp := vtv.findFirstVxlanInterface(nodeKey)
	gomega.Expect(ifp).To(gomega.Not(gomega.BeNil()))
	ifp.If.Vxlan.Vni = 11
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(1))

	// Restore data back to error free state
	ifp.If.Vxlan.Vni = 10
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	// -----------------------------------------------------------------
	// INJECT FAULT: Set bogus destination IP address on node/k8s-master
	// first found vxlan_interface
	k, ifp = vtv.findFirstVxlanInterface(nodeKey)
	gomega.Expect(ifp).To(gomega.Not(gomega.BeNil()))
	dstIPAddr := ifp.If.Vxlan.DstAddress
	ifp.If.Vxlan.DstAddress = "1.2.3.4"
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))
	node, err := vtv.vppCache.RetrieveNodeByGigEIPAddr(dstIPAddr)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(vtv.report.Data[node.Name])).To(gomega.Equal(1))

	// Restore data back to error free state
	ifp.If.Vxlan.DstAddress = dstIPAddr
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	// ----------------------------------------
	// INJECT FAULT: Invalid BD interface index
	nbd := vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains
	gomega.Expect(len(nbd)).To(gomega.Equal(1))

	for _, vxlanBd := range nbd {
		// Create an invalid ifIndex for a BD interface (invalid key in the BdID2Name map)
		keys := make([]uint32, 0)
		for k := range vxlanBd.BdMeta.BdID2Name {
			keys = append(keys, k)
		}

		bogusKey := keys[0] * 100
		vxlanBd.BdMeta.BdID2Name[bogusKey] = vxlanBd.BdMeta.BdID2Name[keys[0]]
		delete(vxlanBd.BdMeta.BdID2Name, keys[0])

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateL2Connectivity()

		gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
		gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))

		// Restore data back to error free state
		vxlanBd.BdMeta.BdID2Name[keys[0]] = vxlanBd.BdMeta.BdID2Name[bogusKey]
		delete(vxlanBd.BdMeta.BdID2Name, bogusKey)

		break
	}

	// ----------------------------------------------------------------------
	// INJECT FAULT: Duplicate BVI interface
	nbd = vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains
	for j, vxlanBd := range nbd {

		// Make sure there are multiple BVI interfaces on the BD
		var k int
		for k = range vxlanBd.Bd.Interfaces {
			if !vxlanBd.Bd.Interfaces[k].BVI {
				vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains[j].Bd.Interfaces[k].BVI = true
				break
			}
		}

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateL2Connectivity()

		gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
		gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(5))

		// Restore data back to error free state
		vtv.vppCache.NodeMap[nodeKey].NodeBridgeDomains[j].Bd.Interfaces[k].BVI = false

		break
	}

	// -----------------------------------------------------------
	// INJECT FAULT: Invalid interface type in a non-BVI interface
	k, ifp = vtv.findFirstVxlanInterface(nodeKey)
	gomega.Expect(ifp).To(gomega.Not(gomega.BeNil()))
	ifp.If.IfType = interfaces.InterfaceType_TAP_INTERFACE
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))
	node, err = vtv.vppCache.RetrieveNodeByGigEIPAddr(ifp.If.Vxlan.DstAddress)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(vtv.report.Data[node.Name])).To(gomega.Equal(1))

	// Restore data back to error free state
	ifp.If.IfType = interfaces.InterfaceType_VXLAN_TUNNEL
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	// ------------------------------------------------
	// INJECT FAULT: Invalid node GigE IP Address index
	vtv.vppCache.GigEIPMap = make(map[string]*telemetrymodel.Node, 0)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(6))
	}

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -------------------------------------------------
	// INJECT FAULT: Invalid node loop MAC Address index
	vtv.vppCache.LoopMACMap = make(map[string]*telemetrymodel.Node, 0)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(3))
	}

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -------------------------------------------------
	// INJECT FAULT: Invalid entry in the GigE IP Address map
	nl := vtv.vppCache.RetrieveAllNodes()
	gomega.Expect(len(nl)).To(gomega.BeNumerically(">=", 2))
	a0 := strings.Split(nl[0].IPAddr, "/")
	a1 := strings.Split(nl[1].IPAddr, "/")
	vtv.vppCache.GigEIPMap[a0[0]] = vtv.vppCache.GigEIPMap[a1[0]]

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nl[0].Name])).To(gomega.Equal(6))

	// Restore data back to error free state
	resetToInitialErrorFreeState()
}

func testValidateL2FibEntries(t *testing.T) {
	nodeKey := "k8s-master"
	resetToInitialErrorFreeState()

	// -------------------------------------------
	// INJECT FAULT: Wrong number of L2Fib entries
	node, err := vtv.l2Validator.VppCache.RetrieveNode(nodeKey)
	gomega.Expect(err).To(gomega.BeNil())
	bogusFibKey := "90:87:65:43:21"
	node.NodeL2Fibs[bogusFibKey] = telemetrymodel.NodeL2FibEntry{
		Fe: telemetrymodel.L2FibEntry{
			BridgeDomainName:        "vxlanBD",
			OutgoingIfName:          "vxlan10",
			PhysAddress:             bogusFibKey,
			StaticConfig:            true,
			BridgedVirtualInterface: false,
		},
		FeMeta: telemetrymodel.L2FibEntryMeta{
			BridgeDomainID:  1,
			OutgoingIfIndex: 100,
		},
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(2))

	// Restore data back to error free state
	delete(node.NodeL2Fibs, bogusFibKey)

	// ------------------------------------------------
	// INJECT FAULT: Missing loop interface on the node
	node, err = vtv.l2Validator.VppCache.RetrieveNode(nodeKey)
	gomega.Expect(err).To(gomega.BeNil())
	for k, ifc := range node.NodeInterfaces {
		if ifc.IfMeta.VppInternalName == "loop0" {
			ifc.IfMeta.VppInternalName = "bogusName"
			node.NodeInterfaces[k] = ifc
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(2))
	}

	// Restore data back to error free state
	for k, ifc := range node.NodeInterfaces {
		if ifc.IfMeta.VppInternalName == "bogusName" {
			ifc.IfMeta.VppInternalName = "loop0"
			node.NodeInterfaces[k] = ifc
			break
		}
	}

	// ------------------------------------------------
	// INJECT FAULT: Missing loop interface L2Fib entry
	node, err = vtv.l2Validator.VppCache.RetrieveNode(nodeKey)
	gomega.Expect(err).To(gomega.BeNil())

	var key string
	var fibEntry telemetrymodel.NodeL2FibEntry
	for key, fibEntry = range node.NodeL2Fibs {
		if fibEntry.Fe.BridgedVirtualInterface {
			delete(node.NodeL2Fibs, key)
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	//for _, n := range vtv.vppCache.RetrieveAllNodes() {
	//	gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(2))
	//}

	// Restore data back to error free state
	node.NodeL2Fibs[key] = fibEntry

	// -------------------------------------------------
	// INJECT FAULT: Invalid entry in the Loop MAC Address map
	vtv.vppCache.LoopMACMap = make(map[string]*telemetrymodel.Node, 0)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(5))
	}

	// Restore data back to error free state
	resetToInitialErrorFreeState()

}

func (v *l2ValidatorTestVars) findFirstVxlanInterface(nodeKey string) (int, *telemetrymodel.NodeInterface) {
	for k, ifc := range v.vppCache.NodeMap[nodeKey].NodeInterfaces {
		if ifc.If.IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
			return k, &ifc
		}
	}
	return -1, nil
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
		errReport := vtv.l2Validator.VppCache.SetSecondaryNodeIndices(node)
		for _, r := range errReport {
			vtv.l2Validator.Report.AppendToNodeReport(node.Name, r)
		}

		// Code replicated from ContivTelemetryCache.populateNodeMaps() -
		// need to inject pod data into each node.
		for _, pod := range vtv.k8sCache.RetrieveAllPods() {
			if pod.HostIPAddress == node.ManIPAddr {
				node.PodMap[pod.Name] = pod
			}
		}
	}
}
