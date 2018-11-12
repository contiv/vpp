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
	"github.com/contiv/vpp/plugins/crd/testdata"
	"github.com/contiv/vpp/plugins/crd/validator/utils"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/onsi/gomega"
	"os"
	"regexp"
	"strings"
	"testing"
)

type l2ValidatorTestVars struct {
	log         *logrus.Logger
	l2Validator *Validator
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
	t.Run("testMissingIPAMTopologyValidation", testMissingIPAMTopologyValidation)
	t.Run("testK8sNodeToNodeInfoOkValidation", testK8sNodeToNodeInfoOkValidation)
	t.Run("testK8sNodeToNodeInfoMissingNiValidation", testK8sNodeToNodeInfoMissingNiValidation)
	t.Run("testK8sNodeToNodeInfoMissingK8snValidation", testK8sNodeToNodeInfoMissingK8snValidation)
	t.Run("testNodesDBValidateL2Connections", testNodesDBValidateL2Connections)
	t.Run("testValidateL2FibEntries", testValidateL2FibEntries)
	t.Run("testValidateArpEntries", testValidateArpEntries)
	t.Run("testValidatePodInfo", testValidatePodInfo)

}

func testErrorFreeTopologyValidation(t *testing.T) {
	resetToInitialErrorFreeState()

	vtv.l2Validator.Validate()

	checkDataReport(5, 0, 0)
}

func testMissingIPAMTopologyValidation(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// INJECT FAULT: Missing IPAM on k8s-master
	vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam = nil

	vtv.l2Validator.Validate()

	checkDataReport(5, 3, 0)
}

func testK8sNodeToNodeInfoOkValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	vtv.l2Validator.ValidateK8sNodeInfo()

	checkDataReport(1, 0, 0)
}

func testK8sNodeToNodeInfoMissingNiValidation(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// INJECT FAULT:: missing vpp node
	vtv.l2Validator.VppCache.DeleteNode(vtv.nodeKey)

	vtv.l2Validator.ValidateK8sNodeInfo()

	checkDataReport(1, 1, 0)
}

func testK8sNodeToNodeInfoMissingK8snValidation(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// INJECT FAULT:: missing K8s node
	vtv.l2Validator.K8sCache.DeleteK8sNode(vtv.nodeKey)

	vtv.l2Validator.ValidateK8sNodeInfo()
	checkDataReport(1, 2, 0)
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
	vtv.l2Validator.ValidateBridgeDomains()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(1))

	delete(bd, 2)

	// --------------------------------------------------------------------
	// INJECT FAULT: No Bridge Domain present on node;
	// NOTE: This TC MUST be executed after the previous one, it depends on
	// the same setup
	delete(bd, 1)

	vtv.report.Clear()
	vtv.l2Validator.ValidateBridgeDomains()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(1))

	resetToInitialErrorFreeState()

	// INJECT FAULT: Set node/k8s-master interface/5 vxlan_vni to 11
	k, ifp := vtv.findFirstVxlanInterface(nodeKey)
	gomega.Expect(ifp).To(gomega.Not(gomega.BeNil()))
	ifp.If.Vxlan.Vni = 11
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	vtv.report.Clear()
	vtv.l2Validator.ValidateBridgeDomains()
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
	vtv.l2Validator.ValidateBridgeDomains()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(3))
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
		vtv.l2Validator.ValidateBridgeDomains()

		gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
		gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(3))

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
		vtv.l2Validator.ValidateBridgeDomains()

		gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
		gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))

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
	vtv.l2Validator.ValidateBridgeDomains()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(3))
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
	vtv.l2Validator.ValidateBridgeDomains()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(5))
	}

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -------------------------------------------------
	// INJECT FAULT: Invalid node loop MAC Address index
	vtv.vppCache.LoopMACMap = make(map[string]*telemetrymodel.Node, 0)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateBridgeDomains()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	for _, n := range vtv.vppCache.RetrieveAllNodes() {
		gomega.Expect(len(vtv.report.Data[n.Name])).To(gomega.Equal(2))
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
	vtv.l2Validator.ValidateBridgeDomains()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nl[0].Name])).To(gomega.Equal(5))

	// Restore data back to error free state
	resetToInitialErrorFreeState()
}

func testValidateL2FibEntries(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// -------------------------------------------
	// INJECT FAULT: Wrong number of L2Fib entries
	node, err := vtv.l2Validator.VppCache.RetrieveNode(vtv.nodeKey)
	gomega.Expect(err).To(gomega.BeNil())
	bdID, err := getVxlanBD(node)
	gomega.Expect(err).To(gomega.BeNil())

	bogusFibKey1 := "90:87:65:43:21"
	node.NodeL2Fibs[bogusFibKey1] = telemetrymodel.NodeL2FibEntry{
		Fe: telemetrymodel.L2FibEntry{
			BridgeDomainName:        "vxlanBD",
			OutgoingIfName:          "vxlan10",
			PhysAddress:             bogusFibKey1,
			StaticConfig:            true,
			BridgedVirtualInterface: false,
		},
		FeMeta: telemetrymodel.L2FibEntryMeta{
			BridgeDomainID:  uint32(bdID),
			OutgoingIfIndex: 100,
		},
	}

	// Inject L2FIB entry for another BD  into L2FIB
	bogusFibKey2 := "90:87:65:43:22"
	node.NodeL2Fibs[bogusFibKey2] = telemetrymodel.NodeL2FibEntry{
		Fe: telemetrymodel.L2FibEntry{
			BridgeDomainName: "anotherBd",
		},
		FeMeta: telemetrymodel.L2FibEntryMeta{
			BridgeDomainID: uint32(bdID) + 1,
		},
	}

	// Inject non-static L2FIB entry into L2FIB
	bogusFibKey3 := "90:87:65:43:23"
	node.NodeL2Fibs[bogusFibKey3] = telemetrymodel.NodeL2FibEntry{
		Fe: telemetrymodel.L2FibEntry{
			BridgeDomainName: "vxlanBD",
			StaticConfig:     false,
		},
		FeMeta: telemetrymodel.L2FibEntryMeta{
			BridgeDomainID: 1,
		},
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 2, 0)

	// Restore data back to error free state
	delete(node.NodeL2Fibs, bogusFibKey1)
	delete(node.NodeL2Fibs, bogusFibKey2)
	delete(node.NodeL2Fibs, bogusFibKey3)

	// --------------------------------------------------
	// INJECT FAULT: Missing loop interface on local node
	node, err = vtv.l2Validator.VppCache.RetrieveNode(vtv.nodeKey)
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

	checkDataReport(1, 1, 1)

	// Restore data back to error free state
	for k, ifc := range node.NodeInterfaces {
		if ifc.IfMeta.VppInternalName == "bogusName" {
			ifc.IfMeta.VppInternalName = "loop0"
			node.NodeInterfaces[k] = ifc
			break
		}
	}

	// ------------------------------------------------------------
	// INJECT FAULT: Bad MAC address on local node's loop interface
	node, err = vtv.l2Validator.VppCache.RetrieveNode(vtv.nodeKey)
	gomega.Expect(err).To(gomega.BeNil())
	loopIf, err := datastore.GetNodeLoopIFInfo(node)
	gomega.Expect(err).To(gomega.BeNil())
	prevMacAddr := loopIf.If.PhysAddress
	loopIf.If.PhysAddress = "90:87:65:43:22"
	node.NodeInterfaces[int(loopIf.IfMeta.SwIfIndex)] = *loopIf

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 1, 1)

	// Restore data back to error free state
	loopIf.If.PhysAddress = prevMacAddr
	node.NodeInterfaces[int(loopIf.IfMeta.SwIfIndex)] = *loopIf

	// ----------------------------------------------------
	// INJECT FAULT: Missing L2Fib entry for the local node
	node, err = vtv.l2Validator.VppCache.RetrieveNode(vtv.nodeKey)
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

	checkDataReport(1, 2, 0)

	// Restore data back to error free state
	node.NodeL2Fibs[key] = fibEntry

	// -------------------------------------------------------
	// INJECT FAULT: Invalid entry in the Loop MAC Address map
	vtv.vppCache.LoopMACMap = make(map[string]*telemetrymodel.Node, 0)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 4, 4)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// ---------------------------------------------------
	// INJECT FAULT: Missing L2Fib entry for a remote node
	for k, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeL2Fibs {
		if !v.Fe.BridgedVirtualInterface {
			delete(vtv.vppCache.NodeMap[vtv.nodeKey].NodeL2Fibs, k)
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 1, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// --------------------------------------------------------------------
	// INJECT FAULT: Invalid VXLAN Destination IP address for a remote node
	for k, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces {
		if v.If.IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
			v.If.Vxlan.DstAddress = "1.2.3.4"
			vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[k] = v
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 3, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -------------------------------------
	// INJECT FAULT: Vxlan BD does not exist
	for k, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeBridgeDomains {
		if v.Bd.Name == "vxlanBD" {
			v.Bd.Name = "anotherBdName"
			vtv.vppCache.NodeMap[vtv.nodeKey].NodeBridgeDomains[k] = v
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidateL2FibEntries()

	checkDataReport(1, 1, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()
}

func testValidateArpEntries(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// ----------------------------------------------
	// INJECT FAULT: Invalid IfIndex in the ARP entry
	for i, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp {
		v.AeMeta.IfIndex = v.AeMeta.IfIndex + 100
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i] = v

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateArpTables()

		checkDataReport(1, 2, 0)

		// Restore data back to error free state
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i].AeMeta.IfIndex = v.AeMeta.IfIndex - 100
		break
	}

	// --------------------------------------------------
	// INJECT FAULT: Invalid MAC Address in the ARP entry
	for i, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp {
		oldPhyAddress := v.Ae.PhysAddress
		v.Ae.PhysAddress = "ff:ee:dd:cc:bb:aa"
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i] = v

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateArpTables()

		checkDataReport(1, 2, 0)

		// Restore data back to error free state
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i].Ae.PhysAddress = oldPhyAddress
		break
	}

	// -------------------------------------------------
	// INJECT FAULT: Invalid IP Address in the ARP entry
	for i, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp {
		oldIPAddress := v.Ae.IPAddress
		v.Ae.IPAddress = "1.2.3.4"
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i] = v

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateArpTables()

		checkDataReport(1, 2, 0)

		// Restore data back to error free state
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i].Ae.IPAddress = oldIPAddress
		break
	}

	// ----------------------------------------------------------------
	// INJECT FAULT: Inconsistent MAC and IP addresses in the ARP entry
	for i, v := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp {
		oldIPAddress := v.Ae.IPAddress
		v.Ae.IPAddress = vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i+1].Ae.IPAddress
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i] = v

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidateArpTables()

		checkDataReport(1, 2, 0)

		// Restore data back to error free state
		vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPArp[i].Ae.PhysAddress = oldIPAddress
		break
	}
}

func testValidatePodInfo(t *testing.T) {
	vtv.nodeKey = "k8s-master"
	resetToInitialErrorFreeState()

	// -------------------------------------------------------
	// INJECT FAULT: Incorrect Host IP address in K8s pod data
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		oldHostIPAddress := pod.HostIPAddress
		vtv.k8sCache.UpdatePod(pod.Name, pod.Namespace, nil, pod.IPAddress, "1.2.3.4", nil)

		// Perform test
		vtv.report.Clear()
		vtv.l2Validator.ValidatePodInfo()

		checkDataReport(2, 0, 0)

		// Restore data back to error free state
		vtv.k8sCache.UpdatePod(pod.Name, pod.Namespace, nil, pod.IPAddress, oldHostIPAddress, nil)
		break
	}

	// -----------------------------------------------
	// INJECT FAULT: Pod missing from the host Pod map
	nodeKeyHostIP := vtv.vppCache.NodeMap[vtv.nodeKey].ManIPAddr
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == nodeKeyHostIP {
			delete(vtv.vppCache.NodeMap[vtv.nodeKey].PodMap, pod.Name)
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, 1, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// ------------------------------------------------------------------
	// INJECT FAULT: Pod in the host Pod map inconsistent with Pod in the
	// K8s database
	nodeKeyHostIP = vtv.vppCache.NodeMap[vtv.nodeKey].ManIPAddr
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == nodeKeyHostIP {
			vtv.vppCache.NodeMap[vtv.nodeKey].PodMap[pod.Name] = &telemetrymodel.Pod{}
			break
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, 1, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -----------------------------------------------------------
	// INJECT FAULT: Pod's host node not in the K8s node database
	podCnt := 0
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == nodeKeyHostIP {
			podCnt++
		}
	}
	vtv.k8sCache.DeleteK8sNode(vtv.vppCache.NodeMap[vtv.nodeKey].Name)

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, podCnt+2, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// ---------------------------------------------------------------------
	// INJECT FAULT: Pod's host IP address inconsistent with the node's host
	// IP address in the K8s database
	k8sNode, err := vtv.k8sCache.RetrieveK8sNode(vtv.vppCache.NodeMap[vtv.nodeKey].Name)
	gomega.Expect(err).To(gomega.BeNil())

	podCnt = 0
	for _, pod := range vtv.k8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == nodeKeyHostIP {
			podCnt++
		}
	}
	for k, adr := range k8sNode.Addresses {
		switch adr.Type {
		case nodemodel.NodeAddress_NodeHostName:
			k8sNode.Addresses[k].Address = "someHost"
		case nodemodel.NodeAddress_NodeInternalIP:
			k8sNode.Addresses[k].Address = "1.2.3.4"
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, podCnt*2, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// -------------------------------------------------
	// INJECT FAULT: Invalid data on pod's tap interface
	for k, ifc := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces {
		matched, err := regexp.Match("tap[1-9]", []byte(ifc.IfMeta.VppInternalName))
		gomega.Expect(err).To(gomega.BeNil())
		if matched {
			ifc.IfMeta.VppInternalName = "anotherIfcName"
			vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[k] = ifc

			// Perform test
			vtv.report.Clear()
			vtv.l2Validator.ValidatePodInfo()

			checkDataReport(1, 1, 0)

			// Restore data back to error free state
			resetToInitialErrorFreeState()
			break
		}
	}

	// ----------------------------------------------
	// INJECT FAULT: Missing pod-facing tap interface
	podIfIPAdr, podIfIPMask, err :=
		utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodVPPSubnetCIDR)
	gomega.Expect(err).To(gomega.BeNil())

ifcLoop:
	for ifIdx, ifc := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces {
		for _, ip := range ifc.If.IPAddresses {
			ipAddr, _, err := utils.Ipv4CidrToAddressAndMask(ip)
			gomega.Expect(err).To(gomega.BeNil())

			if (podIfIPAdr &^ podIfIPMask) == (ipAddr &^ podIfIPMask) {
				delete(vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces, ifIdx)
				break ifcLoop
			}
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, 1, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// --------------------------------------------------------
	// INJECT FAULT: Bad ip address on pod-facing tap interface
	podIfIPAdr, podIfIPMask, err =
		utils.Ipv4CidrToAddressAndMask(vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam.Config.PodVPPSubnetCIDR)
	gomega.Expect(err).To(gomega.BeNil())

ifcLoop1:
	for ifIdx, ifc := range vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces {
		for _, ip := range ifc.If.IPAddresses {
			ipAddr, _, err := utils.Ipv4CidrToAddressAndMask(ip)
			gomega.Expect(err).To(gomega.BeNil())

			if (podIfIPAdr &^ podIfIPMask) == (ipAddr &^ podIfIPMask) {
				ifc.If.IPAddresses = []string{"1.2.3.4"}
				vtv.vppCache.NodeMap[vtv.nodeKey].NodeInterfaces[ifIdx] = ifc
				break ifcLoop1
			}
		}
	}

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, 3, 0)

	// Restore data back to error free state
	resetToInitialErrorFreeState()

	// --------------------------------------------------------
	// INJECT FAULT: Bad ip address on pod-facing tap interface
	ipam := vtv.vppCache.NodeMap[vtv.nodeKey].NodeIPam
	oldPodVPPSubnetCIDR := ipam.Config.PodVPPSubnetCIDR
	addrParts := strings.Split(oldPodVPPSubnetCIDR, "/")
	ipam.Config.PodVPPSubnetCIDR = addrParts[0] + "/32"

	// Perform test
	vtv.report.Clear()
	vtv.l2Validator.ValidatePodInfo()

	checkDataReport(1, 2, 0)

	// Restore data back to error free state
	ipam.Config.PodVPPSubnetCIDR = oldPodVPPSubnetCIDR
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
