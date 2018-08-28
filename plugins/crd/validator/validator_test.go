package validator

import (
	"encoding/json"
	"fmt"
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
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

type validatorTestVars struct {
	log       *logrus.Logger
	processor *Validator
	logWriter *mockLogWriter

	// Mock data
	k8sNodeData []*nodemodel.Node
	k8sPodData  []*podmodel.Pod

	vppCache *datastore.VppDataStore
	k8sCache *datastore.K8sDataStore
	report   *datastore.SimpleReport
}

type nodeData struct {
	ID       uint32
	nodeName string
	IPAdr    string
	ManIPAdr string

	liveness   *telemetrymodel.NodeLiveness
	interfaces telemetrymodel.NodeInterfaces
	bds        telemetrymodel.NodeBridgeDomains
	l2FibTable telemetrymodel.NodeL2FibTable
	arpTable   telemetrymodel.NodeIPArpTable
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

var vtv validatorTestVars

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
	vtv.processor = &Validator{
		Deps: Deps{
			Log: vtv.log,
		},
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
	// t.Run("testNodesDBValidateLoopIFAddresses", testNodesDBValidateLoopIFAddresses)
	// t.Run("testCacheValidateFibEntries", testCacheValidateFibEntries)

}

func testErrorFreeTopologyValidation(t *testing.T) {
	resetToInitialErrorFreeState()

	vtv.processor.Validate()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(4))
}

func testK8sNodeToNodeInfoOkValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	vtv.processor.ValidateK8sNodeInfo()
	gomega.Expect(len(vtv.report.Data)).To(gomega.Equal(0))
}

func testK8sNodeToNodeInfoMissingNiValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	// INJECT FAULT:: missing vpp node
	vtv.processor.VppCache.DeleteNode("k8s-master")

	vtv.processor.ValidateK8sNodeInfo()
	gomega.Expect(len(vtv.report.Data["k8s-master"])).To(gomega.Equal(1))
}

func testK8sNodeToNodeInfoMissingK8snValidation(t *testing.T) {
	resetToInitialErrorFreeState()
	// INJECT FAULT:: missing K8s node
	vtv.processor.K8sCache.DeleteK8sNode("k8s-master")

	vtv.processor.ValidateK8sNodeInfo()
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
	vtv.processor.ValidateL2Connectivity()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(2))

	delete(bd, 2)

	// --------------------------------------------------------------------
	// INJECT FAULT: No Bridge Domain present on node;
	// NOTE: This TC MUST be executed after the previous one, it depends on
	// the same setup
	delete(bd, 1)

	vtv.report.Clear()
	vtv.processor.ValidateL2Connectivity()
	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(2))

	resetToInitialErrorFreeState()

	// INJECT FAULT: Set node/k8s-master interface/5 vxlan_vni to 11
	k, ifp := vtv.findFirstVxlanInterface(nodeKey)
	gomega.Expect(ifp).To(gomega.Not(gomega.BeNil()))
	ifp.If.Vxlan.Vni = 11
	vtv.vppCache.NodeMap[nodeKey].NodeInterfaces[k] = *ifp

	vtv.report.Clear()
	vtv.processor.ValidateL2Connectivity()
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
	vtv.processor.ValidateL2Connectivity()

	gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
	gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))
	node, err := vtv.vppCache.RetrieveNodeByGigEIPAddr(dstIPAddr + "/24") // TODO: handle CIDR mask peoperly
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
		vtv.processor.ValidateL2Connectivity()

		gomega.Expect(len(vtv.report.Data[api.GlobalMsg])).To(gomega.Equal(1))
		gomega.Expect(len(vtv.report.Data[nodeKey])).To(gomega.Equal(4))

		// Restore data back to error free state
		vxlanBd.BdMeta.BdID2Name[keys[0]] = vxlanBd.BdMeta.BdID2Name[bogusKey]
		delete(vxlanBd.BdMeta.BdID2Name, bogusKey)

		break
	}

	// ----------------------------------------------------------------------
	// INJECT FAULT: Duplicate BVI interface

	/*
		nodevxlaninterface2.Vxlan.Vni = 11
		nodeinterfaces2[4] = nodevxlaninterface2
		vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Setting vxlan_vni back to normal...")
		nodevxlaninterface2.Vxlan.Vni = 10
		nodeinterfaces2[4] = nodevxlaninterface2
		vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
		vtv.processor.ValidateL2Connectivity()
		node, _ = vtv.vppCache.RetrieveNode("k8s-worker1")

		nodeinterface2.IfType = interfaces.InterfaceType_TAP_INTERFACE
		nodeinterfaces2[3] = nodeinterface2
		vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
		fmt.Println("Expecting errors as bd has no loop interface.")
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Done expecting errors")
		nodeinterface2.IfType = interfaces.InterfaceType_SOFTWARE_LOOPBACK
		nodeinterfaces2[3] = nodeinterface2
		vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
		vtv.processor.ValidateL2Connectivity()

		fmt.Println("Deleting node with ip 10 from gigE map" +
			". Expecting errors for missing ip")
		delete(vtv.vppCache.GigEIPMap, node.NodeInterfaces[4].Vxlan.DstAddress+api.SubnetMask)
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Done expecting errors")
		node, _ = vtv.vppCache.RetrieveNode("k8s_master")
		vtv.vppCache.GigEIPMap["10"+api.SubnetMask] = node
		vtv.processor.ValidateL2Connectivity()

		fmt.Println("Unmatching vxlan tunnel. Expecting error...")

		nodevxlaninterface1.Vxlan.DstAddress = "20"
		nodeinterfaces[5] = nodevxlaninterface1
		vtv.vppCache.SetNodeInterfaces("k8s_master", nodeinterfaces)
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Done expecting errors...")
		nodevxlaninterface1.Vxlan.DstAddress = "11"
		nodeinterfaces[5] = nodevxlaninterface1
		vtv.vppCache.SetNodeInterfaces("k8s_master", nodeinterfaces)
		vtv.processor.ValidateL2Connectivity()

		fmt.Println("Expecting error for mismatched index of bridge domain")
		bdif2_2.SwIfIndex = 5
		nodebd2 = telemetrymodel.NodeBridgeDomain{
			[]telemetrymodel.BdInterface{bdif2_1, bdif2_2},
			"vxlanBD",
			true,
		}
		nodebdmap2 = make(map[int]telemetrymodel.NodeBridgeDomain)
		nodebdmap2[1] = nodebd2
		vtv.vppCache.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Done expecting errors...")
		bdif2_2.SwIfIndex = 4
		nodebd2 = telemetrymodel.NodeBridgeDomain{
			[]telemetrymodel.BdInterface{bdif2_1, bdif2_2},
			"vxlanBD",
			true,
		}
		nodebdmap2 = make(map[int]telemetrymodel.NodeBridgeDomain)
		nodebdmap2[1] = nodebd2
		vtv.vppCache.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
		vtv.processor.ValidateL2Connectivity()

		fmt.Println("Adding extra node in place of existing one...")
		vtv.vppCache.CreateNode(1, "extraNode", "54321", "54321")
		node, _ = vtv.vppCache.RetrieveNode("extraNode")
		vtv.vppCache.GigEIPMap["10/24"] = node
		vtv.processor.ValidateL2Connectivity()
		fmt.Println("Done expecting errors...")
		node, _ = vtv.vppCache.RetrieveNode("k8s_master")
		vtv.vppCache.GigEIPMap["10/24"] = node
		vtv.vppCache.DeleteNode("extraNode")
		vtv.processor.ValidateL2Connectivity()
	*/
}

func (v *validatorTestVars) findFirstVxlanInterface(nodeKey string) (int, *telemetrymodel.NodeInterface) {
	for k, ifc := range v.vppCache.NodeMap[nodeKey].NodeInterfaces {
		if ifc.If.IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
			return k, &ifc
		}
	}
	return -1, nil
}

/*
func testNodesDBValidateLoopIFAddresses(t *testing.T) {
	resetToInitialErrorFreeState()

	vtv.vppCache.CreateNode(1, "k8s_master", "10", "10")

	node, err := vtv.vppCache.RetrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))
	nodeinterface1 := telemetrymodel.NodeInterface{
		"loop0",
		"loop0",
		3,
		true,
		"11",
		1,
		telemetrymodel.Vxlan{"", "", 1},
		[]string{"11"},
		telemetrymodel.Tap{}}
	nodeinterfaces := map[int]telemetrymodel.NodeInterface{}
	nodeinterfaces[3] = nodeinterface1

	nodeiparp1 := telemetrymodel.NodeIPArpEntry{3, "10", "10", true}
	nodeiparps1 := make([]telemetrymodel.NodeIPArpEntry, 0)
	nodeiparps1 = append(nodeiparps1, nodeiparp1)

	nodeinterface2 := telemetrymodel.NodeInterface{
		"loop0",
		"loop0",
		3,
		true,
		"10",
		1,
		telemetrymodel.Vxlan{"", "", 1},
		[]string{"10"},
		telemetrymodel.Tap{}}
	nodeinterfaces2 := map[int]telemetrymodel.NodeInterface{}
	nodeinterfaces2[3] = nodeinterface2

	nodeiparp2 := telemetrymodel.NodeIPArpEntry{3, "11", "11", true}
	nodeiparps2 := make([]telemetrymodel.NodeIPArpEntry, 0)
	nodeiparps2 = append(nodeiparps2, nodeiparp2)

	vtv.vppCache.CreateNode(2, "k8s-worker1", "11", "11")

	vtv.vppCache.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = vtv.vppCache.RetrieveNode("k8s_master")
	vtv.vppCache.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, err = vtv.vppCache.RetrieveNode("k8s_master")
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	vtv.vppCache.LoopIPMap[node.NodeInterfaces[3].IPAddresses[0]+api.SubnetMask] = node

	vtv.vppCache.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, err = vtv.vppCache.RetrieveNode("k8s-worker1")
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	vtv.vppCache.LoopIPMap[node.NodeInterfaces[3].IPAddresses[0]+api.SubnetMask] = node

	vtv.processor.ValidateArpTables()

	vtv.vppCache.CreateNode(1, "NoMacFoundNode", "12", "12")
	fmt.Println("Expecting errors for node not in ARP table...")
	vtv.processor.ValidateArpTables()
	fmt.Println("Expected errors over for NoMacFoundNode...")
	fmt.Println("Removing NoMacFound from cache...")
	vtv.vppCache.DeleteNode("NoMacFoundNode")
	fmt.Println("Done...")
	fmt.Println("Adding extra arp entry to node k8s_master...")
	nodeiparp3 := telemetrymodel.NodeIPArpEntry{3, "extraIP", "extraMAC", true}
	nodeiparps1 = append(nodeiparps1, nodeiparp3)
	vtv.vppCache.SetNodeIPARPs("k8s_master", nodeiparps1)
	fmt.Println("Done...")
	fmt.Println("Expecting mac not found and ip not found errors for extra ip arp entry...")
	vtv.processor.ValidateArpTables()
	fmt.Println("Done expecting errors...")
	fmt.Println("Removing extra arp entry...")
	fmt.Println("Done...")
	fmt.Println("Adding extra node to cache...")
	fmt.Println("Expecting errors for extra node...")
	vtv.vppCache.CreateNode(3, "BlahNode", "11", "11")
	node2, _ := vtv.vppCache.RetrieveNode("BlahNode")
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node2
	vtv.processor.ValidateArpTables()
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	vtv.vppCache.DeleteNode("BlahNode")

	node, _ = vtv.vppCache.RetrieveNode("k8s_master")
	nodeinterfaces = make(map[int]telemetrymodel.NodeInterface)
	vtv.vppCache.SetNodeInterfaces(node.Name, nodeinterfaces)
	fmt.Println("Expecting errors for missing interface for k8s_master...")
	vtv.processor.ValidateArpTables()
}

func testCacheValidateFibEntries(t *testing.T) {
	resetToInitialErrorFreeState()
	vtv.report.Clear()

	vtv.vppCache.CreateNode(1, "k8s_master", "10", "10")
	node, err := vtv.vppCache.RetrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))
	nodeinterface1 := telemetrymodel.NodeInterface{
		"loop0",
		"loop0",
		interfaces.InterfaceType_SOFTWARE_LOOPBACK,
		true,
		"11",
		1,
		telemetrymodel.Vxlan{"", "", 1},
		[]string{"11"},
		telemetrymodel.Tap{}}
	nodeinterfaces := map[int]telemetrymodel.NodeInterface{}
	nodeinterfaces[3] = nodeinterface1

	nodeiparp1 := telemetrymodel.NodeIPArpEntry{3, "10", "10", true}
	nodeiparps1 := make([]telemetrymodel.NodeIPArpEntry, 0)
	nodeiparps1 = append(nodeiparps1, nodeiparp1)

	nodeinterface2 := telemetrymodel.NodeInterface{
		"loop0",
		"loop0",
		interfaces.InterfaceType_SOFTWARE_LOOPBACK,
		true,
		"10",
		1,
		telemetrymodel.Vxlan{"", "", 1},
		[]string{"10"},
		telemetrymodel.Tap{}}
	nodeinterfaces2 := map[int]telemetrymodel.NodeInterface{}
	nodeinterfaces2[3] = nodeinterface2

	nodeiparp2 := telemetrymodel.NodeIPArpEntry{3, "11", "11", true}
	nodeiparps2 := make([]telemetrymodel.NodeIPArpEntry, 0)
	nodeiparps2 = append(nodeiparps2, nodeiparp2)

	vtv.vppCache.CreateNode(2, "k8s-worker1", "11", "11")

	vtv.vppCache.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = vtv.vppCache.RetrieveNode("k8s_master")
	vtv.vppCache.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, err = vtv.vppCache.RetrieveNode("k8s_master")
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	vtv.vppCache.LoopIPMap[node.NodeInterfaces[3].IPAddresses[0]+api.SubnetMask] = node

	vtv.vppCache.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, err = vtv.vppCache.RetrieveNode("k8s-worker1")
	vtv.vppCache.LoopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	vtv.vppCache.LoopIPMap[node.NodeInterfaces[3].IPAddresses[0]+api.SubnetMask] = node
	node, _ = vtv.vppCache.RetrieveNode("k8s_master")
	bdif1_1 := telemetrymodel.BdInterface{3}
	bdif1_2 := telemetrymodel.BdInterface{5}
	nodebd1 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BdInterface{bdif1_1, bdif1_2},
		"vxlanBD",
		true,
	}
	nodebdmap1 := make(map[int]telemetrymodel.NodeBridgeDomain)
	nodebdmap1[1] = nodebd1
	nodevxlaninterface1 := telemetrymodel.NodeInterface{
		"vxlan_tunnel0",
		"vxlan2",
		interfaces.InterfaceType_VXLAN_TUNNEL,
		true,
		"",
		0,
		telemetrymodel.Vxlan{node.IPAdr, "11",
			10}, []string{}, telemetrymodel.Tap{},
	}
	nodeinterfaces[5] = nodevxlaninterface1
	vtv.vppCache.SetNodeInterfaces("k8s_master", nodeinterfaces)
	vtv.vppCache.SetNodeBridgeDomain("k8s_master", nodebdmap1)

	node, _ = vtv.vppCache.RetrieveNode("k8s-worker1")
	bdif2_1 := telemetrymodel.BdInterface{3}
	bdif2_2 := telemetrymodel.BdInterface{4}
	nodebd2 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BdInterface{bdif2_1, bdif2_2},
		"vxlanBD",
		true,
	}
	nodebdmap2 := make(map[int]telemetrymodel.NodeBridgeDomain)
	nodebdmap2[1] = nodebd2
	nodevxlaninterface2 := telemetrymodel.NodeInterface{
		"vxlan_tunnel0",
		"vxlan2",
		interfaces.InterfaceType_VXLAN_TUNNEL,
		true,
		"",
		0,
		telemetrymodel.Vxlan{node.IPAdr, "10",
			10}, []string{}, telemetrymodel.Tap{},
	}
	nodeinterfaces2[4] = nodevxlaninterface2
	vtv.vppCache.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	vtv.vppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	vtv.vppCache.GigEIPMap[node.IPAdr+api.SubnetMask] = node
	node, _ = vtv.vppCache.RetrieveNode("k8s_master")
	vtv.vppCache.GigEIPMap[node.IPAdr+api.SubnetMask] = node

	vtv.processor.ValidateL2FibEntries()
}
*/

func resetToInitialErrorFreeState() {
	vtv.vppCache.ReinitializeCache()
	vtv.k8sCache.ReinitializeCache()
	vtv.report.Clear()
	vtv.logWriter.clearLog()

	if err := vtv.createNodeTestData(); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	if err := vtv.createK8sPodTestData(); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	if err := vtv.createK8sNodeTestData(); err != nil {
		vtv.log.SetOutput(os.Stdout)
		vtv.log.Error(err)
		gomega.Panic()
	}

	for _, node := range vtv.vppCache.RetrieveAllNodes() {
		errReport := vtv.processor.VppCache.SetSecondaryNodeIndices(node)
		for _, r := range errReport {
			vtv.processor.Report.AppendToNodeReport(node.Name, r)
		}

		// Code replicated from ContivTelemetryCache.populateNodeMaps() -
		// need to inject pod data into each node.
		for _, pod := range vtv.k8sCache.RetrieveAllPods() {
			if pod.HostIPAddress == node.ManIPAdr {
				node.PodMap[pod.Name] = pod
			}
		}
	}
}

// createNodeTestData creates a test vector that roughly corresponds to a 3-node
// vagrant topology (1 master, 2 workers). The created topology is defect-free,
// i.e. defect must be injected into the topology individually for each test
// case.
func (v *validatorTestVars) createNodeTestData() error {
	rawData := getRawNodeTestData()

	for node, data := range rawData {
		ni := &nodeinfomodel.NodeInfo{}
		if err := json.Unmarshal([]byte(data["nodeinfo"]), ni); err != nil {
			return fmt.Errorf("failed to unmarshall node info")
		}

		nl := &telemetrymodel.NodeLiveness{}
		if err := json.Unmarshal([]byte(data["liveness"]), nl); err != nil {
			return fmt.Errorf("failed to unmarshall node liveness, err %s", err)
		}

		nifc := make(telemetrymodel.NodeInterfaces, 0)
		if err := json.Unmarshal([]byte(data["interfaces"]), &nifc); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nbd := make(telemetrymodel.NodeBridgeDomains, 0)
		if err := json.Unmarshal([]byte(data["bridgedomains"]), &nbd); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nodel2fib := make(telemetrymodel.NodeL2FibTable, 0)
		if err := json.Unmarshal([]byte(data["l2fib"]), &nodel2fib); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		narp := make(telemetrymodel.NodeIPArpTable, 0)
		if err := json.Unmarshal([]byte(data["arps"]), &narp); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nr := make(telemetrymodel.NodeStaticRoutes, 0)
		if err := json.Unmarshal([]byte(data["routes"]), &nr); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		if node != ni.Name {
			return fmt.Errorf("invalid data - TODO more precise error")
		}

		if err := vtv.vppCache.CreateNode(ni.Id, ni.Name, ni.IpAddress, ni.ManagementIpAddress); err != nil {
			return fmt.Errorf("failed to create test data for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeLiveness(ni.Name, nl); err != nil {
			return fmt.Errorf("failed to set liveness for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeInterfaces(ni.Name, nifc); err != nil {
			return fmt.Errorf("failed to set interfaces for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeBridgeDomain(ni.Name, nbd); err != nil {
			return fmt.Errorf("failed to set bridge domains for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeL2Fibs(ni.Name, nodel2fib); err != nil {
			return fmt.Errorf("failed to set l2fib table for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeIPARPs(ni.Name, narp); err != nil {
			return fmt.Errorf("failed to set arp table for node %s, err: %s", ni.Name, err)
		}

		if err := vtv.vppCache.SetNodeStaticRoutes(ni.Name, nr); err != nil {
			return fmt.Errorf("failed to set route table for node %s, err: %s", ni.Name, err)
		}
	}
	return nil
}

func (v *validatorTestVars) createK8sPodTestData() error {
	for _, rp := range getRawPodTestData() {
		pod := &podmodel.Pod{
			Label:     []*podmodel.Pod_Label{},
			Container: []*podmodel.Pod_Container{},
		}

		if err := json.Unmarshal([]byte(rp), pod); err != nil {
			return fmt.Errorf("failed to unmarshall pod data, err %s", err)
		}

		if err := v.k8sCache.CreatePod(pod.Name, pod.Namespace, pod.Label,
			pod.IpAddress, pod.HostIpAddress, nil); err != nil {
			return fmt.Errorf("failed to create test data for pod %s, err: %s", pod.Name, err)
		}
	}
	return nil
}

func (v *validatorTestVars) createK8sNodeTestData() error {
	for _, rp := range getRawK8sNodeTestData() {
		node := &nodemodel.Node{
			Addresses: []*nodemodel.NodeAddress{},
			NodeInfo:  &nodemodel.NodeSystemInfo{},
		}

		if err := json.Unmarshal([]byte(rp), node); err != nil {
			return fmt.Errorf("failed to unmarshall pod data, err %s", err)
		}

		if err := v.k8sCache.CreateK8sNode(node.Name, node.Pod_CIDR, node.Provider_ID,
			node.Addresses, node.NodeInfo); err != nil {
			return fmt.Errorf("failed to create test data for pod %s, err: %s", node.Name, err)
		}
	}
	return nil
}
