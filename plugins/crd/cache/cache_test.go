package cache

import (
	"testing"

	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/onsi/gomega"
)

//Checks adding a new node.
//Checks expected error for adding duplicate node.
func TestNodesDB_AddNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "20")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	err := db.CreateNode(2, "k8s_master", "20", "20")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

//Checks adding a node and then looking it up.
//Checks looking up a non-existent key.
func TestNodesDB_GetNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeTwo, ok := db.retrieveNode("NonExistentNode")
	gomega.Ω(ok).Should(gomega.BeFalse())
	gomega.Expect(nodeTwo).To(gomega.BeNil())
}

//Checks adding a node and then deleting it.
//Checks whether expected error is returned when deleting non-existent key.
func TestNodesDB_DeleteNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	err := db.DeleteNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	node, ok = db.retrieveNode("k8s_master")
	gomega.Expect(node).To(gomega.BeNil())
	gomega.Expect(ok).To(gomega.BeTrue())

	err = db.DeleteNode("k8s_master")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

//Creates 3 new nodes and adds them to a database.
//Then, the list is checked to see if it is in order.
func TestNodesDB_GetAllNodes(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.CreateNode(2, "k8s_master2", "10", "10")
	node, ok = db.retrieveNode("k8s_master2")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master2"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(2)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.CreateNode(3, "Ak8s_master3", "10", "10")
	node, ok = db.retrieveNode("Ak8s_master3")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("Ak8s_master3"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(3)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeList := db.RetrieveAllNodes()
	gomega.Expect(len(nodeList)).To(gomega.Equal(3))
	gomega.Expect(nodeList[0].Name).To(gomega.Equal("Ak8s_master3"))

}

func TestNodesDB_SetNodeInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	var ips []string
	nodeIFs := make(map[int]telemetrymodel.NodeInterface)
	nodeIF := telemetrymodel.NodeInterface{"Test", "Testing", 0, true, "", 0, telemetrymodel.Vxlan{}, ips, telemetrymodel.Tap{}}
	nodeIFs[0] = nodeIF

	err := db.SetNodeInterfaces("NENODE", nodeIFs)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeInterfaces("k8s_master", nodeIFs)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nodeIFs[0].VppInternalName).To(gomega.BeEquivalentTo("Test"))
}

func TestNodesDB_SetNodeBridgeDomain(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	var ifs []telemetrymodel.BDinterfaces
	nodeBD := telemetrymodel.NodeBridgeDomain{ifs, "", false}
	nodesBD := make(map[int]telemetrymodel.NodeBridgeDomain)
	nodesBD[0] = nodeBD

	err := db.SetNodeBridgeDomain("NENODE", nodesBD)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeBridgeDomain("k8s_master", nodesBD)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.NodeBridgeDomains[0]).To(gomega.BeEquivalentTo(telemetrymodel.NodeBridgeDomain{ifs, "", false}))

}

func TestNodesDB_SetNodeIPARPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeiparps := make([]telemetrymodel.NodeIPArpEntry, 0)
	nodeiparp := telemetrymodel.NodeIPArpEntry{1, "1.2.3.4", "12:34:56:78", false}
	nodeiparps = append(nodeiparps, nodeiparp)

	err := db.SetNodeIPARPs("NENODE", nodeiparps)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeIPARPs("k8s_master", nodeiparps)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nodeiparps[0]).To(gomega.BeEquivalentTo(telemetrymodel.NodeIPArpEntry{1, "1.2.3.4", "12:34:56:78", false}))
}

func TestNodesDB_SetNodeLiveness(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nlive := telemetrymodel.NodeLiveness{"54321", "12345", 0, 0, 0, 0, ""}
	err := db.SetNodeLiveness("NENODE", &nlive)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeLiveness("k8s_master", &nlive)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(node.NodeLiveness).To(gomega.BeEquivalentTo(&telemetrymodel.NodeLiveness{"54321", "12345", 0, 0, 0, 0, ""}))

}

func TestCache_SetNodeTelemetry(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	ntele := telemetrymodel.NodeTelemetry{"d", []telemetrymodel.Output{}}
	nTeleMap := make(map[string]telemetrymodel.NodeTelemetry)
	nTeleMap["k8s_master"] = ntele
	err := db.SetNodeTelemetry("k8s_master", nTeleMap)
	gomega.Expect(err).To(gomega.BeNil())
	err = db.SetNodeTelemetry("N.E.Node", nTeleMap)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

func TestNodesDB_SetNodeL2Fibs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppCache(logrus.DefaultLogger())
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nfib := telemetrymodel.NodeL2FibEntry{1, 2, "test", true, false}
	nfibs := make(map[string]telemetrymodel.NodeL2FibEntry)
	nfibs[node.Name] = nfib

	err := db.SetNodeL2Fibs("NENODE", nfibs)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeL2Fibs("k8s_master", nfibs)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(node.NodeL2Fibs[node.Name]).To(gomega.BeEquivalentTo(telemetrymodel.NodeL2FibEntry{1, 2, "test", true, false}))

}
func TestNodesDB_ValidateLoopIFAddresses(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewVppCache(logger)
	ctc := ContivTelemetryCache{Deps{}, true, &VppDataStore{}, &K8sDataStore{}, nil,
	map[string][]string{}}
	ctc.VppCache = db
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
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

	db.CreateNode(2, "k8s-worker1", "11", "11")

	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = db.retrieveNode("k8s_master")
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, ok = db.retrieveNode("k8s_master")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.retrieveNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	ctc.ValidateArpTables()

	db.CreateNode(1, "NoMacFoundNode", "12", "12")
	fmt.Println("Expecting errors for node not in ARP table...")
	ctc.ValidateArpTables()
	fmt.Println("Expected errors over for NoMacFoundNode...")
	fmt.Println("Removing NoMacFound from cache...")
	db.DeleteNode("NoMacFoundNode")
	fmt.Println("Done...")
	fmt.Println("Adding extra arp entry to node k8s_master...")
	nodeiparp3 := telemetrymodel.NodeIPArpEntry{3, "extraIP", "extraMAC", true}
	nodeiparps1 = append(nodeiparps1, nodeiparp3)
	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	fmt.Println("Done...")
	fmt.Println("Expecting mac not found and ip not found errors for extra ip arp entry...")
	ctc.ValidateArpTables()
	fmt.Println("Done expecting errors...")
	fmt.Println("Removing extra arp entry...")
	fmt.Println("Done...")
	fmt.Println("Adding extra node to cache...")
	fmt.Println("Expecting errors for extra node...")
	db.CreateNode(3, "BlahNode", "11", "11")
	node2, _ := db.retrieveNode("BlahNode")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node2
	ctc.ValidateArpTables()
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.DeleteNode("BlahNode")

	node, _ = db.retrieveNode("k8s_master")
	nodeinterfaces = make(map[int]telemetrymodel.NodeInterface)
	db.SetNodeInterfaces(node.Name, nodeinterfaces)
	fmt.Println("Expecting errors for missing interface for k8s_master...")
	ctc.ValidateArpTables()

}

func TestNodesDB_ValidateL2Connections(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewVppCache(logger)
	ctc := ContivTelemetryCache{Deps{}, true, &VppDataStore{}, &K8sDataStore{},
	nil, map[string][]string{}}
	ctc.VppCache = db
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
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

	db.CreateNode(2, "k8s-worker1", "11", "11")

	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = db.retrieveNode("k8s_master")
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, ok = db.retrieveNode("k8s_master")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.retrieveNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node
	node, _ = db.retrieveNode("k8s_master")
	bdif1_1 := telemetrymodel.BDinterfaces{3}
	bdif1_2 := telemetrymodel.BDinterfaces{5}
	nodebd1 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif1_1, bdif1_2},
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
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	db.SetNodeBridgeDomain("k8s_master", nodebdmap1)

	node, _ = db.retrieveNode("k8s-worker1")
	bdif2_1 := telemetrymodel.BDinterfaces{3}
	bdif2_2 := telemetrymodel.BDinterfaces{4}
	nodebd2 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif2_1, bdif2_2},
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
	db.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	db.gigEIPMap[node.IPAdr+subnetmask] = node
	node, _ = db.retrieveNode("k8s_master")
	db.gigEIPMap[node.IPAdr+subnetmask] = node
	ctc.ValidateL2Connectivity()

	fmt.Println("Setting vxlan_vni to 11, expecting error...")
	nodevxlaninterface2.Vxlan.Vni = 11
	nodeinterfaces2[4] = nodevxlaninterface2
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	ctc.ValidateL2Connectivity()
	nodelist := db.RetrieveAllNodes()
	db.printnodelogs(nodelist)
	fmt.Println("Setting vxlan_vni back to normal...")
	nodevxlaninterface2.Vxlan.Vni = 10
	nodeinterfaces2[4] = nodevxlaninterface2
	ctc.VppCache.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	ctc.ValidateL2Connectivity()
	node, _ = db.retrieveNode("k8s-worker1")

	nodeinterface2.IfType = interfaces.InterfaceType_TAP_INTERFACE
	nodeinterfaces2[3] = nodeinterface2
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	fmt.Println("Expecting errors as bd has no loop interface.")
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)
	fmt.Println("Done expecting errors")
	nodeinterface2.IfType = interfaces.InterfaceType_SOFTWARE_LOOPBACK
	nodeinterfaces2[3] = nodeinterface2
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)

	fmt.Println("Deleting node with ip 10 from gigE map" +
		". Expecting errors for missing ip")
	delete(db.gigEIPMap, node.NodeInterfaces[4].Vxlan.DstAddress+subnetmask)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)
	fmt.Println("Done expecting errors")
	node, _ = db.retrieveNode("k8s_master")
	db.gigEIPMap["10"+subnetmask] = node
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)

	fmt.Println("Unmatching vxlan tunnel. Expecting error...")

	nodevxlaninterface1.Vxlan.DstAddress = "20"
	nodeinterfaces[5] = nodevxlaninterface1
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)
	fmt.Println("Done expecting errors...")
	nodevxlaninterface1.Vxlan.DstAddress = "11"
	nodeinterfaces[5] = nodevxlaninterface1
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)

	fmt.Println("Expecting error for mismatched index of bridge domain")
	bdif2_2.SwIfIndex = 5
	nodebd2 = telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif2_1, bdif2_2},
		"vxlanBD",
		true,
	}
	nodebdmap2 = make(map[int]telemetrymodel.NodeBridgeDomain)
	nodebdmap2[1] = nodebd2
	db.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)
	fmt.Println("Done expecting errors...")
	bdif2_2.SwIfIndex = 4
	nodebd2 = telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif2_1, bdif2_2},
		"vxlanBD",
		true,
	}
	nodebdmap2 = make(map[int]telemetrymodel.NodeBridgeDomain)
	nodebdmap2[1] = nodebd2
	db.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)

	fmt.Println("Adding extra node in place of existing one...")
	db.CreateNode(1, "extraNode", "54321", "54321")
	node, _ = db.retrieveNode("extraNode")
	db.gigEIPMap["10/24"] = node
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)
	fmt.Println("Done expecting errors...")
	node, _ = db.retrieveNode("k8s_master")
	db.gigEIPMap["10/24"] = node
	db.DeleteNode("extraNode")
	ctc.ValidateL2Connectivity()
	db.printnodelogs(nodelist)

}
func TestCache_ValidateFibEntries(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewVppCache(logger)
	ctc := ContivTelemetryCache{Deps{}, true, &VppDataStore{}, &K8sDataStore{},
	nil, map[string][]string{}}
	ctc.VppCache = db
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.retrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
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

	db.CreateNode(2, "k8s-worker1", "11", "11")

	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = db.retrieveNode("k8s_master")
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, ok = db.retrieveNode("k8s_master")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.retrieveNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node
	node, _ = db.retrieveNode("k8s_master")
	bdif1_1 := telemetrymodel.BDinterfaces{3}
	bdif1_2 := telemetrymodel.BDinterfaces{5}
	nodebd1 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif1_1, bdif1_2},
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
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	db.SetNodeBridgeDomain("k8s_master", nodebdmap1)

	node, _ = db.retrieveNode("k8s-worker1")
	bdif2_1 := telemetrymodel.BDinterfaces{3}
	bdif2_2 := telemetrymodel.BDinterfaces{4}
	nodebd2 := telemetrymodel.NodeBridgeDomain{
		[]telemetrymodel.BDinterfaces{bdif2_1, bdif2_2},
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
	db.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	db.gigEIPMap[node.IPAdr+subnetmask] = node
	node, _ = db.retrieveNode("k8s_master")
	db.gigEIPMap[node.IPAdr+subnetmask] = node

	nodelist := db.RetrieveAllNodes()
	ctc.ValidateL2FibEntries()
	db.printnodelogs(nodelist)

}

func (vds *VppDataStore) printnodelogs(nodelist []*telemetrymodel.Node) {

	for _, node := range nodelist {
		for _, str := range node.Report {
			fmt.Println(str)
		}
		node.Report = node.Report[0:0]
	}

}
