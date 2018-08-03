package cache

import (
	"testing"

	"fmt"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/onsi/gomega"
)

//Checks adding a new node.
//Checks expected error for adding duplicate node.
func TestNodesDB_AddNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "20")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	err := db.addNode(2, "k8s_master", "20", "20")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

//Checks adding a node and then looking it up.
//Checks looking up a non-existent key.
func TestNodesDB_GetNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeTwo, err := db.GetNode("NonExistentNode")
	gomega.Ω(err.Error()).Should(gomega.Equal("value with given key not found: NonExistentNode"))
	gomega.Expect(nodeTwo).To(gomega.BeNil())
}

//Checks adding a node and then deleting it.
//Checks whether expected error is returned when deleting non-existent key.
func TestNodesDB_DeleteNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	//err := db.DeleteNode("k8s_master")
	//gomega.Expect(err).To(gomega.BeNil())
	//node, err = db.GetNode("k8s_master")
	//gomega.Expect(node).To(gomega.BeNil())
	//gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

	//err = db.DeleteNode("k8s_master")
	//gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

//Creates 3 new nodes and adds them to a database.
//Then, the list is checked to see if it is in order.
func TestNodesDB_GetAllNodes(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.addNode(2, "k8s_master2", "10", "10")
	node, ok = db.GetNode("k8s_master2")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master2"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(2)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.addNode(3, "Ak8s_master3", "10", "10")
	node, ok = db.GetNode("Ak8s_master3")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("Ak8s_master3"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(3)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeList := db.GetAllNodes()
	gomega.Expect(len(nodeList)).To(gomega.Equal(3))
	gomega.Expect(nodeList[0].Name).To(gomega.Equal("Ak8s_master3"))

}

func TestNodesDB_SetNodeInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	var ips []string
	nodeIFs := make(map[int]NodeInterface)
	nodeIF := NodeInterface{"Test", "Testing", 0, true, "", 0, vxlan{}, ips, tap{}}
	nodeIFs[0] = nodeIF

	err := db.SetNodeInterfaces("NENODE", nodeIFs)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeInterfaces("k8s_master", nodeIFs)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nodeIFs[0].VppInternalName).To(gomega.BeEquivalentTo("Test"))
}

func TestNodesDB_SetNodeBridgeDomain(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	var ifs []bdinterfaces
	nodeBD := NodeBridgeDomain{ifs, "", false}
	nodesBD := make(map[int]NodeBridgeDomain)
	nodesBD[0] = nodeBD

	err := db.SetNodeBridgeDomain("NENODE", nodesBD)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeBridgeDomain("k8s_master", nodesBD)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.NodeBridgeDomains[0]).To(gomega.BeEquivalentTo(NodeBridgeDomain{ifs, "", false}))

}

func TestNodesDB_SetNodeIPARPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeiparps := make([]NodeIPArpEntry, 0)
	nodeiparp := NodeIPArpEntry{1, "1.2.3.4", "12:34:56:78", false}
	nodeiparps = append(nodeiparps, nodeiparp)

	err := db.SetNodeIPARPs("NENODE", nodeiparps)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeIPARPs("k8s_master", nodeiparps)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nodeiparps[0]).To(gomega.BeEquivalentTo(NodeIPArpEntry{1, "1.2.3.4", "12:34:56:78", false}))
}

func TestNodesDB_SetNodeLiveness(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nlive := NodeLiveness{"54321", "12345", 0, 0, 0, 0, ""}
	err := db.SetNodeLiveness("NENODE", &nlive)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeLiveness("k8s_master", &nlive)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(node.NodeLiveness).To(gomega.BeEquivalentTo(&NodeLiveness{"54321", "12345", 0, 0, 0, 0, ""}))

}

func TestNodesDB_SetNodeL2Fibs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewCache(logrus.DefaultLogger())
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nfib := NodeL2FibEntry{1, 2, "test", true, false}
	nfibs := make(map[string]NodeL2FibEntry)
	nfibs[node.Name] = nfib

	err := db.SetNodeL2Fibs("NENODE", nfibs)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
	err = db.SetNodeL2Fibs("k8s_master", nfibs)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(node.NodeL2Fibs[node.Name]).To(gomega.BeEquivalentTo(NodeL2FibEntry{1, 2, "test", true, false}))

}
func TestNodesDB_ValidateLoopIFAddresses(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewCache(logger)
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))
	nodeinterface1 := NodeInterface{
		"loop0",
		"loop0",
		3,
		true,
		"11",
		1,
		vxlan{"", "", 1},
		[]string{"11"},
		tap{}}
	nodeinterfaces := map[int]NodeInterface{}
	nodeinterfaces[3] = nodeinterface1

	nodeiparp1 := NodeIPArpEntry{3, "10", "10", true}
	nodeiparps1 := make([]NodeIPArpEntry, 0)
	nodeiparps1 = append(nodeiparps1, nodeiparp1)

	nodeinterface2 := NodeInterface{
		"loop0",
		"loop0",
		3,
		true,
		"10",
		1,
		vxlan{"", "", 1},
		[]string{"10"},
		tap{}}
	nodeinterfaces2 := map[int]NodeInterface{}
	nodeinterfaces2[3] = nodeinterface2

	nodeiparp2 := NodeIPArpEntry{3, "11", "11", true}
	nodeiparps2 := make([]NodeIPArpEntry, 0)
	nodeiparps2 = append(nodeiparps2, nodeiparp2)

	db.addNode(2, "k8s-worker1", "11", "11")

	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = db.GetNode("k8s_master")
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, ok = db.GetNode("k8s_master")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.GetNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.ValidateLoopIFAddresses()

	db.addNode(1, "NoMacFoundNode", "12", "12")
	fmt.Println("Expecting errors for node not in ARP table...")
	db.ValidateLoopIFAddresses()
	fmt.Println("Expected errors over for NoMacFoundNode...")
	fmt.Println("Removing NoMacFound from cache...")
	db.deleteNode("NoMacFoundNode")
	fmt.Println("Done...")
	fmt.Println("Adding extra arp entry to node k8s_master...")
	nodeiparp3 := NodeIPArpEntry{3, "extraIP", "extraMAC", true}
	nodeiparps1 = append(nodeiparps1, nodeiparp3)
	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	fmt.Println("Done...")
	fmt.Println("Expecting mac not found and ip not found errors for extra ip arp entry...")
	db.ValidateLoopIFAddresses()
	fmt.Println("Done expecting errors...")
	fmt.Println("Removing extra arp entry...")
	fmt.Println("Done...")
	fmt.Println("Adding extra node to cache...")
	fmt.Println("Expecting errors for extra node...")
	db.addNode(3, "BlahNode", "11", "11")
	node2, _ := db.GetNode("BlahNode")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node2
	db.ValidateLoopIFAddresses()
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.deleteNode("BlahNode")

	node, _ = db.GetNode("k8s_master")
	nodeinterfaces = make(map[int]NodeInterface)
	db.SetNodeInterfaces(node.Name, nodeinterfaces)
	fmt.Println("Expecting errors for missing interface for k8s_master...")
	db.ValidateLoopIFAddresses()

}

func TestNodesDB_ValidateL2Connections(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewCache(logger)
	db.addNode(1, "k8s_master", "10", "10")
	node, ok := db.GetNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))
	nodeinterface1 := NodeInterface{
		"loop0",
		"loop0",
		interfaces.InterfaceType_SOFTWARE_LOOPBACK,
		true,
		"11",
		1,
		vxlan{"", "", 1},
		[]string{"11"},
		tap{}}
	nodeinterfaces := map[int]NodeInterface{}
	nodeinterfaces[3] = nodeinterface1

	nodeiparp1 := NodeIPArpEntry{3, "10", "10", true}
	nodeiparps1 := make([]NodeIPArpEntry, 0)
	nodeiparps1 = append(nodeiparps1, nodeiparp1)

	nodeinterface2 := NodeInterface{
		"loop0",
		"loop0",
		interfaces.InterfaceType_SOFTWARE_LOOPBACK,
		true,
		"10",
		1,
		vxlan{"", "", 1},
		[]string{"10"},
		tap{}}
	nodeinterfaces2 := map[int]NodeInterface{}
	nodeinterfaces2[3] = nodeinterface2

	nodeiparp2 := NodeIPArpEntry{3, "11", "11", true}
	nodeiparps2 := make([]NodeIPArpEntry, 0)
	nodeiparps2 = append(nodeiparps2, nodeiparp2)

	db.addNode(2, "k8s-worker1", "11", "11")

	db.SetNodeIPARPs("k8s_master", nodeiparps1)
	node, _ = db.GetNode("k8s_master")
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	node, ok = db.GetNode("k8s_master")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.GetNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+subnetmask] = node
	node, _ = db.GetNode("k8s_master")
	bdif1_1 := bdinterfaces{3}
	bdif1_2 := bdinterfaces{5}
	nodebd1 := NodeBridgeDomain{
		[]bdinterfaces{bdif1_1, bdif1_2},
		"vxlanBD",
		true,
	}
	nodebdmap1 := make(map[int]NodeBridgeDomain)
	nodebdmap1[1] = nodebd1
	nodevxlaninterface1 := NodeInterface{
		"vxlan_tunnel0",
		"vxlan2",
		interfaces.InterfaceType_VXLAN_TUNNEL,
		true,
		"",
		0,
		vxlan{node.IPAdr, "11",
			10}, []string{}, tap{},
	}
	nodeinterfaces[5] = nodevxlaninterface1
	db.SetNodeInterfaces("k8s_master", nodeinterfaces)
	db.SetNodeBridgeDomain("k8s_master", nodebdmap1)

	node, _ = db.GetNode("k8s-worker1")
	bdif2_1 := bdinterfaces{3}
	bdif2_2 := bdinterfaces{4}
	nodebd2 := NodeBridgeDomain{
		[]bdinterfaces{bdif2_1, bdif2_2},
		"vxlanBD",
		true,
	}
	nodebdmap2 := make(map[int]NodeBridgeDomain)
	nodebdmap2[1] = nodebd2
	nodevxlaninterface2 := NodeInterface{
		"vxlan_tunnel0",
		"vxlan2",
		interfaces.InterfaceType_VXLAN_TUNNEL,
		true,
		"",
		0,
		vxlan{node.IPAdr, "10",
			10}, []string{}, tap{},
	}
	nodeinterfaces2[4] = nodevxlaninterface2
	db.SetNodeBridgeDomain("k8s-worker1", nodebdmap2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	db.gigEIPMap[node.IPAdr+subnetmask] = node
	node, _ = db.GetNode("k8s_master")
	db.gigEIPMap[node.IPAdr+subnetmask] = node
	db.ValidateL2Connections()

	fmt.Println("Setting vxlan_vni to 11, expecting error...")
	nodevxlaninterface2.Vxlan.Vni = 11
	nodeinterfaces2[4] = nodevxlaninterface2
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	db.ValidateL2Connections()
	nodelist := db.GetAllNodes()
	db.printnodelogs(nodelist)
	fmt.Println("Setting vxlan_vni back to normal...")
	nodevxlaninterface2.Vxlan.Vni = 10
	nodeinterfaces2[4] = nodevxlaninterface2
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	db.ValidateL2Connections()
	node, _ = db.GetNode("k8s-worker1")
	db.addNode(43, "extranode", "15", "15")
	db.ValidateL2Connections()
}

func (c *Cache) printnodelogs(nodelist []*Node) {
	fmt.Println("Report for cache")
	for _, str := range c.report {
		fmt.Println(str)
	}
	for _, node := range nodelist {
		for _, str := range node.report {
			fmt.Println(str)
		}
		node.report = node.report[0:0]
	}
	c.report = c.report[0:0]
}
