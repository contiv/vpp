package cache

import (
	"testing"

	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/onsi/gomega"
)

func TestNodesDB_ValidateLoopIFAddresses(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewVppDataStore(logger)
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
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+SubnetMask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.retrieveNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+SubnetMask] = node

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


func TestCache_ValidateFibEntries(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logrus.DefaultLogger()
	db := NewVppDataStore(logger)
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
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+SubnetMask] = node

	db.SetNodeIPARPs("k8s-worker1", nodeiparps2)
	db.SetNodeInterfaces("k8s-worker1", nodeinterfaces2)
	node, ok = db.retrieveNode("k8s-worker1")
	db.loopMACMap[node.NodeInterfaces[3].PhysAddress] = node
	db.loopIPMap[node.NodeInterfaces[3].IPAddresses[0]+SubnetMask] = node
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
	db.gigEIPMap[node.IPAdr+SubnetMask] = node
	node, _ = db.retrieveNode("k8s_master")
	db.gigEIPMap[node.IPAdr+SubnetMask] = node

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
