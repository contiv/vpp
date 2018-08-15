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

package datastore

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/onsi/gomega"
	"testing"
)

//Checks adding a new node.
//Checks expected error for adding duplicate node.
func TestVppDataStore_CreateNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "20")
	node, err := db.RetrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	err = db.CreateNode(2, "k8s_master", "20", "20")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

//Checks adding a node and then looking it up.
//Checks looking up a non-existent key.
func TestVppDataStore_RetrieveNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, err := db.RetrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeTwo, err := db.RetrieveNode("NonExistentNode")
	gomega.Ω(err).Should(gomega.Not(gomega.BeNil()))
	gomega.Expect(nodeTwo).To(gomega.BeNil())
}

//Checks adding a node and then deleting it.
//Checks whether expected error is returned when deleting non-existent key.
func TestVppDataStore_DeleteNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, err := db.RetrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))

	err = db.DeleteNode("k8s_master")
	gomega.Expect(err).To(gomega.BeNil())
	node, err = db.RetrieveNode("k8s_master")
	gomega.Expect(node).To(gomega.BeNil())
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

	err = db.DeleteNode("k8s_master")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

//Creates 3 new nodes and adds them to a database.
//Then, the list is checked to see if it is in order.
func TestVppDataStore_RetrieveAllNodes(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, e := db.RetrieveNode("k8s_master")
	gomega.Expect(e).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.CreateNode(2, "k8s_master2", "10", "10")
	node, e = db.RetrieveNode("k8s_master2")
	gomega.Expect(e).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master2"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(2)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.CreateNode(3, "Ak8s_master3", "10", "10")
	node, e = db.RetrieveNode("Ak8s_master3")
	gomega.Expect(e).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("Ak8s_master3"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(3)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	nodeList := db.RetrieveAllNodes()
	gomega.Expect(len(nodeList)).To(gomega.Equal(3))
	gomega.Expect(nodeList[0].Name).To(gomega.Equal("Ak8s_master3"))

}

func TestVppDataStore_SetNodeInterfaces(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_SetNodeBridgeDomain(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_SetNodeIPARPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_SetNodeLiveness(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_SetNodeTelemetry(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_SetNodeL2Fibs(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
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

func TestVppDataStore_RetrieveNodeByGigEIPAddr(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	node, err := db.RetrieveNodeByGigEIPAddr(node.IPAdr)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s_master"))

	node, err = db.RetrieveNodeByGigEIPAddr("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_RetrieveNodeByHostIPAddr(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	node, err := db.RetrieveNodeByGigEIPAddr(node.IPAdr)
	gomega.Expect(err).To(gomega.BeNil())
	db.HostIPMap["10"] = node

	node, err = db.RetrieveNodeByHostIPAddr("10")
	gomega.Expect(err).To(gomega.BeNil())

	node, err = db.RetrieveNodeByHostIPAddr("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_RetrieveNodeByLoopIPAddr(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	node, err := db.RetrieveNodeByGigEIPAddr(node.IPAdr)
	gomega.Expect(err).To(gomega.BeNil())

	db.LoopIPMap["10"] = node
	node, err = db.RetrieveNodeByLoopIPAddr("10")
	gomega.Expect(err).To(gomega.BeNil())

	node, err = db.RetrieveNodeByLoopIPAddr("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_RetrieveNodeByLoopMacAddr(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	node, err := db.RetrieveNodeByGigEIPAddr(node.IPAdr)
	gomega.Expect(err).To(gomega.BeNil())

	db.LoopMACMap["10"] = node
	node, err = db.RetrieveNodeByLoopMacAddr("10")
	gomega.Expect(err).To(gomega.BeNil())

	_, err = db.RetrieveNodeByLoopMacAddr("0123012031023")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_UpdateNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	err := db.UpdateNode(1, "k8s_master", "20", "20")
	gomega.Expect(err).To(gomega.BeNil())
	node, err = db.RetrieveNode("k8s_master")

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.BeEquivalentTo("20"))

	err = db.UpdateNode(1, "blah", "2", "2")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_ClearCache(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.CreateNode(2, "blah", "20", "20")
	db.ClearCache()

	_, err := db.retrieveNode("k8s_master")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

	_, err = db.retrieveNode("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestVppDataStore_ReinitializeCache(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))

	db.ReinitializeCache()
	_, err := db.retrieveNode("k8s_master")

	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestGetNodeLoopIFInfo(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewVppDataStore()
	db.CreateNode(1, "k8s_master", "10", "10")
	node, ok := db.RetrieveNode("k8s_master")
	gomega.Expect(ok).To(gomega.BeNil())
	gomega.Expect(node.IPAdr).To(gomega.Equal("10"))
	gomega.Expect(node.Name).To(gomega.Equal("k8s_master"))
	gomega.Expect(node.ID).To(gomega.Equal(uint32(1)))
	gomega.Expect(node.ManIPAdr).To(gomega.Equal("10"))
	loopif := telemetrymodel.NodeInterface{"loop0", "loop0", 1, true, "12", 10, telemetrymodel.Vxlan{}, nil, telemetrymodel.Tap{}}
	interfaces := make(map[int]telemetrymodel.NodeInterface)
	interfaces[3] = loopif
	db.SetNodeInterfaces(node.Name, interfaces)
	_, err := GetNodeLoopIFInfo(node)
	gomega.Expect(err).To(gomega.BeNil())
	delete(interfaces, 3)
	_, err = GetNodeLoopIFInfo(node)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}
