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

package ksr

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/ligato/cn-infra/flavors/local"
)

type NodeTestVars struct {
	k8sListWatch      *mockK8sListWatch
	mockKvBroker      *mockKeyProtoValBroker
	nodeReflector     *NodeReflector
	nodeTestData      []coreV1.Node
	reflectorRegistry ReflectorRegistry
}

var nodeTestVars NodeTestVars

func TestNodeReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	nodeTestVars.k8sListWatch = &mockK8sListWatch{}
	nodeTestVars.mockKvBroker = newMockKeyProtoValBroker()

	nodeTestVars.reflectorRegistry = ReflectorRegistry{
		reflectors: make(map[string]*Reflector),
		lock:       sync.RWMutex{},
	}

	nodeTestVars.nodeReflector = &NodeReflector{
		Reflector: Reflector{
			Log:               flavorLocal.LoggerFor("node-reflector"),
			K8sClientset:      &kubernetes.Clientset{},
			K8sListWatch:      nodeTestVars.k8sListWatch,
			Broker:            nodeTestVars.mockKvBroker,
			dsSynced:          false,
			objType:           nodeObjType,
			ReflectorRegistry: &nodeTestVars.reflectorRegistry,
		},
	}

	nodeTestVars.nodeTestData = []coreV1.Node{
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "test-node-1",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/nodes/test-node-1",
				UID:             "44a9312f-f99f-11e7-b9b5-0800271d72be",
				ResourceVersion: "692693",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1.NodeSpec{
				PodCIDR:    "10.20.30.40/24",
				ProviderID: "Provider1",
			},
			Status: coreV1.NodeStatus{
				NodeInfo: coreV1.NodeSystemInfo{
					MachineID:               "db583cb14a226054981e9c4659f785fc",
					SystemUUID:              "ABDB4E0A-664E-46B1-8CB3-1A81A7C7BDCC",
					BootID:                  "4f6d0486-260b-4da8-b672-73af17727874",
					KernelVersion:           "4.4.0-112-generic",
					OSImage:                 "Ubuntu 16.04.3 LTS",
					ContainerRuntimeVersion: "docker://1.13.1",
					KubeletVersion:          "v1.9.2",
					KubeProxyVersion:        "v1.9.2",
					OperatingSystem:         "linux",
					Architecture:            "amd64",
				},
				Addresses: []coreV1.NodeAddress{
					{Type: coreV1.NodeInternalIP, Address: "192.168.56.103"},
					{Type: coreV1.NodeExternalIP, Address: "192.168.56.104"},
					{Type: coreV1.NodeHostName, Address: "master"},
					{Type: coreV1.NodeExternalDNS, Address: "host1.1"},
					{Type: coreV1.NodeInternalDNS, Address: "host1.1"},
					{Type: "Bogus", Address: "Whatever"},
				},
			},
		},
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "test-node-2",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/nodes/test-node-2",
				UID:             "44a9312f-f99f-11e7-b9b5-0800271d72be",
				ResourceVersion: "692693",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1.NodeSpec{
				PodCIDR:    "10.20.30.40/24",
				ProviderID: "Provider2",
			},
			Status: coreV1.NodeStatus{
				NodeInfo: coreV1.NodeSystemInfo{
					MachineID:               "db583cb14a226054981e9c4659f785fc",
					SystemUUID:              "ABDB4E0A-664E-46B1-8CB3-1A81A7C7BDCC",
					BootID:                  "4f6d0486-260b-4da8-b672-73af17727874",
					KernelVersion:           "4.4.0-112-generic",
					OSImage:                 "Ubuntu 16.04.3 LTS",
					ContainerRuntimeVersion: "docker://1.13.1",
					KubeletVersion:          "v1.9.2",
					KubeProxyVersion:        "v1.9.2",
					OperatingSystem:         "linux",
					Architecture:            "amd64",
				},
				Addresses: []coreV1.NodeAddress{
					{Type: coreV1.NodeInternalIP, Address: "192.168.56.105"},
					{Type: coreV1.NodeExternalIP, Address: "192.168.56.106"},
					{Type: coreV1.NodeHostName, Address: "worker2"},
					{Type: coreV1.NodeExternalDNS, Address: "host2.1"},
					{Type: coreV1.NodeInternalDNS, Address: "host2.2"},
				},
			},
		},
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "test-node-3",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/nodes/test-node-3",
				UID:             "44a9312f-f99f-11e7-b9b5-0800271d72be",
				ResourceVersion: "692693",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1.NodeSpec{
				PodCIDR:    "100.200.210.220/24",
				ProviderID: "Provider2",
			},
			Status: coreV1.NodeStatus{
				NodeInfo: coreV1.NodeSystemInfo{
					MachineID:               "db583cb14a226054981e9c4659f785fc",
					SystemUUID:              "ABDB4E0A-664E-46B1-8CB3-1A81A7C7BDCC",
					BootID:                  "4f6d0486-260b-4da8-b672-73af17727874",
					KernelVersion:           "4.4.0-112-generic",
					OSImage:                 "Ubuntu 16.04.3 LTS",
					ContainerRuntimeVersion: "docker://1.13.1",
					KubeletVersion:          "v1.9.2",
					KubeProxyVersion:        "v1.9.2",
					OperatingSystem:         "linux",
					Architecture:            "amd64",
				},
				Addresses: []coreV1.NodeAddress{
					{Type: coreV1.NodeInternalIP, Address: "192.168.56.107"},
					{Type: coreV1.NodeExternalIP, Address: "192.168.56.108"},
					{Type: coreV1.NodeHostName, Address: "worker3"},
					{Type: coreV1.NodeExternalDNS, Address: "host3.1"},
					{Type: coreV1.NodeInternalDNS, Address: "host3.2"},
				},
			},
		},
	}

	// The mock function returns two K8s mock endpoints instances:
	// - a new endpoints instance to be added to the data store
	// - a modified endpoints instance, where and existing instance in the
	//   data store is to be updated
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			// Updated value mock
			&nodeTestVars.nodeTestData[0],
			// New value mock
			&nodeTestVars.nodeTestData[1],
		}
	}

	// Pre-populate the mock data store with pre-existing node data that is
	// supposed to be updated during the test.
	k8sNode1 := &nodeTestVars.nodeTestData[1]
	protoNode1 := nodeTestVars.nodeReflector.nodeToProto(k8sNode1)
	checkNodeToProtoTranslation(t, protoNode1, k8sNode1)

	protoNode1.Addresses[0].Address = "172.16.78.249"

	nodeTestVars.mockKvBroker.Put(node.Key(k8sNode1.GetName()), protoNode1)

	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during resync.
	k8sNode2 := &nodeTestVars.nodeTestData[2]
	protoNode2 := nodeTestVars.nodeReflector.nodeToProto(k8sNode2)
	checkNodeToProtoTranslation(t, protoNode2, k8sNode2)

	nodeTestVars.mockKvBroker.Put(node.Key(k8sNode2.GetName()), protoNode2)

	sStat := *nodeTestVars.nodeReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := nodeTestVars.nodeReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	nodeTestVars.nodeReflector.startDataStoreResync()

	// Wait for the initial sync to finish
	for {
		if nodeTestVars.nodeReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	gomega.Expect(nodeTestVars.mockKvBroker.ds).Should(gomega.HaveLen(2))
	gomega.Expect(sStat.Adds + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Adds))
	gomega.Expect(sStat.Updates + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Updates))
	gomega.Expect(sStat.Updates + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Deletes))
	gomega.Expect(sStat.Resyncs + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Resyncs))

	nodeTestVars.mockKvBroker.ClearDs()
	t.Run("testAddDeleteNode", testAddDeleteNode)

	nodeTestVars.mockKvBroker.ClearDs()
	t.Run("testUpdateNode", testUpdateNode)
}

func testAddDeleteNode(t *testing.T) {
	// Test the node add operation
	for _, k8sNode := range nodeTestVars.nodeTestData {
		// Take a snapshot of counters
		adds := nodeTestVars.nodeReflector.GetStats().Adds
		argErrs := nodeTestVars.nodeReflector.GetStats().ArgErrors

		// Test add with wrong argument type
		nodeTestVars.k8sListWatch.Add(k8sNode)

		gomega.Expect(argErrs + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().ArgErrors))
		gomega.Expect(adds).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Adds))

		// Test add where everything should be good
		nodeTestVars.k8sListWatch.Add(&k8sNode)

		key := node.Key(k8sNode.GetName())
		protoNode := &node.Node{}
		found, _, err := nodeTestVars.mockKvBroker.GetValue(key, protoNode)

		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(err).To(gomega.BeNil())
		gomega.Expect(adds + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Adds))
		gomega.Expect(protoNode).NotTo(gomega.BeNil())

		checkNodeToProtoTranslation(t, protoNode, &k8sNode)
	}

	// Test the node delete operation
	for _, k8sNode := range nodeTestVars.nodeTestData {
		// Take a snapshot of counters
		dels := nodeTestVars.nodeReflector.GetStats().Deletes
		argErrs := nodeTestVars.nodeReflector.GetStats().ArgErrors

		// Test delete with wrong argument type
		nodeTestVars.k8sListWatch.Delete(k8sNode)

		gomega.Expect(argErrs + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().ArgErrors))
		gomega.Expect(dels).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Deletes))

		// Test delete where everything should be good
		nodeTestVars.k8sListWatch.Delete(&k8sNode)
		gomega.Expect(dels + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Deletes))

		key := node.Key(k8sNode.GetName())
		protoNode := &node.Node{}
		found, _, err := nodeTestVars.mockKvBroker.GetValue(key, protoNode)
		gomega.Expect(found).To(gomega.BeFalse())
		gomega.Ω(err).Should(gomega.Succeed())
	}

	nodeTestVars.nodeReflector.Log.Infof("%s: data sync done, statistics: %+v",
		nodeTestVars.nodeReflector.objType, nodeTestVars.nodeReflector.stats)
}

func testUpdateNode(t *testing.T) {
	// Prepare test data
	k8sNodeOld := &nodeTestVars.nodeTestData[0]
	tmpBuf, err := json.Marshal(k8sNodeOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sNodeNew := &coreV1.Node{}
	err = json.Unmarshal(tmpBuf, k8sNodeNew)
	gomega.Ω(err).Should(gomega.Succeed())

	protoNode1 := nodeTestVars.nodeReflector.nodeToProto(k8sNodeOld)
	nodeTestVars.mockKvBroker.Put(node.Key(k8sNodeOld.GetName()), protoNode1)

	// Take a snapshot of counters
	upds := nodeTestVars.nodeReflector.GetStats().Updates
	argErrs := nodeTestVars.nodeReflector.GetStats().ArgErrors

	// Test update with wrong argument type
	nodeTestVars.k8sListWatch.Update(*k8sNodeOld, *k8sNodeNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().ArgErrors))
	gomega.Expect(upds).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Updates))

	// Ensure that there is no update if old and new values are the same
	nodeTestVars.k8sListWatch.Update(k8sNodeOld, k8sNodeNew)
	gomega.Expect(upds).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Updates))

	// Test update where everything is good
	k8sNodeNew.Status.Addresses[0].Address = "24.56.78.90"
	nodeTestVars.k8sListWatch.Update(k8sNodeOld, k8sNodeNew)
	gomega.Expect(upds + 1).To(gomega.Equal(nodeTestVars.nodeReflector.GetStats().Updates))

	key := node.Key(k8sNodeOld.GetName())
	protoNodeNew := &node.Node{}
	found, _, err := nodeTestVars.mockKvBroker.GetValue(key, protoNodeNew)

	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Ω(err).Should(gomega.Succeed())

	checkNodeToProtoTranslation(t, protoNodeNew, k8sNodeNew)

	nodeTestVars.nodeReflector.Log.Infof("%s: data sync done, statistics: %+v",
		nodeTestVars.nodeReflector.objType, nodeTestVars.nodeReflector.stats)

}

func checkNodeToProtoTranslation(t *testing.T, protoNode *node.Node, k8sNode *coreV1.Node) {
	gomega.Expect(protoNode.Name).To(gomega.Equal(k8sNode.GetName()))

	gomega.Expect(protoNode.Pod_CIDR).To(gomega.Equal(k8sNode.Spec.PodCIDR))
	gomega.Expect(protoNode.Provider_ID).To(gomega.Equal(k8sNode.Spec.ProviderID))

	gomega.Expect(protoNode.NodeInfo.Architecture).To(gomega.Equal(k8sNode.Status.NodeInfo.Architecture))
	gomega.Expect(protoNode.NodeInfo.Boot_ID).To(gomega.Equal(k8sNode.Status.NodeInfo.BootID))
	gomega.Expect(protoNode.NodeInfo.ContainerRuntimeVersion).
		To(gomega.Equal(k8sNode.Status.NodeInfo.ContainerRuntimeVersion))
	gomega.Expect(protoNode.NodeInfo.KernelVersion).To(gomega.Equal(k8sNode.Status.NodeInfo.KernelVersion))
	gomega.Expect(protoNode.NodeInfo.KubeletVersion).To(gomega.Equal(k8sNode.Status.NodeInfo.KubeletVersion))
	gomega.Expect(protoNode.NodeInfo.KubeProxyVersion).To(gomega.Equal(k8sNode.Status.NodeInfo.KubeProxyVersion))
	gomega.Expect(protoNode.NodeInfo.Machine_ID).To(gomega.Equal(k8sNode.Status.NodeInfo.MachineID))
	gomega.Expect(protoNode.NodeInfo.OperatingSystem).To(gomega.Equal(k8sNode.Status.NodeInfo.OperatingSystem))
	gomega.Expect(protoNode.NodeInfo.OsImage).To(gomega.Equal(k8sNode.Status.NodeInfo.OSImage))

	for i, addr := range protoNode.Addresses {
		switch addr.Type {
		case node.NodeAddress_NodeHostName:
			gomega.Expect(k8sNode.Status.Addresses[i].Type).To(gomega.BeEquivalentTo(string(coreV1.NodeHostName)))
		case node.NodeAddress_NodeInternalIP:
			gomega.Expect(k8sNode.Status.Addresses[i].Type).To(gomega.BeEquivalentTo(string(coreV1.NodeInternalIP)))
		case node.NodeAddress_NodeExternalIP:
			gomega.Expect(k8sNode.Status.Addresses[i].Type).To(gomega.BeEquivalentTo(string(coreV1.NodeExternalIP)))
		case node.NodeAddress_NodeInternalDNS:
			gomega.Expect(k8sNode.Status.Addresses[i].Type).To(gomega.BeEquivalentTo(string(coreV1.NodeInternalDNS)))
		case node.NodeAddress_NodeExternalDNS:
			gomega.Expect(k8sNode.Status.Addresses[i].Type).To(gomega.BeEquivalentTo(string(coreV1.NodeExternalDNS)))
		}

		gomega.Expect(addr.Address).To(gomega.Equal(string(k8sNode.Status.Addresses[i].Address)))
	}
}
