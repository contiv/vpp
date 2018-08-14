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
	"github.com/contiv/vpp/plugins/ksr/model/node"
	pod2 "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/onsi/gomega"
	"testing"
)

func TestNewK8sDataStore(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

}

func TestK8sDataStore_CreateK8sNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	err = db.CreateK8sNode("k8s-master", "", "", nil, nil)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestK8sDataStore_CreatePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()

	labels := []*pod2.Pod_Label{{Key: "123", Value: "431"}}
	db.CreatePod("k8s-pod1", "namespace1", labels, "1.2.3.4", "hostip", nil)
	pod, err := db.RetrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))

	err = db.CreatePod("k8s-pod1", "", nil, "", "", nil)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

func TestK8sDataStore_DeleteK8sNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	err = db.DeleteK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())

	err = db.DeleteK8sNode("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

func TestK8sDataStore_DeletePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	db.CreatePod("k8s-pod1", "namespace1", nil, "1.2.3.4", "hostip", nil)
	pod, err := db.retrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))

	err = db.DeletePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())

	err = db.DeletePod("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}
func TestK8sDataStore_RetrieveK8sNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.RetrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	_, err = db.RetrieveK8sNode("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestK8sDataStore_RetrievePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	db.CreatePod("k8s-pod1", "namespace1", nil, "1.2.3.4", "hostip", nil)
	pod, err := db.RetrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))

	_, err = db.RetrievePod("blah")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

func TestK8sDataStore_UpdateK8sNode(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	db.UpdateK8sNode("k8s-master", "321", "54321", nil, nil)
	node, err = db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.NodeInfo).To(gomega.BeNil())

	err = db.UpdateK8sNode("blah", "", "", nil, nil)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

}

func TestK8sDataStore_UpdatePod(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	db.CreatePod("k8s-pod1", "namespace1", nil, "1.2.3.4", "hostip", nil)
	pod, err := db.retrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))

	db.UpdatePod(pod.Name, "oekfe", nil, "4.32.1", "", nil)
	pod, err = db.retrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))
	gomega.Expect(pod.Namespace).To(gomega.BeEquivalentTo("oekfe"))

	err = db.UpdatePod("bla", "", nil, "", "", nil)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}

func TestK8sDataStore_RetrieveAllK8sNodes(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	db.CreateK8sNode("k8s-worker1", "2", "432", nil, nil)

	k8snodelist := db.RetrieveAllK8sNodes()

	gomega.Expect(k8snodelist[0].Name).To(gomega.BeEquivalentTo("k8s-master"))
	gomega.Expect(k8snodelist[1].Name).To(gomega.BeEquivalentTo("k8s-worker1"))

}

func TestK8sDataStore_RetrieveAllPods(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	db.CreatePod("k8s-pod1", "namespace1", nil, "1.2.3.4", "hostip", nil)
	pod, err := db.retrievePod("k8s-pod1")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(pod.Name).To(gomega.BeEquivalentTo("k8s-pod1"))

	db.CreatePod("pod2", "", nil, "", "k", nil)

	podlist := db.RetrieveAllPods()

	gomega.Expect(podlist[0].Name).To(gomega.BeEquivalentTo("k8s-pod1"))
	gomega.Expect(podlist[1].Name).To(gomega.BeEquivalentTo("pod2"))

}

func TestK8sDataStore_ReinitializeCache(t *testing.T) {
	gomega.RegisterTestingT(t)
	db := NewK8sDataStore()
	nodeAddresses := []*node.NodeAddress{}
	nodeAddresses = append(nodeAddresses, &node.NodeAddress{Type: 3, Address: "54321"})
	db.CreateK8sNode("k8s-master", "123", "12345", nodeAddresses, &node.NodeSystemInfo{})
	node, err := db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(node.Name).To(gomega.BeEquivalentTo("k8s-master"))

	db.ReinitializeCache()
	node, err = db.retrieveK8sNode("k8s-master")
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))
}
