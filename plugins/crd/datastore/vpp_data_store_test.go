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
