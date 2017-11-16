// Copyright (c) 2017 Cisco and/or its affiliates.
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

package containeridx

import (
	"testing"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/onsi/gomega"
)

func TestNewConfigIndex(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logroot.StandardLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())
}

func TestRegisterUnregister(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logroot.StandardLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		containerIDOne = "48023423"
		containerIDTwo = "asdfadsf"
	)

	res := idx.ListAll()
	gomega.Expect(res).To(gomega.BeNil())

	idx.RegisterContainer(containerIDOne, nil)
	idx.RegisterContainer(containerIDTwo, nil)

	found, _ := idx.LookupContainer(containerIDOne)
	gomega.Expect(found).To(gomega.BeTrue())

	found, _ = idx.LookupContainer(containerIDTwo)
	gomega.Expect(found).To(gomega.BeTrue())

	idx.UnregisterContainer(containerIDOne)

	found, _ = idx.LookupContainer(containerIDOne)
	gomega.Expect(found).To(gomega.BeFalse())

	// unregistering of non-existing item does nothing
	idx.UnregisterContainer(containerIDOne)
}

func TestSecondaryIndexLookup(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logroot.StandardLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		containerA = "AAA"
		containerB = "BBB"
		podNs      = "myNamespace"
		podA       = "123"
		podB       = "456"
	)

	configA := &Config{PodNamespace: podNs, PodName: podA}
	configB := &Config{PodNamespace: podNs, PodName: podB}

	idx.RegisterContainer(containerA, configA)
	idx.RegisterContainer(containerB, configB)

	all := idx.ListAll()
	gomega.Expect(all).To(gomega.ContainElement(containerA))
	gomega.Expect(all).To(gomega.ContainElement(containerB))

	nsMatch := idx.LookupPodNamespace(podNs)
	gomega.Expect(nsMatch).To(gomega.ContainElement(containerA))
	gomega.Expect(nsMatch).To(gomega.ContainElement(containerB))

	podMatch := idx.LookupPodName(podA)
	gomega.Expect(podMatch).To(gomega.ContainElement(containerA))

}
