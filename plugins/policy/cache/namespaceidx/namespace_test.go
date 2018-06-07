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

package namespaceidx

import (
	"testing"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
)

func TestNewConfigIndex(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())
}

func TestRegisterUnregister(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		namespaceIDone   = "default"
		namespaceIDtwo   = "pepsi"
		namespaceIDthree = "coke"
	)

	namespaceDataOne := &nsmodel.Namespace{
		Name: namespaceIDone,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts1",
			},
			{
				Key:   "project",
				Value: "ts2",
			},
		},
	}
	namespaceDataTwo := &nsmodel.Namespace{
		Name: namespaceIDone,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts1",
			},
		},
	}
	namespaceDataThree := &nsmodel.Namespace{
		Name: namespaceIDone,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts2",
			},
		},
	}

	res := idx.ListAll()
	gomega.Expect(res).To(gomega.BeNil())

	idx.RegisterNamespace(namespaceIDone, namespaceDataOne)
	idx.RegisterNamespace(namespaceIDtwo, namespaceDataTwo)
	idx.RegisterNamespace(namespaceIDthree, namespaceDataThree)

	found, data := idx.LookupNamespace(namespaceIDone)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(namespaceDataOne))

	found, data = idx.LookupNamespace(namespaceIDtwo)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(namespaceDataTwo))

	found, data = idx.LookupNamespace(namespaceIDthree)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(namespaceDataThree))

	idx.UnRegisterNamespace(namespaceIDone)
	found, _ = idx.LookupNamespace(namespaceIDone)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnRegisterNamespace(namespaceIDtwo)
	found, _ = idx.LookupNamespace(namespaceIDtwo)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnRegisterNamespace(namespaceIDthree)
	found, _ = idx.LookupNamespace(namespaceIDthree)
	gomega.Expect(found).To(gomega.BeFalse())

	// unregistering of non-existing item does nothing
	idx.UnRegisterNamespace(namespaceIDthree)

}

func TestSecondaryIndexLookup(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		namespaceIDone   = "default"
		namespaceIDtwo   = "pepsi"
		namespaceIDthree = "coke"
		namespaceIDFour  = "nike"
	)

	const (
		label1 = "project/ts1"
		label2 = "project/ts2"
		key1   = "project"
		key2   = "random"
	)

	namespaceDataOne := &nsmodel.Namespace{
		Name: namespaceIDone,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts1",
			},
			{
				Key:   "project",
				Value: "ts2",
			},
		},
	}
	namespaceDataTwo := &nsmodel.Namespace{
		Name: namespaceIDtwo,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts1",
			},
		},
	}
	namespaceDataThree := &nsmodel.Namespace{
		Name: namespaceIDthree,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "project",
				Value: "ts2",
			},
		},
	}
	namespaceDataFour := &nsmodel.Namespace{
		Name: namespaceIDFour,
		Label: []*nsmodel.Namespace_Label{
			{
				Key:   "random",
				Value: "ts5",
			},
		},
	}

	idx.RegisterNamespace(namespaceIDone, namespaceDataOne)
	idx.RegisterNamespace(namespaceIDtwo, namespaceDataTwo)
	idx.RegisterNamespace(namespaceIDthree, namespaceDataThree)
	idx.RegisterNamespace(namespaceIDFour, namespaceDataFour)

	all := idx.ListAll()
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDone))
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDtwo))
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDthree))
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDFour))

	lsMatch := idx.LookupNamespacesByLabelSelector(label1)
	gomega.Expect(lsMatch).To(gomega.ContainElement(namespaceIDone))
	gomega.Expect(lsMatch).To(gomega.ContainElement(namespaceIDtwo))

	lsMatch = idx.LookupNamespacesByLabelSelector(label2)
	gomega.Expect(lsMatch).To(gomega.ContainElement(namespaceIDone))
	gomega.Expect(lsMatch).To(gomega.ContainElement(namespaceIDthree))

	keyMatch := idx.LookupNamespacesByKey(key2)
	gomega.Expect(keyMatch).To(gomega.ContainElement(namespaceIDFour))

	keyMatch = idx.LookupNamespacesByKey(key1)
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDone))
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDtwo))
	gomega.Expect(all).To(gomega.ContainElement(namespaceIDthree))
}
