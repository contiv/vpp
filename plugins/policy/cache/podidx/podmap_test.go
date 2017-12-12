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

package podidx

import (
	"testing"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
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
		podIDone   = "default/pod1"
		podIDtwo   = "default/pod2"
		podIDthree = "default/pod3"
		podIDfour  = "other/pod4"
	)

	podDataOne := &podmodel.Pod{
		Name:      "pod1",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "db",
			},
			{
				Key:   "app",
				Value: "webstore",
			},
		},
	}
	podDataTwo := &podmodel.Pod{
		Name:      "pod2",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "db",
			},
			{
				Key:   "role",
				Value: "frontend",
			},
		},
	}
	podDataThree := &podmodel.Pod{
		Name:      "pod3",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "app",
				Value: "datastore",
			},
		},
	}
	podDataFour := &podmodel.Pod{
		Name:      "pod4",
		Namespace: "other",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "other",
			},
		},
	}

	res := idx.ListAll()
	gomega.Expect(res).To(gomega.BeNil())

	idx.RegisterPod(podIDone, podDataOne)
	idx.RegisterPod(podIDtwo, podDataTwo)
	idx.RegisterPod(podIDthree, podDataThree)
	idx.RegisterPod(podIDfour, podDataFour)

	found, data := idx.LookupPod(podIDone)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(podDataOne))

	found, data = idx.LookupPod(podIDtwo)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(podDataTwo))

	found, data = idx.LookupPod(podIDthree)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(podDataThree))

	found, data = idx.LookupPod(podIDfour)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(data).To(gomega.BeIdenticalTo(podDataFour))

	idx.UnregisterPod(podIDone)
	found, _ = idx.LookupPod(podIDone)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPod(podIDtwo)
	found, _ = idx.LookupPod(podIDtwo)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPod(podIDthree)
	found, _ = idx.LookupPod(podIDthree)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPod(podIDfour)
	found, _ = idx.LookupPod(podIDfour)
	gomega.Expect(found).To(gomega.BeFalse())

	// unregistering of non-existing item does nothing
	idx.UnregisterPod(podIDthree)

}

func TestSecondaryIndexLookup(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		podIDone   = "default/pod1"
		podIDtwo   = "default/pod2"
		podIDthree = "default/pod3"
		podIDfour  = "other/pod4"
	)

	const (
		label1 = "default/role/db"
		label2 = "default/role/frontend"
		label3 = "other/role/other"
		label4 = "role/db"
		label5 = "role/frontend"
		label6 = "role/other"
		nsKey1 = "default/role"
		nsKey2 = "other/role"
		key1   = "role"
		key2   = "app"
	)

	podDataOne := &podmodel.Pod{
		Name:      "pod1",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "db",
			},
			{
				Key:   "app",
				Value: "webstore",
			},
		},
	}
	podDataTwo := &podmodel.Pod{
		Name:      "pod2",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "db",
			},
			{
				Key:   "role",
				Value: "frontend",
			},
		},
	}
	podDataThree := &podmodel.Pod{
		Name:      "pod3",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "app",
				Value: "datastore",
			},
		},
	}
	podDataFour := &podmodel.Pod{
		Name:      "pod4",
		Namespace: "other",
		Label: []*podmodel.Pod_Label{
			{
				Key:   "role",
				Value: "other",
			},
			{
				Key:   "role",
				Value: "db",
			},
		},
	}

	idx.RegisterPod(podIDone, podDataOne)
	idx.RegisterPod(podIDtwo, podDataTwo)
	idx.RegisterPod(podIDthree, podDataThree)
	idx.RegisterPod(podIDfour, podDataFour)

	all := idx.ListAll()
	gomega.Expect(all).To(gomega.ContainElement(podIDone))
	gomega.Expect(all).To(gomega.ContainElement(podIDtwo))
	gomega.Expect(all).To(gomega.ContainElement(podIDthree))
	gomega.Expect(all).To(gomega.ContainElement(podIDfour))

	nsKeyMatch := idx.LookupPodsByNSKey(nsKey1)
	gomega.Expect(nsKeyMatch).To(gomega.ContainElement(podIDone))
	gomega.Expect(nsKeyMatch).To(gomega.ContainElement(podIDtwo))

	nsKeyMatch = idx.LookupPodsByNSKey(nsKey2)
	gomega.Expect(nsKeyMatch).To(gomega.BeEquivalentTo([]string{podIDfour}))

	nsLabelMatch := idx.LookupPodsByNSLabelSelector(label1)
	gomega.Expect(nsLabelMatch).To(gomega.ContainElement(podIDone))
	gomega.Expect(nsLabelMatch).To(gomega.ContainElement(podIDtwo))

	nsLabelMatch = idx.LookupPodsByNSLabelSelector(label2)
	gomega.Expect(nsLabelMatch).To(gomega.BeEquivalentTo([]string{podIDtwo}))

	nsLabelMatch = idx.LookupPodsByNSLabelSelector(label3)
	gomega.Expect(nsLabelMatch).To(gomega.BeEquivalentTo([]string{podIDfour}))

	labelMatch := idx.LookupPodsByLabelSelector(label4)
	gomega.Expect(labelMatch).To(gomega.ContainElement(podIDone))
	gomega.Expect(labelMatch).To(gomega.ContainElement(podIDtwo))
	gomega.Expect(labelMatch).To(gomega.ContainElement(podIDfour))

	labelMatch = idx.LookupPodsByLabelSelector(label5)
	gomega.Expect(labelMatch).To(gomega.BeEquivalentTo([]string{podIDtwo}))

	labelMatch = idx.LookupPodsByLabelSelector(label6)
	gomega.Expect(labelMatch).To(gomega.BeEquivalentTo([]string{podIDfour}))

	keyMatch := idx.LookupPodsByLabelKey(key1)
	gomega.Expect(keyMatch).To(gomega.ContainElement(podIDone))
	gomega.Expect(keyMatch).To(gomega.ContainElement(podIDtwo))
	gomega.Expect(keyMatch).To(gomega.ContainElement(podIDfour))

	keyMatch = idx.LookupPodsByLabelKey(key2)
	gomega.Expect(keyMatch).To(gomega.ContainElement(podIDthree))
	gomega.Expect(keyMatch).To(gomega.ContainElement(podIDone))

}
