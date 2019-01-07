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

package cache

import (
	"testing"

	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache/testdata"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"

	"github.com/contiv/vpp/mock/datasync"
)

func TestLookupPod(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPod")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)

	testPod1 := podmodel.ID{
		Name:      "pod1",
		Namespace: "ns1",
	}

	testPod2 := podmodel.ID{
		Name:      "pod2",
		Namespace: "ns1",
	}

	testPod3 := podmodel.ID{
		Name:      "pod1",
		Namespace: "ns4",
	}

	expectParam1, expectParam2 := pc.LookupPod(testPod1)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.PodOne))

	expectParam1, expectParam2 = pc.LookupPod(testPod2)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.PodTwo))

	expectParam1, expectParam2 = pc.LookupPod(testPod3)
	gomega.Expect(expectParam1).To(gomega.BeFalse())
	gomega.Expect(expectParam2).To(gomega.BeNil())
}

func TestLookupPodsByNSLabelSelector(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPodsByNSLabelSelector")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)
	pc.configuredPods.RegisterPod(testdata.Pod5, testdata.PodFive)
	pc.configuredPods.RegisterPod(testdata.Pod6, testdata.PodSix)

	expectParam := pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel0)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFive)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodSix)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel1)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace2, testdata.CombinationLabel2)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace2, testdata.CombinationLabel3)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace2, testdata.CombinationLabel4)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel5)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFive)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodSix)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace2, testdata.CombinationLabel6)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFour)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel7)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel12)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFive)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodSix)))

	expectParam = pc.LookupPodsByLabelSelectorInsideNs(testdata.Namespace1, testdata.CombinationLabel13)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFive)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodSix)))
}

func TestLookupPodsByLabelSelector(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPodsByLabelSelector")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)
	pc.configuredPods.RegisterPod(testdata.Pod5, testdata.PodFive)
	pc.configuredPods.RegisterPod(testdata.Pod6, testdata.PodSix)

	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace1, testdata.TestNamespace1)
	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace2, testdata.TestNamespace2)

	expectParam := pc.LookupPodsByNsLabelSelector(testdata.CombinationLabel0)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFour)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFive)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodSix)))

	expectParam = pc.LookupPodsByNsLabelSelector(testdata.CombinationLabel8)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFour)))

	expectParam = pc.LookupPodsByNsLabelSelector(testdata.CombinationLabel9)
	gomega.Expect(expectParam).To(gomega.BeEmpty())
}

func TestLookupPodsByNamespace(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPodsByNamespace")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)

	testNamespace1 := "ns1"
	testNamespace2 := "ns2"
	testNamespaceN := "nsN"

	expectParam := pc.LookupPodsByNamespace(testNamespace1)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))

	expectParam = pc.LookupPodsByNamespace(testNamespace2)
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFour)))

	expectParam = pc.LookupPodsByNamespace(testNamespaceN)
	gomega.Expect(expectParam).To(gomega.BeEmpty())
}

func TestListAllPods(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestListAllPods")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)

	expectParam := pc.ListAllPods()
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodOne)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodTwo)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodThree)))
	gomega.Expect(expectParam).To(gomega.ContainElement(podmodel.GetID(testdata.PodFour)))

}

func TestLookupPolicy(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPolicy")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredPolicies.RegisterPolicy(testdata.Policy1, testdata.TestPolicy1)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy2, testdata.TestPolicy2)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy3, testdata.TestPolicy3)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy4, testdata.TestPolicy4)

	policy1 := policymodel.ID{
		Name:      "deny-all-traffic",
		Namespace: "ns1",
	}

	policy2 := policymodel.ID{
		Name:      "api-allow",
		Namespace: "ns1",
	}

	policy3 := policymodel.ID{
		Name:      "web-allow-all",
		Namespace: "ns4",
	}

	expectParam1, expectParam2 := pc.LookupPolicy(policy1)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.TestPolicy1))

	expectParam1, expectParam2 = pc.LookupPolicy(policy2)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.TestPolicy2))

	expectParam1, expectParam2 = pc.LookupPolicy(policy3)
	gomega.Expect(expectParam1).To(gomega.BeFalse())
	gomega.Expect(expectParam2).To(gomega.BeNil())
}

func TestLookupPoliciesByPod(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupPoliciesByPod")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()
	//Register Pods
	pc.configuredPods.RegisterPod(testdata.Pod1, testdata.PodOne)
	pc.configuredPods.RegisterPod(testdata.Pod2, testdata.PodTwo)
	pc.configuredPods.RegisterPod(testdata.Pod3, testdata.PodThree)
	pc.configuredPods.RegisterPod(testdata.Pod4, testdata.PodFour)
	//Register Policies
	pc.configuredPolicies.RegisterPolicy(testdata.Policy1, testdata.TestPolicy1)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy2, testdata.TestPolicy2)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy3, testdata.TestPolicy3)
	pc.configuredPolicies.RegisterPolicy(testdata.Policy4, testdata.TestPolicy4)

	testPod0 := podmodel.ID{
		Name:      "pod1",
		Namespace: "ns5",
	}

	testPod1 := podmodel.ID{
		Name:      "pod1",
		Namespace: "ns1",
	}

	testPod2 := podmodel.ID{
		Name:      "pod2",
		Namespace: "ns1",
	}

	testPod3 := podmodel.ID{
		Name:      "pod1",
		Namespace: "ns4",
	}

	expectParam := pc.LookupPoliciesByPod(testPod0)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.LookupPoliciesByPod(testPod1)
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy1)))
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy3)))
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy4)))

	expectParam = pc.LookupPoliciesByPod(testPod2)
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy1)))
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy3)))
	gomega.Expect(expectParam).To(gomega.ContainElement(policymodel.GetID(testdata.TestPolicy4)))

	expectParam = pc.LookupPoliciesByPod(testPod3)
	gomega.Expect(expectParam).To(gomega.BeEmpty())
}

func TestLookupNamespace(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupNamespace")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace1, testdata.TestNamespace1)
	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace2, testdata.TestNamespace2)

	ns1 := namespace.ID("ns1")
	ns2 := namespace.ID("ns2")
	ns3 := namespace.ID("ns3")

	expectParam1, expectParam2 := pc.LookupNamespace(ns1)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.TestNamespace1))

	expectParam1, expectParam2 = pc.LookupNamespace(ns2)
	gomega.Expect(expectParam1).To(gomega.BeTrue())
	gomega.Expect(expectParam2).To(gomega.BeEquivalentTo(testdata.TestNamespace2))

	expectParam1, expectParam2 = pc.LookupNamespace(ns3)
	gomega.Expect(expectParam1).To(gomega.BeFalse())
	gomega.Expect(expectParam2).To(gomega.BeNil())
}

func TestListAllNamespaces(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestLookupNamespace")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pc.Init()

	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace1, testdata.TestNamespace1)
	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace2, testdata.TestNamespace2)

	expectParam := pc.ListAllNamespaces()
	gomega.Expect(expectParam).To(gomega.ContainElement(namespace.GetID(testdata.TestNamespace1)))
	gomega.Expect(expectParam).To(gomega.ContainElement(namespace.GetID(testdata.TestNamespace2)))
}

func TestUpdate(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestUpdate")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}

	pod1 := podmodel.ID{Name: "pod1", Namespace: testdata.Namespace1}
	pod2 := podmodel.ID{Name: "pod2", Namespace: testdata.Namespace2}
	pod3 := podmodel.ID{Name: "pod3", Namespace: testdata.Namespace1}

	pod1aModel := &podmodel.Pod{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}

	pod1bModel := &podmodel.Pod{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
		Label: []*podmodel.Pod_Label{
			{
				Key:   "app",
				Value: "test",
			},
		},
	}

	pod2aModel := &podmodel.Pod{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
	}

	pod2bModel := &podmodel.Pod{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
		Label: []*podmodel.Pod_Label{
			{
				Key:   "app",
				Value: "test",
			},
		},
	}

	pod3aModel := &podmodel.Pod{
		Name:      pod3.Name,
		Namespace: pod3.Namespace,
	}

	pod3bModel := &podmodel.Pod{
		Name:      pod3.Name,
		Namespace: pod3.Namespace,
		Label: []*podmodel.Pod_Label{
			{
				Key:   "app",
				Value: "test",
			},
		},
	}

	pc.Init()
	// -> datasync
	datasnc := datasync.NewMockDataSync()

	// Add pods.
	dataChange1 := datasnc.PutEvent(podmodel.Key(pod1.Name, pod1.Namespace), pod1aModel)
	gomega.Expect(pc.Update(dataChange1)).To(gomega.BeNil())
	dataChange2 := datasnc.PutEvent(podmodel.Key(pod2.Name, pod2.Namespace), pod2aModel)
	gomega.Expect(pc.Update(dataChange2)).To(gomega.BeNil())
	dataChange3 := datasnc.PutEvent(podmodel.Key(pod3.Name, pod3.Namespace), pod3aModel)
	gomega.Expect(pc.Update(dataChange3)).To(gomega.BeNil())

	//Update Pods.
	dataChange4 := datasnc.PutEvent(podmodel.Key(pod1.Name, pod1.Namespace), pod1bModel)
	gomega.Expect(pc.Update(dataChange4)).To(gomega.BeNil())
	dataChange5 := datasnc.PutEvent(podmodel.Key(pod2.Name, pod2.Namespace), pod2bModel)
	gomega.Expect(pc.Update(dataChange5)).To(gomega.BeNil())
	dataChange6 := datasnc.PutEvent(podmodel.Key(pod3.Name, pod3.Namespace), pod3bModel)
	gomega.Expect(pc.Update(dataChange6)).To(gomega.BeNil())

	//Delete Pods.
	pc.configuredPods.RegisterPod(podmodel.Key(pod1.Name, pod1.Namespace), pod1bModel)
	pc.configuredPods.RegisterPod(podmodel.Key(pod2.Name, pod2.Namespace), pod2bModel)
	dataChange7 := datasnc.DeleteEvent(podmodel.Key(pod1.Name, pod1.Namespace))
	gomega.Expect(pc.Update(dataChange7)).To(gomega.BeNil())
	dataChange8 := datasnc.DeleteEvent(podmodel.Key(pod2.Name, pod2.Namespace))
	gomega.Expect(pc.Update(dataChange8)).To(gomega.BeNil())

	// Add Namespaces.
	nsChange1 := datasnc.PutEvent(namespace.Key(testdata.Namespace1), testdata.TestNamespace1)
	gomega.Expect(pc.Update(nsChange1)).To(gomega.BeNil())
	nsChange2 := datasnc.PutEvent(namespace.Key(testdata.Namespace2), testdata.TestNamespace2)
	gomega.Expect(pc.Update(nsChange2)).To(gomega.BeNil())

	// Update Namespaces.
	nsChange1 = datasnc.PutEvent(namespace.Key(testdata.Namespace1), testdata.TestNamespace1b)
	gomega.Expect(pc.Update(nsChange1)).To(gomega.BeNil())
	nsChange2 = datasnc.PutEvent(namespace.Key(testdata.Namespace2), testdata.TestNamespace2b)
	gomega.Expect(pc.Update(nsChange2)).To(gomega.BeNil())
	//Delete Namespaces.
	pc.configuredNamespaces.RegisterNamespace(namespace.Key(testdata.Namespace1), testdata.TestNamespace1)
	pc.configuredNamespaces.RegisterNamespace(namespace.Key(testdata.Namespace2), testdata.TestNamespace2)
	nsChange1 = datasnc.DeleteEvent(namespace.Key(testdata.Namespace1))
	gomega.Expect(pc.Update(nsChange1)).To(gomega.BeNil())
	nsChange2 = datasnc.DeleteEvent(namespace.Key(testdata.Namespace2))
	gomega.Expect(pc.Update(nsChange2)).To(gomega.BeNil())

	// Add Policies.
	policyChange1 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy1.Name, testdata.TestPolicy1.Namespace), testdata.TestPolicy1)
	gomega.Expect(pc.Update(policyChange1)).To(gomega.BeNil())
	policyChange2 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy2.Name, testdata.TestPolicy2.Namespace), testdata.TestPolicy2)
	gomega.Expect(pc.Update(policyChange2)).To(gomega.BeNil())
	policyChange3 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy3.Name, testdata.TestPolicy3.Namespace), testdata.TestPolicy3)
	gomega.Expect(pc.Update(policyChange3)).To(gomega.BeNil())

	//Update Policies.
	policyChange1 = datasnc.PutEvent(policymodel.Key(testdata.TestPolicy1b.Name, testdata.TestPolicy1b.Namespace), testdata.TestPolicy1b)
	gomega.Expect(pc.Update(policyChange1)).To(gomega.BeNil())
	policyChange2 = datasnc.PutEvent(policymodel.Key(testdata.TestPolicy3b.Name, testdata.TestPolicy3b.Namespace), testdata.TestPolicy3b)
	gomega.Expect(pc.Update(policyChange2)).To(gomega.BeNil())

	//Delete Policies
	pc.configuredPolicies.RegisterPolicy(policymodel.Key(testdata.TestPolicy1.Name, testdata.TestPolicy1.Namespace), testdata.TestPolicy1)
	pc.configuredPolicies.RegisterPolicy(policymodel.Key(testdata.TestPolicy2.Name, testdata.TestPolicy2.Namespace), testdata.TestPolicy2)
	policyChange1 = datasnc.DeleteEvent(policymodel.Key(testdata.TestPolicy1.Name, testdata.TestPolicy1.Namespace))
	gomega.Expect(pc.Update(policyChange1)).To(gomega.BeNil())
	policyChange2 = datasnc.DeleteEvent(policymodel.Key(testdata.TestPolicy2.Name, testdata.TestPolicy2.Namespace))
	gomega.Expect(pc.Update(policyChange2)).To(gomega.BeNil())

}

func TestResync(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestResync")

	// Create an instance of PolicyCache
	pc := &PolicyCache{
		Deps: Deps{
			Log: logger,
		},
	}
	pod1 := podmodel.ID{Name: "pod1", Namespace: testdata.Namespace1}
	pod2 := podmodel.ID{Name: "pod2", Namespace: testdata.Namespace2}
	pod3 := podmodel.ID{Name: "pod3", Namespace: testdata.Namespace1}

	pod1aModel := &podmodel.Pod{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}

	pod2aModel := &podmodel.Pod{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
	}

	pod3aModel := &podmodel.Pod{
		Name:      pod3.Name,
		Namespace: pod3.Namespace,
	}

	pc.Init()
	// -> datasync
	datasnc := datasync.NewMockDataSync()

	dataChange1 := datasnc.PutEvent(podmodel.Key(pod1.Name, pod1.Namespace), pod1aModel)
	gomega.Expect(pc.Update(dataChange1)).To(gomega.BeNil())
	dataChange2 := datasnc.PutEvent(podmodel.Key(pod2.Name, pod2.Namespace), pod2aModel)
	gomega.Expect(pc.Update(dataChange2)).To(gomega.BeNil())
	dataChange3 := datasnc.PutEvent(podmodel.Key(pod3.Name, pod3.Namespace), pod3aModel)
	gomega.Expect(pc.Update(dataChange3)).To(gomega.BeNil())

	nsChange1 := datasnc.PutEvent(namespace.Key(testdata.Namespace1), testdata.TestNamespace1)
	gomega.Expect(pc.Update(nsChange1)).To(gomega.BeNil())
	nsChange2 := datasnc.PutEvent(namespace.Key(testdata.Namespace2), testdata.TestNamespace2)
	gomega.Expect(pc.Update(nsChange2)).To(gomega.BeNil())

	policyChange1 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy1.Name, testdata.TestPolicy1.Namespace), testdata.TestPolicy1)
	gomega.Expect(pc.Update(policyChange1)).To(gomega.BeNil())
	policyChange2 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy2.Name, testdata.TestPolicy2.Namespace), testdata.TestPolicy2)
	gomega.Expect(pc.Update(policyChange2)).To(gomega.BeNil())
	policyChange3 := datasnc.PutEvent(policymodel.Key(testdata.TestPolicy3.Name, testdata.TestPolicy3.Namespace), testdata.TestPolicy3)
	gomega.Expect(pc.Update(policyChange3)).To(gomega.BeNil())

	keyPrefixes := []string{policymodel.KeyPrefix(), namespace.KeyPrefix(), podmodel.KeyPrefix()}
	resyncEv, _ := datasnc.ResyncEvent(keyPrefixes...)
	gomega.Expect(pc.Resync(resyncEv.KubeState)).To(gomega.BeNil())
}
