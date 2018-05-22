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

	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache/testdata"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
)

func TestGetPodsByNSLabelSelector(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestGetPodsByNSLabelSelector")

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
	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace1, testdata.TestNamespace1)
	pc.configuredNamespaces.RegisterNamespace(testdata.Namespace2, testdata.TestNamespace2)

	testNamespace := "ns1"

	testLabel0 := []*policymodel.Policy_Label{}

	testLabel1 := []*policymodel.Policy_Label{
		{
			Key:   "role",
			Value: "db",
		},
	}

	testLabel2 := []*policymodel.Policy_Label{
		{
			Key:   "role",
			Value: "random",
		},
		{
			Key:   "app",
			Value: "datastore",
		},
	}

	testLabel3 := []*policymodel.Policy_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test2",
		},
	}

	testLabel4 := []*policymodel.Policy_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test3",
		},
	}

	expectParam := pc.getMatchLabelPodsInsideNs(testNamespace, testLabel0)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchLabelPodsInsideNs(testNamespace, testLabel1)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchLabelPodsInsideNs(testNamespace, testLabel2)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getPodsByNsLabelSelector(testLabel0)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getPodsByNsLabelSelector(testLabel3)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod3))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod4))

	expectParam = pc.getPodsByNsLabelSelector(testLabel4)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

}
