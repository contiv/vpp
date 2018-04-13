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

func TestGetMatchExpressionPods(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestGetMatchExpressionPods")

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

	testExpression0 := []*policymodel.Policy_LabelSelector_LabelExpression{}

	testExpression1 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}
	testExpression2 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}

	testExpression3 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "random",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}

	testExpression4 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "random",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}

	testExpression5 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"db"},
		},
	}
	testExpression6 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"db"},
		},
	}

	testExpression7 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"random"},
		},
	}

	testExpression8 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
	}

	testExpression9 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}

	testExpression10 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
		{
			Key:      "app",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"datastore"},
		},
	}

	testExpression11 := []*policymodel.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
		{
			Key:      "app",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"datastore"},
		},
		{
			Key:      "random",
			Operator: policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}

	expectParam := pc.getMatchExpressionPods(testNamespace, testExpression0)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression1)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression2)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression3)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression4)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression5)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression6)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression7)
	gomega.Expect(expectParam).To(gomega.BeEmpty())

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression8)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression9)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod2))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression10)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))

	expectParam = pc.getMatchExpressionPods(testNamespace, testExpression11)
	gomega.Expect(expectParam).To(gomega.ContainElement(testdata.Pod1))

}
