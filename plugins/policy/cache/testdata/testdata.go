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

package testdata

import (
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

const (
	namespace1 = "ns1"
	namespace2 = "ns2"
)

var (
	PodIDs = []string{
		namespace1 + "/pod1",
		namespace1 + "/pod2",
		namespace2 + "/pod3",
		namespace2 + "/pod4",
		namespace1 + "/pod5",
		namespace1 + "/pod6",
	}

	// aliases
	Pod1 = PodIDs[0]
	Pod2 = PodIDs[1]
	Pod3 = PodIDs[2]
	Pod4 = PodIDs[3]
	Pod5 = PodIDs[4]
	Pod6 = PodIDs[5]

	NamespaceIDs = []string{
		namespace1,
		namespace2,
	}

	// aliases
	Namespace1 = NamespaceIDs[0]
	Namespace2 = NamespaceIDs[1]

	PolicyIDs = []string{
		namespace1 + "/deny-all-traffic",
		namespace1 + "/api-allow",
		namespace1 + "/web-allow-all",
		namespace1 + "/default-deny-all",
	}

	// aliases
	Policy1 = PolicyIDs[0]
	Policy2 = PolicyIDs[1]
	Policy3 = PolicyIDs[2]
	Policy4 = PolicyIDs[3]
)

var PodOne = &podmodel.Pod{
	Name:      "pod1",
	Namespace: namespace1,
	Label: []*podmodel.Pod_Label{
		{
			Key:   "role",
			Value: "db",
		},
		{
			Key:   "app",
			Value: "datastore",
		},
	},
}

var PodTwo = &podmodel.Pod{
	Name:      "pod2",
	Namespace: namespace1,
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

var PodThree = &podmodel.Pod{
	Name:      "pod3",
	Namespace: namespace2,
	Label: []*podmodel.Pod_Label{
		{
			Key:   "app",
			Value: "datastore",
		},
		{
			Key:   "role",
			Value: "frontend",
		},
	},
}

var PodFour = &podmodel.Pod{
	Name:      "pod4",
	Namespace: namespace2,
	Label: []*podmodel.Pod_Label{
		{
			Key:   "role",
			Value: "db",
		},
	},
}

var PodFive = &podmodel.Pod{
	Name:      "pod5",
	Namespace: namespace1,
	Label:     []*podmodel.Pod_Label{},
}

var PodSix = &podmodel.Pod{
	Name:      "pod6",
	Namespace: namespace1,
	Label: []*podmodel.Pod_Label{
		{
			Key:   "app1",
			Value: "random1",
		},
		{
			Key:   "app2",
			Value: "random2",
		},
	},
}

var TestNamespace1 = &nsmodel.Namespace{
	Name: namespace1,
}

var TestNamespace2 = &nsmodel.Namespace{
	Name: "ns2",
	Label: []*nsmodel.Namespace_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test2",
		},
	},
}

var TestNamespace1b = &nsmodel.Namespace{
	Name: namespace1,
	Label: []*nsmodel.Namespace_Label{
		{
			Key:   "app",
			Value: "test1",
		},
	},
}

var TestNamespace2b = &nsmodel.Namespace{
	Name: "ns2",
	Label: []*nsmodel.Namespace_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test3",
		},
	},
}

var TestPolicy1 = &policy.Policy{
	Name:      "deny-all-traffic",
	Namespace: namespace1,
	Pods: &policy.Policy_LabelSelector{
		MatchLabel: []*policy.Policy_Label{
			{
				Key:   "role",
				Value: "db",
			},
		},
	},
	PolicyType:  0,
	IngressRule: []*policy.Policy_IngressRule{},
	EgressRule:  nil,
}

var TestPolicy1b = &policy.Policy{
	Name:      "deny-all-traffic",
	Namespace: namespace1,
	Pods: &policy.Policy_LabelSelector{
		MatchLabel: []*policy.Policy_Label{
			{
				Key:   "role",
				Value: "new",
			},
		},
	},
	PolicyType:  0,
	IngressRule: []*policy.Policy_IngressRule{},
	EgressRule:  nil,
}

var TestPolicy2 = &policy.Policy{
	Name:      "api-allow",
	Namespace: namespace1,
	Pods: &policy.Policy_LabelSelector{
		MatchLabel: []*policy.Policy_Label{
			{
				Key:   "role",
				Value: "db",
			},
			{
				Key:   "role",
				Value: "frontend",
			},
		},
	},
	PolicyType: 1,
	IngressRule: []*policy.Policy_IngressRule{
		{
			From: []*policy.Policy_Peer{
				{
					Pods: &policy.Policy_LabelSelector{
						MatchLabel: []*policy.Policy_Label{
							{
								Key:   "role",
								Value: "db",
							},
						},
					},
				},
			},
		},
	},
	EgressRule: nil,
}

var TestPolicy3 = &policy.Policy{
	Name:      "web-allow-all",
	Namespace: namespace1,
	Pods: &policy.Policy_LabelSelector{
		MatchLabel: []*policy.Policy_Label{
			{
				Key:   "role",
				Value: "db",
			},
		},
	},
	PolicyType:  1,
	IngressRule: []*policy.Policy_IngressRule{},
	EgressRule:  nil,
}

var TestPolicy3b = &policy.Policy{
	Name:      "web-allow-all",
	Namespace: namespace1,
	Pods: &policy.Policy_LabelSelector{
		MatchLabel: []*policy.Policy_Label{
			{
				Key:   "role",
				Value: "new",
			},
		},
	},
	PolicyType:  1,
	IngressRule: []*policy.Policy_IngressRule{},
	EgressRule:  nil,
}

var TestPolicy4 = &policy.Policy{
	Name:       "default-deny-all",
	Namespace:  namespace1,
	Pods:       &policy.Policy_LabelSelector{},
	PolicyType: 0,
}

var (
	TestExpression0 = []*policy.Policy_LabelSelector_LabelExpression{}

	TestExpression1 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}

	TestExpression2 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}

	TestExpression3 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "random",
			Operator: policy.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}

	TestExpression4 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "random",
			Operator: policy.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}

	TestExpression5 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"db"},
		},
	}
	TestExpression6 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"db"},
		},
	}

	TestExpression7 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"random"},
		},
	}

	TestExpression8 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
	}

	TestExpression9 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
	}

	TestExpression10 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
		{
			Key:      "app",
			Operator: policy.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"datastore"},
		},
	}

	TestExpression11 = []*policy.Policy_LabelSelector_LabelExpression{
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_NOT_IN,
			Value:    []string{"random"},
		},
		{
			Key:      "role",
			Operator: policy.Policy_LabelSelector_LabelExpression_EXISTS,
			Value:    nil,
		},
		{
			Key:      "app",
			Operator: policy.Policy_LabelSelector_LabelExpression_IN,
			Value:    []string{"datastore"},
		},
		{
			Key:      "random",
			Operator: policy.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST,
			Value:    nil,
		},
	}
)

var (
	TestLabel0 = []*policy.Policy_Label{}

	TestLabel1 = []*policy.Policy_Label{
		{
			Key:   "role",
			Value: "db",
		},
	}

	TestLabel2 = []*policy.Policy_Label{
		{
			Key:   "role",
			Value: "random",
		},
		{
			Key:   "app",
			Value: "datastore",
		},
	}

	TestLabel3 = []*policy.Policy_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test2",
		},
	}

	TestLabel4 = []*policy.Policy_Label{
		{
			Key:   "app",
			Value: "test1",
		},
		{
			Key:   "app",
			Value: "test3",
		},
	}

	TestLabel5 = []*policy.Policy_Label{
		{
			Key:   "app",
			Value: "test1",
		},
	}

	TestLabel6 = []*policy.Policy_Label{
		{
			Key:   "app",
			Value: "datastore",
		},
	}
)

var (
	CombinationLabel0 = &policy.Policy_LabelSelector{
		MatchLabel:      []*policy.Policy_Label{},
		MatchExpression: []*policy.Policy_LabelSelector_LabelExpression{},
	}

	CombinationLabel1 = &policy.Policy_LabelSelector{
		MatchLabel:      TestLabel1,
		MatchExpression: TestExpression4,
	}

	CombinationLabel2 = &policy.Policy_LabelSelector{
		MatchLabel:      TestLabel6,
		MatchExpression: TestExpression11,
	}

	CombinationLabel3 = &policy.Policy_LabelSelector{
		MatchLabel:      TestLabel6,
		MatchExpression: TestExpression10,
	}

	CombinationLabel4 = &policy.Policy_LabelSelector{
		MatchLabel:      TestLabel6,
		MatchExpression: TestExpression9,
	}

	CombinationLabel5 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel0,
	}
	CombinationLabel6 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel1,
	}
	CombinationLabel7 = &policy.Policy_LabelSelector{
		MatchLabel:      TestLabel2,
		MatchExpression: TestExpression5,
	}
	CombinationLabel8 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel3,
	}
	CombinationLabel9 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel4,
	}
	CombinationLabel10 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel5,
	}

	CombinationLabel11 = &policy.Policy_LabelSelector{
		MatchLabel: TestLabel5,
	}

	CombinationLabel12 = &policy.Policy_LabelSelector{
		MatchExpression: TestExpression6,
	}

	CombinationLabel13 = &policy.Policy_LabelSelector{
		MatchExpression: TestExpression2,
	}
)
