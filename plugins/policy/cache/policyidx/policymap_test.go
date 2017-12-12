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

package policyidx

import (
	"testing"

	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
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
		policyIDone   = "default/allow-limited-traffic"
		policyIDtwo   = "default/deny-all"
		policyIDthree = "default/allow-egress-only"
		policyIDfour  = "other/deny-all"
	)

	res := idx.ListAll()
	gomega.Expect(res).To(gomega.BeNil())

	idx.RegisterPolicy(policyIDone, nil)
	idx.RegisterPolicy(policyIDtwo, nil)
	idx.RegisterPolicy(policyIDthree, nil)
	idx.RegisterPolicy(policyIDfour, nil)

	found, _ := idx.LookupPolicy(policyIDone)
	gomega.Expect(found).To(gomega.BeTrue())

	found, _ = idx.LookupPolicy(policyIDtwo)
	gomega.Expect(found).To(gomega.BeTrue())

	found, _ = idx.LookupPolicy(policyIDthree)
	gomega.Expect(found).To(gomega.BeTrue())

	found, _ = idx.LookupPolicy(policyIDfour)
	gomega.Expect(found).To(gomega.BeTrue())

	idx.UnregisterPolicy(policyIDone)
	found, _ = idx.LookupPolicy(policyIDone)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPolicy(policyIDtwo)
	found, _ = idx.LookupPolicy(policyIDtwo)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPolicy(policyIDthree)
	found, _ = idx.LookupPolicy(policyIDthree)
	gomega.Expect(found).To(gomega.BeFalse())

	idx.UnregisterPolicy(policyIDfour)
	found, _ = idx.LookupPolicy(policyIDfour)
	gomega.Expect(found).To(gomega.BeFalse())

	// unregistering of non-existing item does nothing
	idx.UnregisterPolicy(policyIDthree)

}

func TestSecondaryIndexLookup(t *testing.T) {
	gomega.RegisterTestingT(t)

	idx := NewConfigIndex(logrus.DefaultLogger(), core.PluginName("Plugin-name"), "title")
	gomega.Expect(idx).NotTo(gomega.BeNil())

	const (
		policyIDone   = "default/allow-limited-traffic"
		policyIDtwo   = "deny-all-traffic"
		policyIDthree = "default/allow-ingress-only"
		policyIDfour  = "other/allow-limited-traffic"
		policyIDfive  = "other/deny-all"
		nsLabelKey1   = "default/role/db"
		nsLabelKey2   = "default/app/webstore"
		nsLabelKey3   = "other/app/webstore"
		labelKey1     = "app/webstore"
		labelKey2     = "role/frontend"
	)

	policyDataOne := &policymodel.Policy{
		Name:      "allow-limited-traffic",
		Namespace: "default",
		Pods: &policymodel.Policy_LabelSelector{
			MatchLabel: []*policymodel.Policy_Label{
				{
					Key:   "role",
					Value: "db",
				},
			},
		},
	}

	policyDataTwo := &policymodel.Policy{
		Name:      "deny-all-traffic",
		Namespace: "default",
		Pods: &policymodel.Policy_LabelSelector{
			MatchLabel: []*policymodel.Policy_Label{
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
	}

	policyDataThree := &policymodel.Policy{
		Name:      "allow-ingress-only",
		Namespace: "default",
		Pods: &policymodel.Policy_LabelSelector{
			MatchLabel: []*policymodel.Policy_Label{
				{
					Key:   "role",
					Value: "db",
				},
				{
					Key:   "app",
					Value: "webstore",
				},
			},
		},
	}

	policyDataFour := &policymodel.Policy{
		Name:      "allow-limited-traffic",
		Namespace: "other",
		Pods: &policymodel.Policy_LabelSelector{
			MatchLabel: []*policymodel.Policy_Label{
				{
					Key:   "role",
					Value: "db",
				},
				{
					Key:   "app",
					Value: "webstore",
				},
			},
		},
	}

	policyDataFive := &policymodel.Policy{
		Name:      "deny-all",
		Namespace: "other",
		Pods: &policymodel.Policy_LabelSelector{
			MatchLabel: []*policymodel.Policy_Label{
				{
					Key:   "role",
					Value: "frontend",
				},
			},
		},
	}

	idx.RegisterPolicy(policyIDone, policyDataOne)
	idx.RegisterPolicy(policyIDtwo, policyDataTwo)
	idx.RegisterPolicy(policyIDthree, policyDataThree)
	idx.RegisterPolicy(policyIDfour, policyDataFour)
	idx.RegisterPolicy(policyIDfive, policyDataFive)

	all := idx.ListAll()
	gomega.Expect(all).To(gomega.ContainElement(policyIDone))
	gomega.Expect(all).To(gomega.ContainElement(policyIDtwo))
	gomega.Expect(all).To(gomega.ContainElement(policyIDthree))
	gomega.Expect(all).To(gomega.ContainElement(policyIDfour))
	gomega.Expect(all).To(gomega.ContainElement(policyIDfive))

	nsLabelMatch := idx.LookupPolicyByNSLabelSelector(nsLabelKey1)
	gomega.Expect(nsLabelMatch).To(gomega.ContainElement(policyIDone))
	gomega.Expect(nsLabelMatch).To(gomega.ContainElement(policyIDtwo))
	gomega.Expect(nsLabelMatch).To(gomega.ContainElement(policyIDthree))

	nsLabelMatch = idx.LookupPolicyByNSLabelSelector(nsLabelKey2)
	gomega.Expect(nsLabelMatch).To(gomega.BeEquivalentTo([]string{policyIDthree}))

	nsLabelMatch = idx.LookupPolicyByNSLabelSelector(nsLabelKey3)
	gomega.Expect(nsLabelMatch).To(gomega.BeEquivalentTo([]string{policyIDfour}))

	labelMatch := idx.LookupPolicyByLabelSelector(labelKey1)
	gomega.Expect(labelMatch).To(gomega.ContainElement(policyIDthree))
	gomega.Expect(labelMatch).To(gomega.ContainElement(policyIDfour))

	labelMatch = idx.LookupPolicyByLabelSelector(labelKey2)
	gomega.Expect(labelMatch).To(gomega.ContainElement(policyIDtwo))
	gomega.Expect(labelMatch).To(gomega.ContainElement(policyIDfive))

}
