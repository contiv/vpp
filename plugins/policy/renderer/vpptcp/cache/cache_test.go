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
	"net"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/onsi/gomega"
)

func ipNetwork(addr string) (ip net.IP, maskLen uint8) {
	if addr == "" {
		return net.IP{}, 0
	}
	_, network, error := net.ParseCIDR(addr)
	maskSize, _ := network.Mask.Size()
	gomega.Expect(error).To(gomega.BeNil())
	return network.IP, uint8(maskSize)
}

func checkSessionRules(list []*SessionRule, rules ...*SessionRule) {
	gomega.Expect(len(list)).To(gomega.BeEquivalentTo(len(rules)))

	for _, rule := range rules {
		found := false
		for _, rule2 := range list {
			if rule.Compare(rule2) == 0 {
				found = true
				break
			}
		}
		gomega.Expect(found).To(gomega.BeTrue())
	}
}

func checkNamespaces(cache *SessionRuleCache, namespaces ...int) {
	allNs := cache.AllNamespaces()
	gomega.Expect(len(allNs)).To(gomega.BeEquivalentTo(len(namespaces)))

	for _, ns := range namespaces {
		found := false
		for _, ns2 := range allNs {
			if ns == int(ns2) {
				found = true
				break
			}
		}
		gomega.Expect(found).To(gomega.BeTrue())
	}
}

func TestSingleIngressRuleSingleNs(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleIngressRuleSingleNs")

	// Prepare input data.
	lclIP, lclPlen := ipNetwork("192.168.1.0/24")
	rule := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		LclIP:          lclIP,
		LclPlen:        lclPlen,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeGlobal,
		Tag:            []byte("test"),
	}
	ingress := NewSessionRuleList(0, rule)
	egress := NewSessionRuleList(0)

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() (SessionRuleList, error) { return NewSessionRuleList(0), nil })
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for one namespace
	txn.Update(10, ingress, egress)
	checkNamespaces(ruleCache) /* not yet commited */
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, rule)
	checkSessionRules(removed)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress, rule)
	checkSessionRules(cacheEgress)
}

func TestSingleEgressRuleSingleNs(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSingleEgressRuleSingleNs")

	// Prepare input data.
	lclIP, lclPlen := ipNetwork("192.168.1.1/32")
	rmtIP, rmtPlen := ipNetwork("192.168.1.1/32")
	rule := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		LclIP:          lclIP,
		LclPlen:        lclPlen,
		RmtIP:          rmtIP,
		RmtPlen:        rmtPlen,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            []byte("test"),
	}
	ingress := NewSessionRuleList(0)
	egress := NewSessionRuleList(0, rule)

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() (SessionRuleList, error) { return NewSessionRuleList(0), nil })
	checkNamespaces(ruleCache)

	// Run single transaction.
	txn := ruleCache.NewTxn(false)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Change config for one namespace
	txn.Update(10, ingress, egress)
	checkNamespaces(ruleCache) /* not yet commited */
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, rule)
	checkSessionRules(removed)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress)
	checkSessionRules(cacheEgress, rule)
}
