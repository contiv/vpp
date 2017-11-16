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

func ipNetwork(addr string) (ip [16]byte, maskLen uint8) {
	if addr == "" {
		return ip, 0
	}
	_, network, error := net.ParseCIDR(addr)
	maskSize, _ := network.Mask.Size()
	gomega.Expect(error).To(gomega.BeNil())
	if network.IP.To4() != nil {
		copy(ip[:], network.IP.To4())
	} else {
		copy(ip[:], network.IP.To16())
	}
	return ip, uint8(maskSize)
}

func makeTag(tagStr string) [64]byte {
	tag := [64]byte{}
	copy(tag[:], tagStr)
	return tag
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
	rmtIP, rmtPlen := ipNetwork("192.168.1.0/24")
	rule := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP,
		RmtPlen:        rmtPlen,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
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
	rmtIP, rmtPlen := ipNetwork("192.168.2.0/24")
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
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
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

func TestMultipleRulesSingleNsWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesSingleNsWithDataChange")

	// Prepare input data.
	rmtIP1, rmtPlen1 := ipNetwork("192.168.1.0/24")
	inRule1 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP1,
		RmtPlen:        rmtPlen1,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	rmtIP2, rmtPlen2 := ipNetwork("192.168.2.0/24")
	inRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP2,
		RmtPlen:        rmtPlen2,
		LclPort:        22,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	lclIP3, lclPlen3 := ipNetwork("192.168.3.1/32")
	rmtIP3, rmtPlen3 := ipNetwork("10.0.0.0/8")
	egRule1 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP3,
		LclPlen:        lclPlen3,
		RmtIP:          rmtIP3,
		RmtPlen:        rmtPlen3,
		LclPort:        777,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP4, lclPlen4 := ipNetwork("192.168.3.1/32")
	egRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		LclIP:          lclIP4,
		LclPlen:        lclPlen4,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     10,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP5, lclPlen5 := ipNetwork("192.168.3.1/32")
	egRule3 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP5,
		LclPlen:        lclPlen5,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     10,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}

	ingress := NewSessionRuleList(0, inRule1, inRule2)
	egress := NewSessionRuleList(0, egRule1, egRule2, egRule3)

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
	checkSessionRules(added, inRule1, inRule2, egRule1, egRule2, egRule3)
	checkSessionRules(removed)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress, inRule1, inRule2)
	checkSessionRules(cacheEgress, egRule1, egRule2, egRule3)

	// Run second transaction with a config change.
	txn = ruleCache.NewTxn(false)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Updated config.
	inRule3 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          0,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	lclIP6, lclPlen6 := ipNetwork("2001:db8:a0b:12f0::1/128")
	rmtIP6, rmtPlen6 := ipNetwork("2001:0000:6dcd:8c74:76cc:63bf:ac32:6a1/64")
	egRule4 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          0,
		LclIP:          lclIP6,
		LclPlen:        lclPlen6,
		RmtIP:          rmtIP6,
		RmtPlen:        rmtPlen6,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     10,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}

	ingress2 := NewSessionRuleList(0, inRule3)
	egress2 := NewSessionRuleList(0, egRule1, egRule3, egRule4)

	// Change config for one namespace
	txn.Update(10, ingress2, egress2)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, inRule3, egRule4)
	checkSessionRules(removed, inRule1, inRule2, egRule2)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10)

	// Verify cache content.
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress, inRule3)
	checkSessionRules(cacheEgress, egRule1, egRule3, egRule4)
}

func TestMultipleRulesMultipleNsWithDataChange(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultipleNsWithDataChange")

	// Prepare input data.
	rmtIP1, rmtPlen1 := ipNetwork("192.168.1.0/24")
	inRule1 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP1,
		RmtPlen:        rmtPlen1,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	rmtIP2, rmtPlen2 := ipNetwork("192.168.2.0/24")
	inRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP2,
		RmtPlen:        rmtPlen2,
		LclPort:        22,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     15,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	lclIP3, lclPlen3 := ipNetwork("192.168.3.1/32")
	rmtIP3, rmtPlen3 := ipNetwork("10.0.0.0/8")
	egRule1 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP3,
		LclPlen:        lclPlen3,
		RmtIP:          rmtIP3,
		RmtPlen:        rmtPlen3,
		LclPort:        777,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP4, lclPlen4 := ipNetwork("192.168.3.2/32")
	egRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		LclIP:          lclIP4,
		LclPlen:        lclPlen4,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP5, lclPlen5 := ipNetwork("192.168.3.2/32")
	egRule3 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP5,
		LclPlen:        lclPlen5,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}

	ingressNs10 := NewSessionRuleList(0, inRule1)
	egressNs10 := NewSessionRuleList(0, egRule1)

	ingressNs15 := NewSessionRuleList(0, inRule2)
	egressNs15 := NewSessionRuleList(0, egRule2, egRule3)

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

	// Change config for two namespaces
	txn.Update(10, ingressNs10, egressNs10)
	txn.Update(15, ingressNs15, egressNs15)
	checkNamespaces(ruleCache) /* not yet commited */
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, inRule1, inRule2, egRule1, egRule2, egRule3)
	checkSessionRules(removed)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10, 15)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress, inRule1)
	checkSessionRules(cacheEgress, egRule1)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(15)
	checkSessionRules(cacheIngress, inRule2)
	checkSessionRules(cacheEgress, egRule2, egRule3)

	// Run second transaction with a config change.
	txn = ruleCache.NewTxn(false)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	gomega.Expect(removed).To(gomega.BeEmpty())

	// Updated config.
	inRule3 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          0,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     15,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}

	ingressNs10 = NewSessionRuleList(0)
	egressNs10 = NewSessionRuleList(0)

	ingressNs15 = NewSessionRuleList(0, inRule2, inRule3)
	egressNs15 = NewSessionRuleList(0)

	// Change config for both namespaces
	txn.Update(10, ingressNs10, egressNs10)
	txn.Update(15, ingressNs15, egressNs15)
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, inRule3)
	checkSessionRules(removed, inRule1, egRule1, egRule2, egRule3)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10, 15)

	// Verify cache content.
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress)
	checkSessionRules(cacheEgress)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(15)
	checkSessionRules(cacheIngress, inRule2, inRule3)
	checkSessionRules(cacheEgress)
}

func TestMultipleRulesMultipleNsWithResync(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestMultipleRulesMultipleNsWithResync")

	// Prepare input data.
	rmtIP1, rmtPlen1 := ipNetwork("192.168.1.0/24")
	inRule1 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP1,
		RmtPlen:        rmtPlen1,
		LclPort:        80,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     10,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	rmtIP2, rmtPlen2 := ipNetwork("192.168.2.0/24")
	inRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		RmtIP:          rmtIP2,
		RmtPlen:        rmtPlen2,
		LclPort:        22,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     15,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}
	lclIP3, lclPlen3 := ipNetwork("192.168.3.1/32")
	rmtIP3, rmtPlen3 := ipNetwork("10.0.0.0/8")
	egRule1 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP3,
		LclPlen:        lclPlen3,
		RmtIP:          rmtIP3,
		RmtPlen:        rmtPlen3,
		LclPort:        777,
		ActionIndex:    RuleActionAllow,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP4, lclPlen4 := ipNetwork("192.168.3.2/32")
	egRule2 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          1,
		LclIP:          lclIP4,
		LclPlen:        lclPlen4,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}
	lclIP5, lclPlen5 := ipNetwork("192.168.3.2/32")
	egRule3 := &SessionRule{
		TransportProto: RuleProtoUDP,
		IsIP4:          1,
		LclIP:          lclIP5,
		LclPlen:        lclPlen5,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     0,
		Scope:          RuleScopeGlobal,
		Tag:            makeTag("test"),
	}

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() (SessionRuleList, error) {
		return NewSessionRuleList(0, inRule1, inRule2, egRule1, egRule2, egRule3), nil
	})
	checkNamespaces(ruleCache)

	// Run single RESYNC transaction.
	txn := ruleCache.NewTxn(true)
	added, removed, err := txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(added).To(gomega.BeEmpty())
	checkSessionRules(removed, inRule1, inRule2, egRule1, egRule2, egRule3)

	// Prepare new config.
	inRule3 := &SessionRule{
		TransportProto: RuleProtoTCP,
		IsIP4:          0,
		LclPort:        0,
		ActionIndex:    RuleActionDeny,
		AppnsIndex:     15,
		Scope:          RuleScopeLocal,
		Tag:            makeTag("test"),
	}

	ingressNs10 := NewSessionRuleList(0)
	egressNs10 := NewSessionRuleList(0, egRule1)

	ingressNs15 := NewSessionRuleList(0, inRule2, inRule3)
	egressNs15 := NewSessionRuleList(0)

	// Change config for both namespaces
	txn.Update(10, ingressNs10, egressNs10)
	txn.Update(15, ingressNs15, egressNs15)
	checkNamespaces(ruleCache) /* not yet commited */
	added, removed, err = txn.Changes()
	gomega.Expect(err).To(gomega.BeNil())
	checkSessionRules(added, inRule3)
	checkSessionRules(removed, inRule1, egRule2, egRule3)

	// Commit the transaction.
	txn.Commit()
	checkNamespaces(ruleCache, 10, 15)

	// Verify cache content.
	cacheIngress, cacheEgress := ruleCache.LookupByNamespace(10)
	checkSessionRules(cacheIngress)
	checkSessionRules(cacheEgress, egRule1)
	cacheIngress, cacheEgress = ruleCache.LookupByNamespace(15)
	checkSessionRules(cacheIngress, inRule2, inRule3)
	checkSessionRules(cacheEgress)
}
