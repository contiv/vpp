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
	"crypto/md5"
	"encoding/hex"
	"net"
	"sort"
	"strconv"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/ligato/cn-infra/logging"
)

// SessionRuleCache implements SessionRuleCacheAPI.
type SessionRuleCache struct {
	Deps

	config map[uint32]NamespaceConfig // namespace index -> namespace config
	tables *SessionTables

	dumpClbk  func() ([]*SessionRule, error)
	tagPrefix string
}

// Deps lists dependencies of SessionRuleCache.
type Deps struct {
	Log logging.Logger
}

// SessionRuleCacheTxn represents a single transaction of SessionRuleCache.
type SessionRuleCacheTxn struct {
	cache  *SessionRuleCache
	resync bool

	config         map[uint32]NamespaceConfig
	tables         *SessionTables
	upToDateTables bool
}

// SessionRuleList is an ordered array of Session rules.
// API:
//  Insert(rule)
//  Remove(idx)
//  Diff(ruleList) -> (added, removed []*SessionRule)
// Use NewSessionRuleList() to initialize a new list.
type SessionRuleList struct {
	numItems int /* actual number of rules, the rest are nils */
	rules    []*SessionRule
}

// NamespaceConfig stores both ingress and egress rules associated with a VPP
// session namespace.
type NamespaceConfig struct {
	ipAddr  *net.IPNet
	ingress []*renderer.ContivRule
	egress  []*renderer.ContivRule
}

// SessionTables groups content
type SessionTables struct {
	global *SessionRuleList
	local  map[uint32]*SessionRuleList // namespace index -> rules
}

// Ports is a set of port numbers.
type Ports map[uint16]struct{}

// AnyPort is a constant that represents any port.
const AnyPort uint16 = 0

// NewSessionRuleList is a constructor for SessionRuleList.
func NewSessionRuleList() *SessionRuleList {
	list := &SessionRuleList{}
	list.numItems = 0
	list.rules = []*SessionRule{}
	return list
}

// NewSessionTables is a constructor for SessionTables.
func NewSessionTables() *SessionTables {
	tables := &SessionTables{}
	tables.global = NewSessionRuleList()
	tables.local = make(map[uint32]*SessionRuleList)
	return tables
}

// NewPorts is a constructor for Ports.
func NewPorts(portNums ...uint16) Ports {
	ports := make(Ports)
	for _, portNum := range portNums {
		ports.Add(portNum)
	}
	return ports
}

// Init initializes the SessionRule Cache.
// <dumpClbk> is a callback that the cache will use to dump currently
// installed session rules in VPP.
func (src *SessionRuleCache) Init(dumpClbk func() ([]*SessionRule, error), tagPrefix string) error {
	src.config = make(map[uint32]NamespaceConfig)
	src.dumpClbk = dumpClbk
	src.tagPrefix = tagPrefix
	src.tables = NewSessionTables()
	return nil
}

// NewTxn starts a new transaction. The changes are reflected in the cache
// only after Commit() is called.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one, otherwise namespaces not mentioned
// in the transaction are left unchanged.
func (src *SessionRuleCache) NewTxn(resync bool) Txn {
	txn := &SessionRuleCacheTxn{
		cache:          src,
		resync:         resync,
		config:         make(map[uint32]NamespaceConfig),
		tables:         NewSessionTables(),
		upToDateTables: false,
	}
	if !resync {
		// copy config
		for nsIndex, nsConfig := range src.config {
			txn.config[nsIndex] = nsConfig
		}
	}
	return txn
}

// LookupByNamespace returns rules assigned to a given namespace.
func (src *SessionRuleCache) LookupByNamespace(nsIndex uint32) (ingress, egress []*renderer.ContivRule) {
	nsConfig, exists := src.config[nsIndex]
	if !exists {
		return nil, nil
	}
	return nsConfig.ingress, nsConfig.egress
}

// AllNamespaces returns set of indexes of all known VPP session namespaces
// (already updated configuration).
func (src *SessionRuleCache) AllNamespaces() (namespaces []uint32) {
	for nsIndex := range src.config {
		namespaces = append(namespaces, nsIndex)
	}
	return namespaces
}

// Update changes the list of rules for a given session namespace.
// The change is applied into the cache during commit.
// Run Changes() before Commit() to learn the set of pending updates (merged
// to minimal diff).
func (srct *SessionRuleCacheTxn) Update(nsIndex uint32, ipAddr *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) {
	srct.cache.Log.WithFields(logging.Fields{
		"nsIndex": nsIndex,
		"ipAddr":  ipAddr,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("SessionRuleCacheTxn Update()")

	srct.config[nsIndex] = NamespaceConfig{ipAddr: ipAddr, ingress: ingress, egress: egress}
	srct.upToDateTables = false
}

// Changes calculates a minimalistic set of changes prepared in the
// transaction up to this point.
// Must be run before Commit().
func (srct *SessionRuleCacheTxn) Changes() (added, removed []*SessionRule, err error) {
	if !srct.upToDateTables {
		srct.refreshTables()
	}
	if srct.resync {
		// Handle RESYNC
		// First, get currently installed tables.
		currentRules, err := srct.cache.dumpClbk()
		if err != nil {
			return nil, nil, err
		}
		currentTables := NewSessionTables()
		for _, rule := range currentRules {
			if rule.Scope == RuleScopeLocal {
				_, hasNs := currentTables.local[rule.AppnsIndex]
				if !hasNs {
					currentTables.local[rule.AppnsIndex] = NewSessionRuleList()
				}
				currentTables.local[rule.AppnsIndex].Insert(rule)
			} else {
				currentTables.global.Insert(rule)
			}
		}
		// Add rules automatically installed by VPP that could have been
		// but were not overwritten by the filtering rules.
		for nsIndex := range currentTables.local {
			hasAllTCP := false
			hasAllUDP := false
			for i := 0; i < currentTables.local[nsIndex].numItems; i++ {
				rule := currentTables.local[nsIndex].rules[i]
				if rule.RmtPlen == 0 && rule.RmtPort == 0 {
					if rule.TransportProto == RuleProtoTCP {
						hasAllTCP = true
					} else {
						hasAllUDP = true
					}
				}
			}
			if !hasAllTCP {
				currentTables.local[nsIndex].Insert(defaultDoNothingRule(nsIndex, RuleProtoTCP))
			}
			if !hasAllUDP {
				currentTables.local[nsIndex].Insert(defaultDoNothingRule(nsIndex, RuleProtoUDP))
			}
		}
		// Compare currently installed tables with those from the transaction.
		added, removed = srct.tables.Diff(currentTables)
	} else {
		// Handle config change.
		added, removed = srct.tables.Diff(srct.cache.tables)
	}

	srct.cache.Log.WithFields(logging.Fields{
		"added":   added,
		"removed": removed,
	}).Debug("SessionRuleCacheTxn Changes()")
	return added, removed, nil
}

// Commit applies the changes into the underlying cache.
func (srct *SessionRuleCacheTxn) Commit() {
	srct.cache.config = srct.config
	if !srct.upToDateTables {
		srct.refreshTables()
	}
	srct.cache.tables = srct.tables
}

// refreshTables re-calculates the session tables to implement the Contiv rules
// from the transaction.
func (srct *SessionRuleCacheTxn) refreshTables() {
	// Global table
	srct.tables.global = NewSessionRuleList()
	for nsIndex, nsConfig := range srct.config {
		egressRules := convertEgressRules(nsIndex, nsConfig.ipAddr, nsConfig.egress, srct.cache.tagPrefix)
		srct.tables.global.Insert(egressRules...)
	}
	// Local tables = ingress + combined with egress for intra-host filtering
	for nsIndex := range srct.config {
		srct.tables.local[nsIndex] = NewSessionRuleList()
	}
	for nsIndex := range srct.config {
		ingress := srct.getCombinedIngressRules(nsIndex)
		ingressRules := convertIngressRules(nsIndex, ingress, srct.cache.tagPrefix)
		srct.tables.local[nsIndex].Insert(ingressRules...)
	}
	srct.upToDateTables = true
}

// getCombinedIngressRules returns ingress rules for a given namespace combined
// with restrictions imposed by egress rules of all namespaces on this host.
func (srct *SessionRuleCacheTxn) getCombinedIngressRules(nsIndex uint32) []*renderer.ContivRule {
	nsConfig := srct.config[nsIndex]
	srcIP := nsConfig.ipAddr

	// make copy of ingress rules
	rules := []*renderer.ContivRule{}
	for _, contivRule := range nsConfig.ingress {
		rules = append(rules, contivRule)
	}

	// This implementation assumes there is either no deny rule or only the default
	// deny-the-rest for both UDP and TCP.
	hasDeny := false
	for _, contivRule := range rules {
		if contivRule.Action == renderer.ActionDeny {
			hasDeny = true
			break
		}
	}

	// traverse egress rules of every other namespace on this host
	for rmtNsIndex, rmtNsConfig := range srct.config {
		if rmtNsIndex == nsIndex {
			continue
		}

		// first test if anything is blocked on the egress side
		rmtHasDeny := false
		for _, rmtContivRule := range rmtNsConfig.egress {
			if rmtContivRule.Action == renderer.ActionDeny {
				rmtHasDeny = true
				break
			}
		}
		if !rmtHasDeny {
			continue /* no egress blocking */
		}

		// determine which ports nsIndex can access in rmtNsIndex wrt. egress policies
		egTCP, egUDP := getAllowedEgressPorts(srcIP, rmtNsConfig.egress)
		// determine which ports nsIndex can access in rmtNsIndex wrt. ingress policies
		inTCP := NewPorts(AnyPort)
		inUDP := NewPorts(AnyPort)
		if hasDeny {
			inTCP, inUDP = getAllowedIngressPorts(rmtNsConfig.ipAddr, nsConfig.ingress)
		}

		// Intersect TCP ports
		if !inTCP.IsSubsetOf(egTCP) {
			allowedTCP := inTCP.Intersection(egTCP) /* intersection is certainly not AnyPort */

			// cleanup TCP rule subtree with the root node:
			// 	lclIP 0/0 lclPort 0 -> rmtIP rmtNsConfig.ipAddr/32(or 128) rmtPort 0
			filtered := []*renderer.ContivRule{}
			for _, contivRule := range rules {
				if contivRule.Protocol != renderer.TCP || len(contivRule.DestNetwork.IP) == 0 {
					filtered = append(filtered, contivRule)
					continue
				}
				ones, bits := contivRule.DestNetwork.Mask.Size()
				if ones != bits || !contivRule.DestNetwork.IP.Equal(rmtNsConfig.ipAddr.IP) {
					filtered = append(filtered, contivRule)
					continue
				}
			}
			rules = filtered

			// Add explicit rule for each allowed port from the intersection
			// of ingress with egress.
			for tcpPort := range allowedTCP {
				ruleID := strconv.Itoa(int(nsIndex)) + "-combined-" + strconv.Itoa(int(rmtNsIndex))
				ruleID += "-TCP:" + strconv.Itoa(int(tcpPort))
				newRule := &renderer.ContivRule{
					ID:          ruleID,
					Action:      renderer.ActionPermit,
					SrcNetwork:  &net.IPNet{},
					DestNetwork: rmtNsConfig.ipAddr,
					SrcPort:     AnyPort,
					DestPort:    tcpPort,
					Protocol:    renderer.TCP,
				}
				rules = append(rules, newRule)
			}

			// Add the "deny-the-rest" rule.
			ruleID := strconv.Itoa(int(nsIndex)) + "-combined-" + strconv.Itoa(int(rmtNsIndex)) + "-TCP:NONE"
			newRule := &renderer.ContivRule{
				ID:          ruleID,
				Action:      renderer.ActionDeny,
				SrcNetwork:  &net.IPNet{},
				DestNetwork: rmtNsConfig.ipAddr,
				SrcPort:     AnyPort,
				DestPort:    AnyPort,
				Protocol:    renderer.TCP,
			}
			rules = append(rules, newRule)
		}

		if !inUDP.IsSubsetOf(egUDP) {
			allowedUDP := inUDP.Intersection(egUDP) /* intersection is certainly not AnyPort */

			// cleanup UDP rule subtree with the root node:
			// 	lclIP 0/0 lclPort 0 -> rmtIP rmtNsConfig.ipAddr/32(or 128) rmtPort 0
			filtered := []*renderer.ContivRule{}
			for _, contivRule := range rules {
				if contivRule.Protocol != renderer.UDP || len(contivRule.DestNetwork.IP) == 0 {
					filtered = append(filtered, contivRule)
					continue
				}
				ones, bits := contivRule.DestNetwork.Mask.Size()
				if ones != bits || !contivRule.DestNetwork.IP.Equal(rmtNsConfig.ipAddr.IP) {
					filtered = append(filtered, contivRule)
					continue
				}
			}
			rules = filtered

			// Add explicit rule for each allowed port from the intersection
			// of ingress with egress.
			for udpPort := range allowedUDP {
				ruleID := "combined-" + strconv.Itoa(int(rmtNsIndex)) + "-UDP:" + strconv.Itoa(int(udpPort))
				newRule := &renderer.ContivRule{
					ID:          ruleID,
					Action:      renderer.ActionPermit,
					DestNetwork: rmtNsConfig.ipAddr,
					DestPort:    udpPort,
					Protocol:    renderer.UDP,
				}
				rules = append(rules, newRule)
			}

			// Add the "deny-the-rest" rule.
			ruleID := "combined-" + strconv.Itoa(int(rmtNsIndex)) + "-UDP:NONE"
			newRule := &renderer.ContivRule{
				ID:          ruleID,
				Action:      renderer.ActionDeny,
				DestNetwork: rmtNsConfig.ipAddr,
				Protocol:    renderer.UDP,
			}
			rules = append(rules, newRule)
		}
	}
	return rules
}

func (srl *SessionRuleList) lookupIdxByRule(rule *SessionRule) int {
	return sort.Search(srl.numItems,
		func(i int) bool {
			return rule.Compare(srl.rules[i], false) <= 0
		})
}

// Insert SessionRule(s) into the list.
func (srl *SessionRuleList) Insert(rules ...*SessionRule) bool {
	allIn := true
	for _, rule := range rules {
		if !srl.insert(rule) {
			allIn = false
		}
	}
	return allIn
}

func (srl *SessionRuleList) insert(rule *SessionRule) bool {
	// Insert the rule at the right index to keep the order
	idx := srl.lookupIdxByRule(rule)
	if idx < srl.numItems &&
		rule.Compare(srl.rules[idx], false) == 0 {
		/* already added */
		return false
	}
	if srl.numItems == len(srl.rules) {
		/* just increase the size by one */
		srl.rules = append(srl.rules, nil)
	}
	if idx < srl.numItems {
		// move "bigger" rules to the right
		copy(srl.rules[idx+1:], srl.rules[idx:])
	}
	srl.rules[idx] = rule
	srl.numItems++
	return true
}

// Remove removes rule under a given index from the list.
func (srl *SessionRuleList) Remove(idx int) bool {
	if idx < srl.numItems {
		if idx < srl.numItems-1 {
			// move "bigger" rules to the left
			copy(srl.rules[idx:], srl.rules[idx+1:])
		}
		srl.numItems--
		srl.rules[srl.numItems] = nil
		return true
	}
	return false
}

// Diff returns the difference between this list and <srl2>.
// Added/Removed is from this list point of view.
func (srl *SessionRuleList) Diff(srl2 *SessionRuleList) (added, removed []*SessionRule) {
	added = []*SessionRule{}
	removed = []*SessionRule{}
	idx1 := 0
	idx2 := 0
	for idx1 < srl.numItems || idx2 < srl2.numItems {
		if idx1 < srl.numItems {
			if idx2 < srl2.numItems {
				order := srl.rules[idx1].Compare(srl2.rules[idx2], true)
				switch order {
				case 0:
					idx1++
					idx2++
				case -1:
					added = append(added, srl.rules[idx1])
					idx1++
				case 1:
					removed = append(removed, srl2.rules[idx2])
					idx2++
				}
			} else {
				added = append(added, srl.rules[idx1])
				idx1++
			}
		} else {
			removed = append(removed, srl2.rules[idx2])
			idx2++
		}
	}
	return added, removed
}

// Diff returns the difference between these tables and <st2>.
// Added/Removed is from these tables point of view.
func (st *SessionTables) Diff(st2 *SessionTables) (added, removed []*SessionRule) {
	added, removed = st.global.Diff(st2.global)

	for nsIndex, nsRules := range st.local {
		nsRules2, hasNs := st2.local[nsIndex]
		if hasNs {
			nsAdded, nsRemoved := nsRules.Diff(nsRules2)
			added = append(added, nsAdded...)
			removed = append(removed, nsRemoved...)
		} else {
			nsRules2 = NewSessionRuleList()
			// these rules are installed by VPP by default.
			nsRules2.Insert(defaultDoNothingRule(nsIndex, RuleProtoTCP))
			nsRules2.Insert(defaultDoNothingRule(nsIndex, RuleProtoUDP))
			nsAdded, nsRemoved := nsRules.Diff(nsRules2)
			added = append(added, nsAdded...)
			removed = append(removed, nsRemoved...)
		}
	}
	for nsIndex, nsRules2 := range st2.local {
		if _, hasNs := st.local[nsIndex]; !hasNs {
			nsRules := NewSessionRuleList()
			// these rules are installed by VPP by default.
			nsRules.Insert(defaultDoNothingRule(nsIndex, RuleProtoTCP))
			nsRules.Insert(defaultDoNothingRule(nsIndex, RuleProtoUDP))
			nsAdded, nsRemoved := nsRules.Diff(nsRules2)
			added = append(added, nsAdded...)
			removed = append(removed, nsRemoved...)
		}
	}
	return added, removed
}

// Add port number into the set
func (p Ports) Add(port uint16) {
	p[port] = struct{}{}
}

// Has returns true if the given port is in the set.
func (p Ports) Has(port uint16) bool {
	return p.HasExplicit(0) || p.HasExplicit(port)
}

// HasExplicit returns true if the given port is in the set regardless of AnyPort
// presence.
func (p Ports) HasExplicit(port uint16) bool {
	_, has := p[port]
	return has
}

// IsSubsetOf returns true if this set is a subset of <p2>.
func (p Ports) IsSubsetOf(p2 Ports) bool {
	if p2.Has(AnyPort) {
		return true
	}
	if p.Has(AnyPort) {
		return false
	}
	for port := range p {
		if !p2.Has(port) {
			return false
		}
	}
	return true
}

// Intersection returns the set of ports which are both in this set and in <p2>.
func (p Ports) Intersection(p2 Ports) Ports {
	if p.Has(AnyPort) {
		return p2
	}
	if p2.Has(AnyPort) {
		return p
	}
	intersection := NewPorts()
	for port := range p {
		if p2.Has(port) {
			intersection.Add(port)
		}
	}
	return intersection
}

// getAllowedEgressPorts returns allowed destination UDP and TCP ports for a given
// source pod IP wrt. egress rules.
func getAllowedEgressPorts(srcIP *net.IPNet, egress []*renderer.ContivRule) (tcp, udp Ports) {
	tcp = NewPorts()
	udp = NewPorts()
	for _, rule := range egress {
		if rule.Action == renderer.ActionDeny {
			continue
		}
		if len(rule.SrcNetwork.IP) > 0 && !rule.SrcNetwork.Contains(srcIP.IP) {
			continue
		}
		/* matching ALLOW rule */
		if rule.Protocol == renderer.TCP {
			tcp.Add(rule.DestPort)
		} else {
			udp.Add(rule.DestPort)
		}
	}
	return tcp, udp
}

// getAllowedIngressPorts returns allowed destination UDP and TCP ports for a given
// destination pod IP wrt. ingress rules.
func getAllowedIngressPorts(dstIP *net.IPNet, ingress []*renderer.ContivRule) (tcp, udp Ports) {
	tcp = NewPorts()
	udp = NewPorts()
	for _, rule := range ingress {
		if rule.Action == renderer.ActionDeny {
			continue
		}
		if len(rule.DestNetwork.IP) > 0 && !rule.DestNetwork.Contains(dstIP.IP) {
			continue
		}
		/* matching ALLOW rule */
		if rule.Protocol == renderer.TCP {
			tcp.Add(rule.DestPort)
		} else {
			udp.Add(rule.DestPort)
		}
	}
	return tcp, udp
}

// convertEgressRules constructs egress session rules for a given namespace
// to be installed into the global table.
func convertEgressRules(nsIndex uint32, ipAddr *net.IPNet, egress []*renderer.ContivRule, tagPrefix string) []*SessionRule {
	// Construct egress Session rules.
	sessionRules := []*SessionRule{}
	for _, rule := range egress {
		sessionRule := &SessionRule{}
		// Transport Protocol
		switch rule.Protocol {
		case renderer.TCP:
			sessionRule.TransportProto = RuleProtoTCP
		case renderer.UDP:
			sessionRule.TransportProto = RuleProtoUDP
		default:
			sessionRule.TransportProto = RuleProtoTCP
		}
		// Is IPv4
		if len(rule.SrcNetwork.IP) != 0 {
			if rule.SrcNetwork.IP.To4() != nil {
				sessionRule.IsIP4 = 1
			}
		} else {
			if ipAddr.IP.To4() != nil {
				sessionRule.IsIP4 = 1
			}
		}
		// Local IP
		if ipAddr.IP.To4() != nil {
			copy(sessionRule.LclIP[:], ipAddr.IP.To4())
		} else {
			copy(sessionRule.LclIP[:], ipAddr.IP.To16())
		}
		lclPlen, _ := ipAddr.Mask.Size()
		sessionRule.LclPlen = uint8(lclPlen)
		// Local port
		sessionRule.LclPort = rule.DestPort
		// Remote IP
		if len(rule.SrcNetwork.IP) > 0 {
			if rule.SrcNetwork.IP.To4() != nil {
				copy(sessionRule.RmtIP[:], rule.SrcNetwork.IP.To4())
			} else {
				copy(sessionRule.RmtIP[:], rule.SrcNetwork.IP.To16())
			}
			rmtPlen, _ := rule.SrcNetwork.Mask.Size()
			sessionRule.RmtPlen = uint8(rmtPlen)
		}
		// Remote port
		sessionRule.RmtPort = rule.SrcPort /* it is any */
		// Action Index
		if rule.Action == renderer.ActionPermit {
			// Action
			sessionRule.ActionIndex = RuleActionAllow
		} else {
			// Action
			sessionRule.ActionIndex = RuleActionDeny
		}
		// Application namespace index
		sessionRule.AppnsIndex = 0
		// Scope
		sessionRule.Scope = RuleScopeGlobal
		// Tag
		ruleID := getMD5Hash(strconv.Itoa(int(nsIndex)) + "-egress-" + rule.ID)
		copy(sessionRule.Tag[:], tagPrefix+ruleID)
		// Add rule into the list.
		sessionRules = append(sessionRules, sessionRule)
	}
	return sessionRules
}

// convertIngressRules constructs ingress session rules for a given namespace
// to be installed into the local table.
func convertIngressRules(nsIndex uint32, ingress []*renderer.ContivRule, tagPrefix string) []*SessionRule {
	hasAllTCP := false
	hasAllUDP := false
	// Construct ingress Session rules.
	sessionRules := []*SessionRule{}
	for _, rule := range ingress {
		// is this rule for all dst IP and ports?
		if len(rule.DestNetwork.IP) == 0 && rule.DestPort == 0 {
			if rule.Protocol == renderer.TCP {
				hasAllTCP = true
			} else {
				hasAllUDP = true
			}
		}
		sessionRule := &SessionRule{}
		// Transport Protocol
		switch rule.Protocol {
		case renderer.TCP:
			sessionRule.TransportProto = RuleProtoTCP
		case renderer.UDP:
			sessionRule.TransportProto = RuleProtoUDP
		default:
			sessionRule.TransportProto = RuleProtoTCP
		}
		// Is IPv4
		if len(rule.DestNetwork.IP) != 0 {
			if rule.DestNetwork.IP.To4() != nil {
				sessionRule.IsIP4 = 1
			}
		} else {
			sessionRule.IsIP4 = 1
		}
		// Local IP = 0/0
		// Local port
		sessionRule.LclPort = rule.SrcPort /* it is any */
		// Remote IP
		if len(rule.DestNetwork.IP) > 0 {
			if rule.DestNetwork.IP.To4() != nil {
				copy(sessionRule.RmtIP[:], rule.DestNetwork.IP.To4())
			} else {
				copy(sessionRule.RmtIP[:], rule.DestNetwork.IP.To16())
			}
			rmtPlen, _ := rule.DestNetwork.Mask.Size()
			sessionRule.RmtPlen = uint8(rmtPlen)
		}
		// Remote port
		sessionRule.RmtPort = rule.DestPort
		// Action Index
		if rule.Action == renderer.ActionPermit {
			// Action
			sessionRule.ActionIndex = RuleActionAllow
		} else {
			// Action
			sessionRule.ActionIndex = RuleActionDeny
		}
		// Application namespace index
		sessionRule.AppnsIndex = nsIndex
		// Scope
		sessionRule.Scope = RuleScopeLocal
		// Tag
		ruleID := getMD5Hash(strconv.Itoa(int(nsIndex)) + "-ingress-" + rule.ID)
		copy(sessionRule.Tag[:], tagPrefix+ruleID)
		// Add rule into the list.
		sessionRules = append(sessionRules, sessionRule)
	}
	if !hasAllTCP {
		// Add rule "0/0 0 0/0 0 TCP -1" normally installed by VPP and needed
		// for non-filtered traffic transfer.
		sessionRules = append(sessionRules, defaultDoNothingRule(nsIndex, RuleProtoTCP))
	}
	if !hasAllUDP {
		// Add rule "0/0 0 0/0 0 UDP -1" normally installed by VPP and needed for
		// non-filtered traffic transfer.
		sessionRules = append(sessionRules, defaultDoNothingRule(nsIndex, RuleProtoUDP))
	}
	return sessionRules
}

// This is the only rule installed automatically by VPP that may be overwritten
// by the agent for traffic filtering.
func defaultDoNothingRule(nsIndex uint32, protocol uint8) *SessionRule {
	sessionRule := &SessionRule{}
	sessionRule.TransportProto = protocol
	sessionRule.ActionIndex = RuleActionDoNothing
	sessionRule.AppnsIndex = nsIndex
	sessionRule.Scope = RuleScopeLocal
	sessionRule.IsIP4 = uint8(1)
	return sessionRule
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
