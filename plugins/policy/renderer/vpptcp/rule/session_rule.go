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

package rule

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
	"github.com/contiv/vpp/plugins/policy/utils"
)

const (
	// SessionRuleTagPrefix is used to tag session rules created for the implementation
	// of K8s policies.
	SessionRuleTagPrefix = "contiv/vpp-policy"

	// AnyProtocolSessionRuleTag is used to mark rules used to implement
	// filtering for ANY protocol.
	AnyProtocolSessionRuleTag = "-ANY"

	// SplitSessionRuleTag is used to mark deny-all rules split into two
	// (two halves of the IP address space) in order to avoid collision with
	// the VPP proxy rules.
	SplitSessionRuleTag = "-SPLIT"

	// ScopeGlobal is a constant used to set the global scope for a session rule.
	ScopeGlobal = 1

	// ScopeLocal is a constant used to set the local scope for a session rule.
	ScopeLocal = 2

	// ScopeBoth is a constant used to set both the local and the global scope
	// for a session rule.
	ScopeBoth = 3

	// ActionDoNothing is a constant used to set DO-NOTHING action for a session
	// rule.
	ActionDoNothing = ^uint32(0)

	// ActionDeny is a constant used to set DENY action for a session rule.
	ActionDeny = ^uint32(0) - 1

	// ActionAllow is a constant used to set ALLOW action for a session rule.
	ActionAllow = ^uint32(0) - 2

	// ProtoTCP is a constant used to set TCP protocol for a session rule.
	ProtoTCP = 0

	// ProtoUDP is a constant used to set UDP protocol for a session rule.
	ProtoUDP = 1
)

// SessionRule defines and groups the fields of a VPP session rule.
type SessionRule struct {
	TransportProto uint8
	IsIP4          uint8
	LclIP          [16]byte
	LclPlen        uint8
	RmtIP          [16]byte
	RmtPlen        uint8
	LclPort        uint16
	RmtPort        uint16
	ActionIndex    uint32
	AppnsIndex     uint32
	Scope          uint8
	Tag            [64]byte
}

// IPNet interface lists methods (formerly) provided by IPNet plugin, which
// are needed by VPPTCP Renderer.
type IPNet interface {
	// GetNsIndex returns application namespace related to the given pod.
	GetNsIndex(podNamespace, podName string) (nsIndex uint32, exists bool)
	// GetPodByAppNsIndex returns pod related to the given application namespace.
	GetPodByAppNsIndex(nsIndex uint32) (podNamespace, podName string, exists bool)
}

// Copy creates a deep copy of the Session rule.
func (sr *SessionRule) Copy() *SessionRule {
	srCopy := &SessionRule{}
	*(srCopy) = *sr
	return srCopy
}

// String converts Session Rule into a human-readable string representation.
func (sr *SessionRule) String() string {
	var scope string
	var action string
	var l4Proto string

	switch sr.Scope {
	case 0:
		scope = "global"
	case ScopeGlobal:
		scope = "global"
	case ScopeLocal:
		scope = "local"
	case ScopeBoth:
		scope = "both"
	default:
		scope = "invalid"
	}

	switch sr.ActionIndex {
	case ActionDoNothing:
		action = "do-nothing"
	case ActionAllow:
		action = "allow"
	case ActionDeny:
		action = "deny"
	default:
		action = fmt.Sprintf("fwd->%d", sr.ActionIndex)
	}

	ipBits := net.IPv4len * 8
	if sr.IsIP4 == 0 {
		ipBits = net.IPv6len * 8
	}

	lcl := &net.IPNet{}
	lcl.IP = make([]byte, ipBits/8)
	copy(lcl.IP, sr.LclIP[:])
	lcl.Mask = net.CIDRMask(int(sr.LclPlen), ipBits)

	rmt := &net.IPNet{}
	rmt.IP = make([]byte, ipBits/8)
	copy(rmt.IP, sr.RmtIP[:])
	rmt.Mask = net.CIDRMask(int(sr.RmtPlen), ipBits)

	switch sr.TransportProto {
	case ProtoTCP:
		l4Proto = "TCP"
	case ProtoUDP:
		l4Proto = "UDP"
	default:
		l4Proto = "invalid"
	}

	tagLen := bytes.IndexByte(sr.Tag[:], 0)
	tag := string(sr.Tag[:tagLen])

	return fmt.Sprintf("Rule <ns:%d scope:%s action:%s lcl:%s[%s:%d] rmt:%s:[%s:%d] tag:%s>",
		sr.AppnsIndex, scope, action, lcl.String(), l4Proto, sr.LclPort, rmt.String(), l4Proto,
		sr.RmtPort, tag)
}

// Compare returns -1, 0, 1 if this<sr2 or this==sr2 or this>sr2, respectively.
// Session rules have a total order defined on them.
func (sr *SessionRule) Compare(sr2 *SessionRule, compareTag bool) int {
	nsOrder := utils.CompareInts(int(sr.AppnsIndex), int(sr2.AppnsIndex))
	if nsOrder != 0 {
		return nsOrder
	}
	scopeOrder := utils.CompareInts(int(sr.Scope), int(sr2.Scope))
	if scopeOrder != 0 {
		return scopeOrder
	}
	actionOrder := utils.CompareInts(int(sr.ActionIndex), int(sr2.ActionIndex))
	if actionOrder != 0 {
		return actionOrder
	}
	ipVerOrder := utils.CompareInts(int(sr.IsIP4), int(sr2.IsIP4))
	if ipVerOrder != 0 {
		return ipVerOrder
	}
	lclOrder := utils.CompareIPNetsBytes(sr.LclPlen, sr.LclIP, sr2.LclPlen, sr2.LclIP)
	if lclOrder != 0 {
		return lclOrder
	}
	rmtOrder := utils.CompareIPNetsBytes(sr.RmtPlen, sr.RmtIP, sr2.RmtPlen, sr2.RmtIP)
	if rmtOrder != 0 {
		return rmtOrder
	}
	protocolOrder := utils.CompareInts(int(sr.TransportProto), int(sr2.TransportProto))
	if protocolOrder != 0 {
		return protocolOrder
	}
	lclPortOrder := utils.CompareInts(int(sr.LclPort), int(sr2.LclPort))
	if lclPortOrder != 0 {
		return lclPortOrder
	}
	rmtPortOrder := utils.CompareInts(int(sr.RmtPort), int(sr2.RmtPort))
	if rmtPortOrder != 0 {
		return rmtPortOrder
	}
	if compareTag {
		return bytes.Compare(sr.Tag[:], sr2.Tag[:])
	}
	return 0
}

// ExportSessionRules converts Contiv rules into the corresponding set of session rules.
// Set *podID* to nil if the rules are from the global table.
func ExportSessionRules(rules []*renderer.ContivRule, podID *podmodel.ID, podIP net.IP, ipnet IPNet, log logging.Logger) []*SessionRule {
	global := podID == nil
	// Construct Session rules.
	sessionRules := []*SessionRule{}

	var nsIndex uint32
	if !global {
		// Get the target namespace index.
		var found bool
		nsIndex, found = ipnet.GetNsIndex(podID.Namespace, podID.Name)
		if !found {
			log.WithField("pod", podID).Warn("Unable to get the namespace index of the Pod")
			return sessionRules
		}
	}

	for _, rule := range rules {
		if rule.DestPort == 0 && rule.Action == renderer.ActionPermit &&
			((global && len(rule.SrcNetwork.IP) == 0) || (!global && len(rule.DestNetwork.IP) == 0)) {
			/* do not install allow-all destination rules - it is the default behaviour in the stack */
			continue
		}

		if !global && len(rule.DestNetwork.IP) > 0 {
			ones, bits := rule.DestNetwork.Mask.Size()
			if ones == bits && rule.DestNetwork.IP.Equal(podIP) {
				/* do not install rules that have the same source as destination */
				continue
			}
		}

		if rule.Protocol == renderer.ANY {
			// VPPTCP stack supports only TCP and UDP traffic, no other L4 protocol or pure L3 traffic.
			// Filtering for ANY protocol is thus implemented as two rules - one for TCP, the other for UDP.
			ruleTCP := rule.Copy()
			ruleTCP.Protocol = renderer.TCP
			ruleUDP := rule.Copy()
			ruleUDP.Protocol = renderer.UDP
			sessionRules = append(sessionRules,
				convertContivRule(ruleTCP, global, nsIndex, SessionRuleTagPrefix+AnyProtocolSessionRuleTag)...)
			sessionRules = append(sessionRules,
				convertContivRule(ruleUDP, global, nsIndex, SessionRuleTagPrefix+AnyProtocolSessionRuleTag)...)
		} else {
			sessionRules = append(sessionRules, convertContivRule(rule, global, nsIndex, SessionRuleTagPrefix)...)
		}
	}
	return sessionRules
}

// convertContivRule converts Contiv rule for TCP or UDP into the corresponding set of session rules.
func convertContivRule(rule *renderer.ContivRule, global bool, nsIndex uint32, tagPrefix string) []*SessionRule {
	// Construct Session rules.
	sessionRules := []*SessionRule{}
	sessionRule := &SessionRule{}

	// Transport Protocol
	if rule.Protocol == renderer.TCP {
		sessionRule.TransportProto = ProtoTCP
	} else {
		sessionRule.TransportProto = ProtoUDP
	}

	// Is IPv4?
	if global &&
		(len(rule.SrcNetwork.IP) == 0 || rule.SrcNetwork.IP.To4() != nil) {
		sessionRule.IsIP4 = 1
	}
	if !global &&
		(len(rule.DestNetwork.IP) == 0 || rule.DestNetwork.IP.To4() != nil) {
		sessionRule.IsIP4 = 1
	}

	// Local IP
	if global {
		if sessionRule.IsIP4 == 1 {
			copy(sessionRule.LclIP[:], rule.DestNetwork.IP.To4())
		} else {
			copy(sessionRule.LclIP[:], rule.DestNetwork.IP.To16())
		}
		lclPlen, _ := rule.DestNetwork.Mask.Size()
		sessionRule.LclPlen = uint8(lclPlen)
	} // 0/0 for local tables

	// Local port
	if global {
		sessionRule.LclPort = rule.DestPort
	} else {
		sessionRule.LclPort = rule.SrcPort /* it is any */
	}

	// Remote IP
	rmt := rule.SrcNetwork
	if !global {
		rmt = rule.DestNetwork
	}
	if len(rmt.IP) > 0 {
		if sessionRule.IsIP4 == 1 {
			copy(sessionRule.RmtIP[:], rmt.IP.To4())
		} else {
			copy(sessionRule.RmtIP[:], rmt.IP.To16())
		}
		rmtPlen, _ := rmt.Mask.Size()
		sessionRule.RmtPlen = uint8(rmtPlen)
	}

	// Remote port
	if global {
		sessionRule.RmtPort = rule.SrcPort /* it is any */
	} else {
		sessionRule.RmtPort = rule.DestPort
	}

	// Action Index
	if rule.Action == renderer.ActionPermit {
		sessionRule.ActionIndex = ActionAllow
	} else {
		sessionRule.ActionIndex = ActionDeny
	}

	// Application namespace index
	sessionRule.AppnsIndex = nsIndex

	// Scope
	if global {
		sessionRule.Scope = ScopeGlobal
	} else {
		sessionRule.Scope = ScopeLocal
	}

	if (global && len(rule.SrcNetwork.IP) == 0) || (!global && len(rule.DestNetwork.IP) == 0) {
		// Install deny-all as two rules with the all-IPs subnet split in half
		// to avoid collisions with proxy rules.
		sessionRule.RmtPlen = 1
		sessionRule2 := sessionRule.Copy()
		// 1/1
		copy(sessionRule.Tag[:], tagPrefix+SplitSessionRuleTag)
		sessionRules = append(sessionRules, sessionRule)
		// 1/2
		sessionRule2.RmtIP[0] = 1 << 7
		copy(sessionRule2.Tag[:], tagPrefix+SplitSessionRuleTag)
		sessionRules = append(sessionRules, sessionRule2)
	} else {
		// Tag
		copy(sessionRule.Tag[:], tagPrefix)
		// Add single rule into the list.
		sessionRules = append(sessionRules, sessionRule)
	}
	return sessionRules
}

// ImportSessionRules imports a list of session rules into a newly created
// list of ContivRule tables, suitable for Resync with the cache.
func ImportSessionRules(rules []*SessionRule, ipnet IPNet, log logging.Logger) (tables []*cache.ContivRuleTable) {
	globalTable := cache.NewContivRuleTable(cache.Global)
	localTables := make(map[podmodel.ID]*cache.ContivRuleTable)

	for _, rule := range rules {
		// Export contiv rule.
		contivRule := &renderer.ContivRule{}

		// Tag
		tagLen := bytes.IndexByte(rule.Tag[:], 0)
		tag := string(rule.Tag[:tagLen])
		if strings.HasSuffix(tag, SplitSessionRuleTag) {
			// Merge session rules originally split from a single Contiv rule.
			if rule.RmtIP[0] != 0 {
				continue /* skip this half */
			}
			rule.RmtPlen = 0 /* merge */
			tag = strings.TrimSuffix(tag, SplitSessionRuleTag)
		}

		// Transport Protocol
		if strings.HasSuffix(tag, AnyProtocolSessionRuleTag) {
			// Merge session rules originally split to implement filtering for ANY protocol.
			if rule.TransportProto == ProtoUDP {
				continue /* skip for UDP */
			}
			contivRule.Protocol = renderer.ANY
		} else {
			switch rule.TransportProto {
			case ProtoTCP:
				contivRule.Protocol = renderer.TCP
			case ProtoUDP:
				contivRule.Protocol = renderer.UDP
			default:
				contivRule.Protocol = renderer.TCP
			}
		}

		// Source and destination IP address.
		var srcIP, dstIP [16]byte
		var srcPlen, dstPlen uint8
		var ipLen int
		if rule.Scope == ScopeGlobal {
			srcIP = rule.RmtIP
			srcPlen = rule.RmtPlen
			dstIP = rule.LclIP
			dstPlen = rule.LclPlen
		} else {
			srcIP = rule.LclIP
			srcPlen = rule.LclPlen
			dstIP = rule.RmtIP
			dstPlen = rule.RmtPlen
		}
		if rule.IsIP4 > 0 {
			ipLen = net.IPv4len
		} else {
			ipLen = net.IPv6len
		}
		contivRule.SrcNetwork = &net.IPNet{}
		if srcPlen > 0 {
			contivRule.SrcNetwork.IP = make(net.IP, ipLen)
			copy(contivRule.SrcNetwork.IP, srcIP[:])
			contivRule.SrcNetwork.Mask = net.CIDRMask(int(srcPlen), ipLen*8)
		}
		contivRule.DestNetwork = &net.IPNet{}
		if dstPlen > 0 {
			contivRule.DestNetwork.IP = make(net.IP, ipLen)
			copy(contivRule.DestNetwork.IP, dstIP[:])
			contivRule.DestNetwork.Mask = net.CIDRMask(int(dstPlen), ipLen*8)
		}

		// Source and destination port
		if rule.Scope == ScopeGlobal {
			contivRule.SrcPort = rule.RmtPort
			contivRule.DestPort = rule.LclPort
		} else {
			contivRule.SrcPort = rule.LclPort
			contivRule.DestPort = rule.RmtPort
		}

		// Action Index
		if rule.ActionIndex == ActionAllow {
			contivRule.Action = renderer.ActionPermit
		} else {
			contivRule.Action = renderer.ActionDeny
		}

		// Insert the rule into the corresponding table.
		if rule.Scope == ScopeGlobal {
			globalTable.InsertRule(contivRule)
		} else {
			// Get ID of the pod to which this rule is associated.
			podNamespace, podName, exists := ipnet.GetPodByAppNsIndex(rule.AppnsIndex)
			if !exists {
				log.WithField("rule", rule).Warn("Failed to get pod corresponding to NS index from the session rule")
				continue
			}
			podID := podmodel.ID{Name: podName, Namespace: podNamespace}
			if _, hasTable := localTables[podID]; !hasTable {
				localTables[podID] = cache.NewContivRuleTable(cache.Local)
				localTables[podID].Pods.Add(podID)
			}
			localTables[podID].InsertRule(contivRule)
		}
	}

	tables = append(tables, globalTable)
	for _, localTable := range localTables {
		tables = append(tables, localTable)
	}
	return tables
}
