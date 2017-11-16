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

package acl

import (
	"net"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/acl/cache"
)

// Renderer renders Contiv Rules into VPP ACLs.
// ACLs are installed into VPP by the aclplugin from vpp-agent.
// The configuration changes are transported into aclplugin via localclient.
type Renderer struct {
	Deps

	cache *cache.ContivRuleCache
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log           logging.Logger
	LogFactory    logging.LogFactory /* optional */
	Contiv        contiv.API         /* for GetIfName() */
	VPP           defaultplugins.API /* for DumpACLs() */
	ACLTxnFactory func() (dsl linux.DataChangeDSL)
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	Log      logging.Logger
	cache    cache.ContivRuleCacheAPI
	vpp      defaultplugins.API
	renderer *Renderer
	resync   bool
	config   map[string]*InterfaceConfig // interface name -> config
}

// InterfaceConfig temporarily stores configuration for a single interface
// until a transaction commit is called.
type InterfaceConfig struct {
	ingress []*renderer.ContivRule
	egress  []*renderer.ContivRule
}

// Init initializes the ACL Renderer.
func (r *Renderer) Init() error {
	r.cache = &cache.ContivRuleCache{}
	if r.LogFactory != nil {
		r.cache.Log = r.LogFactory.NewLogger("-aclCache")
	} else {
		r.cache.Log = r.Log
	}
	r.cache.Init()
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. Rollback is not yet supported however.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one. Otherwise, the change is performed incrementally,
// i.e. interfaces not mentioned in the transaction are left unaffected.
func (r *Renderer) NewTxn(resync bool) renderer.Txn {
	txn := &RendererTxn{
		Log:      r.Log,
		cache:    r.cache,
		vpp:      r.VPP,
		renderer: r,
		resync:   resync,
		config:   make(map[string]*InterfaceConfig),
	}
	return txn
}

// Render applies the set of ingress & egress rules for a given VPP interface.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) renderer.Txn {
	art.renderer.Log.WithFields(logging.Fields{
		"pod":     pod,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("ACL RendererTxn Render()")

	// Get the target interface.
	ifName, found := art.renderer.Contiv.GetIfName(pod.Namespace, pod.Name)
	if !found {
		art.renderer.Log.WithField("pod", pod).Warn("Unable to get the interface assigned to the Pod")
		return art
	}

	art.config[ifName] = &InterfaceConfig{ingress: ingress, egress: egress}
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied as one transaction via the
// localclient.
func (art *RendererTxn) Commit() error {
	if art.resync {
		// Re-synchronize with VPP first.
		dumpIngress, dumpEgress := art.dumpVppACLConfig()
		err := art.cache.Resync(dumpIngress, dumpEgress)
		if err != nil {
			return err
		}
	}

	// Prepare a set of updates in a cache transaction.
	txn := art.cache.NewTxn()
	for ifName, config := range art.config {
		err := txn.Update(ifName, config.ingress, config.egress)
		if err != nil {
			return err
		}
	}

	if art.resync {
		// Apply empty config for interfaces not present in the transaction.
		txnInterfaces := txn.AllInterfaces()
		emptyList := []*renderer.ContivRule{}
		for ifName := range art.cache.AllInterfaces() {
			if !txnInterfaces.Has(ifName) {
				txn.Update(ifName, emptyList, emptyList)
			}
		}
	}

	// Get the minimalistic diff to be rendered.
	ingress, egress := txn.Changes()
	ingress = art.filterEmpty(ingress)
	egress = art.filterEmpty(egress)

	if len(ingress) == 0 && len(egress) == 0 {
		art.renderer.Log.Debug("No changes to be rendered in a transaction")
		return nil
	}

	// Render ACLs and propagate changes via localclient.
	dsl := art.renderer.ACLTxnFactory()
	putDsl := dsl.Put()
	deleteDsl := dsl.Delete()

	art.renderChanges(putDsl, deleteDsl, ingress, true)
	art.renderChanges(putDsl, deleteDsl, egress, false)

	err := dsl.Send().ReceiveReply()
	if err != nil {
		return err
	}

	// Save changes into the cache.
	return txn.Commit()
}

// Remove lists with no rules since empty list of rules is equivalent to no ACL.
func (art *RendererTxn) filterEmpty(changes []*cache.TxnChange) []*cache.TxnChange {
	filtered := []*cache.TxnChange{}
	for _, change := range changes {
		if len(change.List.Rules) > 0 {
			filtered = append(filtered, change)
		}
	}
	return filtered
}

// dumpVppACLConfig dumps current ACL config is the format suitable for the resync
// of the cache.
func (art *RendererTxn) dumpVppACLConfig() (ingress, egress []*cache.ContivRuleList) {
	var err error
	ingress = []*cache.ContivRuleList{}
	egress = []*cache.ContivRuleList{}

	// TODO: Use dump from acl-plugin once it is available
	//aclDump := art.vpp.DumpACLs()
	aclDump := []*vpp_acl.AccessLists_Acl{} /* assume empty VPP state for now */
	for _, acl := range aclDump {
		isIngress := true
		ruleList := &cache.ContivRuleList{}
		// ID
		ruleList.ID = acl.AclName
		// Interfaces
		ruleList.Interfaces = make(cache.InterfaceSet)
		if acl.Interfaces == nil {
			// invalid, skip
			art.Log.WithField("aclName", acl.AclName).Warn("Skipping ACL without 'Interfaces'")
			continue
		}
		if len(acl.Interfaces.Ingress) > 0 {
			isIngress = true
			for _, ifName := range acl.Interfaces.Ingress {
				ruleList.Interfaces.Add(ifName)
			}
		} else if len(acl.Interfaces.Egress) > 0 {
			isIngress = false
			for _, ifName := range acl.Interfaces.Egress {
				ruleList.Interfaces.Add(ifName)
			}
		} else {
			// unused, skip
			art.Log.WithField("aclName", acl.AclName).Warn("Skipping ACL without assigned interfaces")
			continue
		}
		// Rules
		ruleList.Rules = []*renderer.ContivRule{}
		for _, aclRule := range acl.Rules {
			rule := &renderer.ContivRule{}
			// Rule ID
			rule.ID = aclRule.RuleName
			// Rule Action
			if aclRule.Actions == nil {
				// invalid, skip
				art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule without 'Actions'")
				continue
			}
			if aclRule.Actions.AclAction == vpp_acl.AclAction_PERMIT {
				rule.Action = renderer.ActionPermit
			} else {
				rule.Action = renderer.ActionDeny
			}
			// Rule IPs
			if aclRule.Matches == nil {
				// invalid, skip
				art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule without 'Matches'")
				continue
			}
			if aclRule.Matches.IpRule == nil {
				// unhandled, skip
				art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL MAC-IP rule")
				continue
			}
			rule.SrcNetwork = &net.IPNet{}
			rule.DestNetwork = &net.IPNet{}
			if aclRule.Matches.IpRule.Ip != nil {
				if aclRule.Matches.IpRule.Ip.SourceNetwork != "" {
					_, rule.SrcNetwork, err = net.ParseCIDR(aclRule.Matches.IpRule.Ip.SourceNetwork)
					if err != nil {
						art.Log.WithField("err", err).Warn("Failed to parse source IP address")
						continue
					}
				}
				if aclRule.Matches.IpRule.Ip.DestinationNetwork != "" {
					_, rule.DestNetwork, err = net.ParseCIDR(aclRule.Matches.IpRule.Ip.DestinationNetwork)
					if err != nil {
						art.Log.WithField("err", err).Warn("Failed to parse destination IP address")
						continue
					}
				}
			}
			// L4
			if aclRule.Matches.IpRule.Icmp != nil || aclRule.Matches.IpRule.Other != nil {
				// unhandled, skip
				art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ICMP/Other ACL rule")
				continue
			}
			if aclRule.Matches.IpRule.Tcp != nil {
				rule.Protocol = renderer.TCP
				if aclRule.Matches.IpRule.Tcp.SourcePortRange != nil {
					if aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort != aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort {
						// unhandled, skip
						art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule with TCP port range")
						continue
					}
					rule.SrcPort = uint16(aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort)
				}
				if aclRule.Matches.IpRule.Tcp.DestinationPortRange != nil {
					if aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort != aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort {
						// unhandled, skip
						art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule with TCP port range")
						continue
					}
					rule.DestPort = uint16(aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort)
				}
			} else {
				rule.Protocol = renderer.UDP
				if aclRule.Matches.IpRule.Udp.SourcePortRange != nil {
					if aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort != aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort {
						// unhandled, skip
						art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule with UDP port range")
						continue
					}
					rule.SrcPort = uint16(aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort)
				}
				if aclRule.Matches.IpRule.Udp.DestinationPortRange != nil {
					if aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort != aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort {
						// unhandled, skip
						art.Log.WithField("ruleName", aclRule.RuleName).Warn("Skipping ACL rule with UDP port range")
						continue
					}
					rule.DestPort = uint16(aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort)
				}
			}
			// Add rule to the list.
			ruleList.Rules = append(ruleList.Rules, rule)
		}
		// Private
		ruleList.Private = acl
		// Add to the list.
		if isIngress {
			ingress = append(ingress, ruleList)
		} else {
			egress = append(egress, ruleList)
		}
	}

	return ingress, egress
}

// render Contiv Rule changes into the equivalent ACL configuration changes.
func (art *RendererTxn) renderChanges(putDsl linux.PutDSL, deleteDsl linux.DeleteDSL, changes []*cache.TxnChange, ingress bool) {
	for _, change := range changes {
		if len(change.PreviousInterfaces) == 0 {
			// New ACL
			acl := art.renderACL(change.List, ingress)
			putDsl.ACL(acl)
			art.renderer.Log.WithFields(logging.Fields{
				"list": change.List,
				"acl":  acl,
			}).Debug("Put new ACL")
		} else if len(change.List.Interfaces) != 0 {
			// Changed interfaces
			acl := change.List.Private.(*vpp_acl.AccessLists_Acl)
			acl.Interfaces = art.renderInterfaces(change.List.Interfaces, ingress)
			putDsl.ACL(acl)
			art.renderer.Log.WithFields(logging.Fields{
				"list":          change.List,
				"oldInterfaces": change.PreviousInterfaces,
				"acl":           acl,
			}).Debug("Put updated ACL")
		} else {
			// Removed ACL
			acl := change.List.Private.(*vpp_acl.AccessLists_Acl)
			deleteDsl.ACL(acl.AclName)
			art.renderer.Log.WithFields(logging.Fields{
				"list": change.List,
				"acl":  acl,
			}).Debug("Removed ACL")
		}
	}
}

// renderInterfaces renders ContivRuleList into the equivalent ACL configuration.
func (art *RendererTxn) renderACL(ruleList *cache.ContivRuleList, ingress bool) *vpp_acl.AccessLists_Acl {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.AccessLists_Acl{}
	acl.AclName = ruleList.ID
	acl.Interfaces = art.renderInterfaces(ruleList.Interfaces, ingress)
	for _, rule := range ruleList.Rules {
		aclRule := &vpp_acl.AccessLists_Acl_Rule{}
		aclRule.RuleName = rule.ID
		aclRule.Actions = &vpp_acl.AccessLists_Acl_Rule_Actions{}
		if rule.Action == renderer.ActionDeny {
			aclRule.Actions.AclAction = vpp_acl.AclAction_DENY
		} else {
			aclRule.Actions.AclAction = vpp_acl.AclAction_REFLECT
		}
		aclRule.Matches = &vpp_acl.AccessLists_Acl_Rule_Matches{}
		aclRule.Matches.IpRule = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{}
		aclRule.Matches.IpRule.Ip = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{}
		if len(rule.SrcNetwork.IP) > 0 {
			aclRule.Matches.IpRule.Ip.SourceNetwork = rule.SrcNetwork.String()
		}
		if len(rule.DestNetwork.IP) > 0 {
			aclRule.Matches.IpRule.Ip.DestinationNetwork = rule.DestNetwork.String()
		}
		if rule.Protocol == renderer.TCP {
			aclRule.Matches.IpRule.Tcp = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{}
			aclRule.Matches.IpRule.Tcp.SourcePortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_SourcePortRange{}
			aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort = uint32(rule.SrcPort)
			if rule.SrcPort == 0 {
				aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort = uint32(maxPortNum)
			} else {
				aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort = uint32(rule.SrcPort)
			}
			aclRule.Matches.IpRule.Tcp.DestinationPortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{}
			aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
			if rule.DestPort == 0 {
				aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(maxPortNum)
			} else {
				aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
			}
		} else {
			aclRule.Matches.IpRule.Udp = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{}
			aclRule.Matches.IpRule.Udp.SourcePortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_SourcePortRange{}
			aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort = uint32(rule.SrcPort)
			if rule.SrcPort == 0 {
				aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort = uint32(maxPortNum)
			} else {
				aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort = uint32(rule.SrcPort)
			}
			aclRule.Matches.IpRule.Udp.DestinationPortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{}
			aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
			if rule.DestPort == 0 {
				aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort = uint32(maxPortNum)
			} else {
				aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
			}
		}
		acl.Rules = append(acl.Rules, aclRule)
	}
	ruleList.Private = acl
	return acl
}

// renderInterfaces renders a set of Interface names into the corresponding
// instance of AccessLists_Acl_Interfaces.
func (art *RendererTxn) renderInterfaces(interfaces cache.InterfaceSet, ingress bool) *vpp_acl.AccessLists_Acl_Interfaces {
	aclIfs := &vpp_acl.AccessLists_Acl_Interfaces{}
	for ifName := range interfaces {
		if ingress {
			aclIfs.Ingress = append(aclIfs.Ingress, ifName)
		} else {
			aclIfs.Egress = append(aclIfs.Egress, ifName)
		}
	}
	return aclIfs
}
