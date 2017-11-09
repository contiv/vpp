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
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"

	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
)

// Renderer renders Contiv Rules into VPP ACLs.
// ACLs are installed into VPP by the aclplugin from vpp-agent.
// The configuration changes are transported into aclplugin via localclient.
type Renderer struct {
	Deps
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log                 logging.Logger
	Cache               cache.ContivRuleCacheAPI
	ACLTxnFactory       func() (dsl linux.DataChangeDSL)
	ACLResyncTxnFactory func() (dsl linux.DataResyncDSL)
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	cacheTxn cache.Txn
	renderer *Renderer
	resync   bool
}

// Init initializes the ACL Renderer.
func (r *Renderer) Init() error {
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. Rollback is not yet supported however.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one. Otherwise, the change is performed incrementally,
// i.e. interfaces not mentioned in the transaction are left unaffected.
func (r *Renderer) NewTxn(resync bool) renderer.Txn {
	return &RendererTxn{cacheTxn: r.Cache.NewTxn(resync), renderer: r, resync: resync}
}

// Render applies the set of ingress & egress rules for a given VPP interface.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(ifName string, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) renderer.Txn {
	art.renderer.Log.WithFields(logging.Fields{
		"ifName":  ifName,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("ACL RendererTxn Render()")
	art.cacheTxn.Update(ifName, ingress, egress)
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied as one transaction via the
// localclient.
func (art *RendererTxn) Commit() error {
	ingress, egress := art.cacheTxn.Changes()
	ingress = art.filterEmpty(ingress)
	egress = art.filterEmpty(egress)

	if len(ingress) == 0 && len(egress) == 0 {
		art.renderer.Log.Debug("No changes to be rendered in a transaction")
		return nil
	}

	if art.resync == true {
		dsl := art.renderer.ACLResyncTxnFactory()

		art.renderResync(dsl, ingress, true)
		art.renderResync(dsl, egress, false)

		err := dsl.Send().ReceiveReply()
		if err != nil {
			return err
		}
	} else {
		dsl := art.renderer.ACLTxnFactory()
		putDsl := dsl.Put()
		deleteDsl := dsl.Delete()

		art.renderChanges(putDsl, deleteDsl, ingress, true)
		art.renderChanges(putDsl, deleteDsl, egress, false)

		err := dsl.Send().ReceiveReply()
		if err != nil {
			return err
		}
	}

	art.cacheTxn.Commit()
	return nil
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

// render RESYNC event with Contiv Rules into the equivalent RESYNC event for
// ACL configuration.
func (art *RendererTxn) renderResync(dsl linux.DataResyncDSL, changes []*cache.TxnChange, ingress bool) {
	for _, change := range changes {
		acl := art.renderACL(change.List, ingress)
		dsl.ACL(acl)
		art.renderer.Log.WithFields(logging.Fields{
			"list": change.List,
			"acl":  acl,
		}).Debug("Resync ACL")
	}
}

// renderInterfaces renders ContivRuleList into the equivalent ACL configuration.
func (art *RendererTxn) renderACL(ruleList *cache.ContivRuleList, ingress bool) *vpp_acl.AccessLists_Acl {
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
			aclRule.Actions.AclAction = vpp_acl.AclAction_PERMIT
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
			aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort = uint32(65535)
			aclRule.Matches.IpRule.Tcp.DestinationPortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{}
			aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
			aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
		} else {
			aclRule.Matches.IpRule.Udp = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{}
			aclRule.Matches.IpRule.Udp.SourcePortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_SourcePortRange{}
			aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort = uint32(rule.SrcPort)
			aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort = uint32(65535)
			aclRule.Matches.IpRule.Udp.DestinationPortRange = &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{}
			aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
			aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
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
