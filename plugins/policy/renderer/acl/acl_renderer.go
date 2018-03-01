/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package acl

import (
	"net"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
)

const (
	// ACLNamePrefix is used to tag ACLs created for the implementation of K8s policies.
	ACLNamePrefix = "contiv/vpp-policy-"

	// ReflectiveACLName is the name of the *reflective* ACL (full name prefixed with
	// ACLNamePrefix). Reflective ACL is used to allow responses of accepted sessions
	// regardless of installed policies on the way back.
	ReflectiveACLName = "REFLECTION"
)

// Renderer renders Contiv Rules into VPP ACLs.
// ACLs are installed into VPP by the aclplugin from vpp-agent.
// The configuration changes are transported into aclplugin via localclient.
type Renderer struct {
	Deps

	cache         *cache.RendererCache
	podInterfaces PodInterfaces
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
	cacheTxn cache.Txn
	vpp      defaultplugins.API
	renderer *Renderer
	resync   bool
}

// PodInterfaces is a map used to remember interface of each (configured) pod.
type PodInterfaces map[podmodel.ID]string

// Init initializes the ACL Renderer.
func (r *Renderer) Init() error {
	r.cache = &cache.RendererCache{}
	if r.LogFactory != nil {
		r.cache.Log = r.LogFactory.NewLogger("-aclCache")
	} else {
		r.cache.Log = r.Log
	}
	r.cache.Init(cache.EgressOrientation)
	r.podInterfaces = make(PodInterfaces)
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
		cacheTxn: r.cache.NewTxn(),
		vpp:      r.VPP,
		renderer: r,
		resync:   resync,
	}
	return txn
}

// Render applies the set of ingress & egress rules for a given pod.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule, removed bool) renderer.Txn {
	art.renderer.Log.WithFields(logging.Fields{
		"pod":     pod,
		"ingress": ingress,
		"egress":  egress,
		"removed": removed,
	}).Debug("ACL RendererTxn Render()")

	art.cacheTxn.Update(pod, &cache.PodConfig{PodIP: podIP, Ingress: ingress, Egress: egress, Removed: removed})
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using RendererCache and applied as one transaction via the
// localclient.
func (art *RendererTxn) Commit() error {
	var globalTable *cache.ContivRuleTable

	if art.resync {
		// Re-synchronize with VPP first.
		aclDump, err := art.dumpVppACLConfig()
		if err != nil {
			return err
		}
		err = art.renderer.cache.Resync(aclDump)
		if err != nil {
			return err
		}
		// Remove pods not present in the transaction.
		txnPods := art.cacheTxn.GetUpdatedPods()
		for pod := range art.renderer.cache.GetAllPods() {
			if !txnPods.Has(pod) {
				art.cacheTxn.Update(pod,
					&cache.PodConfig{
						Removed: true,
					})
			}
		}
	}

	// Get the minimalistic diff to be rendered.
	changes := art.cacheTxn.GetChanges()
	if !art.resync && len(changes) == 0 {
		art.renderer.Log.Debug("No changes to be rendered in the transaction")
		// Still need to commit the configuration updates from the transaction.
		return art.cacheTxn.Commit()
	}

	// Render ACLs and propagate changes via localclient.
	dsl := art.renderer.ACLTxnFactory()
	putDsl := dsl.Put()
	deleteDsl := dsl.Delete()

	// First render local tables.
	for _, change := range changes {
		if change.Table.Type == cache.Global {
			// Reconfigure global table after the local ones.
			globalTable = change.Table
			continue
		}
		if len(change.PreviousPods) == 0 {
			// New ACL
			acl := art.renderACL(change.Table)
			putDsl.ACL(acl)
			art.renderer.Log.WithFields(logging.Fields{
				"table": change.Table,
				"acl":   acl,
			}).Debug("Put new ACL")
		} else if len(change.Table.Pods) != 0 {
			// Changed interfaces
			aclPrivCopy := proto.Clone(change.Table.Private.(*vpp_acl.AccessLists_Acl))
			acl := aclPrivCopy.(*vpp_acl.AccessLists_Acl)
			acl.Interfaces = art.renderInterfaces(change.Table.Pods, false)
			putDsl.ACL(acl)
			art.renderer.Log.WithFields(logging.Fields{
				"table":    change.Table,
				"prevPods": change.PreviousPods,
				"acl":      acl,
			}).Debug("Put updated ACL")
		} else {
			// Removed ACL
			acl := change.Table.Private.(*vpp_acl.AccessLists_Acl)
			deleteDsl.ACL(acl.AclName)
			art.renderer.Log.WithFields(logging.Fields{
				"table": change.Table,
				"acl":   acl,
			}).Debug("Removed ACL")
		}
	}

	if art.resync && globalTable == nil && art.renderer.cache.GetGlobalTable().NumOfRules != 0 {
		// Even if the content of the global table has not changed, resync the interfaces.
		globalTable = art.renderer.cache.GetGlobalTable()
	}

	// Render the global table.
	if globalTable != nil {
		globalACL := art.renderACL(globalTable)
		if globalTable.NumOfRules == 0 {
			// Remove empty global table.
			deleteDsl.ACL(globalACL.AclName)
			art.renderer.Log.WithFields(logging.Fields{
				"table": globalTable,
				"acl":   globalACL,
			}).Debug("Removed Global ACL")
		} else {
			// Update content of the global table.
			globalACL.Interfaces.Egress = art.getNodeOutputInterfaces()
			putDsl.ACL(globalACL)
			art.renderer.Log.WithFields(logging.Fields{
				"table": globalTable,
				"acl":   globalACL,
			}).Debug("Put Global ACL")
		}
	}

	// Render the reflective ACL
	if art.resync || !art.cacheTxn.GetIsolatedPods().Equals(art.renderer.cache.GetIsolatedPods()) {
		reflectiveACL := art.reflectiveACL()
		putDsl.ACL(reflectiveACL)
		art.renderer.Log.WithFields(logging.Fields{
			"acl": reflectiveACL,
		}).Debug("Put Reflective ACL")
	}

	err := dsl.Send().ReceiveReply()
	if err != nil {
		return err
	}

	// Save changes into the cache.
	return art.cacheTxn.Commit()
}

// reflectiveACL returns the configuration of the reflective ACL.
func (art *RendererTxn) reflectiveACL() *vpp_acl.AccessLists_Acl {
	// Prepare table to render the ACL from.
	ruleTCPAny := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	}
	ruleUDPAny := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.UDP,
		SrcPort:     0,
		DestPort:    0,
	}
	table := cache.NewContivRuleTable(ReflectiveACLName)
	table.Rules = []*renderer.ContivRule{ruleTCPAny, ruleUDPAny}
	table.NumOfRules = 2
	table.Pods = art.cacheTxn.GetIsolatedPods()
	// Render the ACL.
	acl := art.renderACL(table)
	acl.Interfaces.Ingress = append(acl.Interfaces.Ingress, art.getNodeOutputInterfaces()...)
	return acl
}

// getNodeOutputInterfaces returns the list of interfaces that connect this K8s node
// with the outside world.
func (art *RendererTxn) getNodeOutputInterfaces() []string {
	interfaces := []string{}
	interfaces = append(interfaces, art.renderer.Contiv.GetHostInterconnectIfName())
	interfaces = append(interfaces, art.renderer.Contiv.GetMainPhysicalIfName())
	interfaces = append(interfaces, art.renderer.Contiv.GetOtherPhysicalIfNames()...)
	vxlanBVI := art.renderer.Contiv.GetVxlanBVIIfName()
	if vxlanBVI != "" {
		interfaces = append(interfaces, vxlanBVI)
	}
	return interfaces
}

// renderACL renders ContivRuleTable into the equivalent ACL configuration.
func (art *RendererTxn) renderACL(table *cache.ContivRuleTable) *vpp_acl.AccessLists_Acl {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.AccessLists_Acl{}
	acl.AclName = ACLNamePrefix + table.ID
	acl.Interfaces = art.renderInterfaces(table.Pods, table.ID == ReflectiveACLName)
	for i := 0; i < table.NumOfRules; i++ {
		rule := table.Rules[i]
		aclRule := &vpp_acl.AccessLists_Acl_Rule{}
		aclRule.Actions = &vpp_acl.AccessLists_Acl_Rule_Actions{}
		if rule.Action == renderer.ActionDeny {
			aclRule.Actions.AclAction = vpp_acl.AclAction_DENY
		} else if table.ID == ReflectiveACLName {
			aclRule.Actions.AclAction = vpp_acl.AclAction_REFLECT
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
	table.Private = acl
	return acl
}

// renderInterfaces renders a set of Interface names into the corresponding
// instance of AccessLists_Acl_Interfaces.
func (art *RendererTxn) renderInterfaces(pods cache.PodSet, ingress bool) *vpp_acl.AccessLists_Acl_Interfaces {
	aclIfs := &vpp_acl.AccessLists_Acl_Interfaces{}
	for podID := range pods {
		// Get the interface associated with the pod.
		ifName, found := art.renderer.podInterfaces[podID] // first query local cache
		if !found {
			ifName, found = art.renderer.Contiv.GetIfName(podID.Namespace, podID.Name) // next query Contiv plugin
			if !found {
				art.renderer.Log.WithField("pod", podID).Warn("Unable to get the interface assigned to the Pod")
				continue
			}
		}
		art.renderer.podInterfaces[podID] = ifName
		if ingress {
			aclIfs.Ingress = append(aclIfs.Ingress, ifName)
		} else {
			aclIfs.Egress = append(aclIfs.Egress, ifName)
		}
	}
	return aclIfs
}

// dumpVppACLConfig dumps current ACL config in the format suitable for the resync
// of the cache.
func (art *RendererTxn) dumpVppACLConfig() (tables []*cache.ContivRuleTable, err error) {
	const maxPortNum = uint32(^uint16(0))
	tables = []*cache.ContivRuleTable{}

	aclDump, err := art.vpp.DumpACL()
	if err != nil {
		return tables, err
	}
	for _, acl := range aclDump {
		if !strings.HasPrefix(acl.AclName, ACLNamePrefix) {
			/* ACL not installed by this plugin */
			continue
		}
		aclName := strings.TrimPrefix(acl.AclName, ACLNamePrefix)

		// Skip the Reflective ACL.
		if aclName == ReflectiveACLName {
			continue
		}

		// Local / Global table
		table := cache.NewContivRuleTable(aclName)

		// Pods
		if table.Type == cache.Local {
			if acl.Interfaces == nil {
				// invalid, skip
				art.Log.WithField("aclName", acl.AclName).Warn("Skipping ACL without 'Interfaces'")
				continue
			}
			if len(acl.Interfaces.Ingress) > 0 {
				// invalid, skip
				art.Log.WithField("aclName", acl.AclName).Warn("Skipping non-reflective ACL assigned to ingress")
				continue
			}
			if len(acl.Interfaces.Egress) > 0 {
				for _, ifName := range acl.Interfaces.Egress {
					podNs, podName, exists := art.renderer.Contiv.GetPodByIf(ifName)
					if !exists {
						continue
					}
					table.Pods.Add(podmodel.ID{Name: podName, Namespace: podNs})
				}
			} else {
				// unused, skip
				art.Log.WithField("aclName", acl.AclName).Warn("Skipping ACL without assigned interfaces")
				continue
			}
		}

		// Rules
		for _, aclRule := range acl.Rules {
			rule := &renderer.ContivRule{}
			// Rule Action
			if aclRule.Actions == nil {
				// invalid, skip
				art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule without 'Actions'")
				continue
			}
			switch aclRule.Actions.AclAction {
			case vpp_acl.AclAction_PERMIT:
				rule.Action = renderer.ActionPermit
			case vpp_acl.AclAction_DENY:
				rule.Action = renderer.ActionDeny
			default:
				art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule with unhandled action 'REFLECT'")
				continue
			}
			// Rule IPs
			if aclRule.Matches == nil {
				// invalid, skip
				art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule without 'Matches'")
				continue
			}
			if aclRule.Matches.IpRule == nil {
				// unhandled, skip
				art.Log.WithField("rule", aclRule).Warn("Skipping ACL MAC-IP rule")
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
				art.Log.WithField("rule", aclRule).Warn("Skipping ICMP/Other ACL rule")
				continue
			}
			if aclRule.Matches.IpRule.Tcp != nil {
				rule.Protocol = renderer.TCP
				if aclRule.Matches.IpRule.Tcp.SourcePortRange != nil {
					if aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort != aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort {
						if aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort != 0 ||
							aclRule.Matches.IpRule.Tcp.SourcePortRange.UpperPort != maxPortNum {
							// unhandled, skip
							art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule with TCP port range")
							continue
						}
					}
					rule.SrcPort = uint16(aclRule.Matches.IpRule.Tcp.SourcePortRange.LowerPort)
				}
				if aclRule.Matches.IpRule.Tcp.DestinationPortRange != nil {
					if aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort != aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort {
						if aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort != 0 ||
							aclRule.Matches.IpRule.Tcp.DestinationPortRange.UpperPort != maxPortNum {
							// unhandled, skip
							art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule with TCP port range")
							continue
						}
					}
					rule.DestPort = uint16(aclRule.Matches.IpRule.Tcp.DestinationPortRange.LowerPort)
				}
			} else {
				rule.Protocol = renderer.UDP
				if aclRule.Matches.IpRule.Udp.SourcePortRange != nil {
					if aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort != aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort {
						if aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort != 0 ||
							aclRule.Matches.IpRule.Udp.SourcePortRange.UpperPort != maxPortNum {
							// unhandled, skip
							art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule with UDP port range")
							continue
						}
					}
					rule.SrcPort = uint16(aclRule.Matches.IpRule.Udp.SourcePortRange.LowerPort)
				}
				if aclRule.Matches.IpRule.Udp.DestinationPortRange != nil {
					if aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort != aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort {
						if aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort != 0 ||
							aclRule.Matches.IpRule.Udp.DestinationPortRange.UpperPort != maxPortNum {
							// unhandled, skip
							art.Log.WithField("rule", aclRule).Warn("Skipping ACL rule with UDP port range")
							continue
						}
					}
					rule.DestPort = uint16(aclRule.Matches.IpRule.Udp.DestinationPortRange.LowerPort)
				}
			}
			// Add rule to the list.
			table.InsertRule(rule)
		}

		// Private
		table.Private = acl

		// Add table to the list of tables.
		tables = append(tables, table)
	}

	return tables, nil
}
