// Copyright (c) 2019 Cisco and/or its affiliates.
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

package iptables

import (
	"fmt"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/linux/iptables"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"net"
	"strings"
)

// Renderer renders Contiv Rules into iptables rules.
// The configuration changes are transported into iptables plugin via localclient.
type Renderer struct {
	Deps
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log        logging.Logger
	LogFactory logging.LoggerFactory /* optional */
	PodManager podmanager.API
	UpdateTxn  func() (txn controller.UpdateOperations)
	ResyncTxn  func() (txn controller.ResyncOperations)
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	Log      logging.Logger
	renderer *Renderer
	resync   bool
}

// Init initializes the iptables Renderer.
func (r *Renderer) Init() error {
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
		renderer: r,
		resync:   resync,
	}
	return txn
}

// Render applies the set of ingress & egress rules for a given pod.
// The existing rules are replaced. It adds rendered config for iptables into
// the current transaction.
func (rt *RendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule, removed bool) renderer.Txn {
	rt.renderer.Log.WithFields(logging.Fields{
		"pod":           pod,
		"ingress-count": len(ingress),
		"egress-count":  len(egress),
		"removed":       removed,
	}).Debug("iptables RendererTxn Render()")
	if removed {
		txn := rt.renderer.UpdateTxn()
		// delete both chains - ingress and eagress
		txn.Delete(linux_iptables.RuleChainKey(rt.chainName(pod, true)))
		txn.Delete(linux_iptables.RuleChainKey(rt.chainName(pod, false)))
	} else {
		if rt.resync {
			txn := rt.renderer.ResyncTxn()
			controller.PutAll(txn, rt.renderRuleChains(pod, podIP, ingress, egress))
		} else {
			txn := rt.renderer.UpdateTxn()
			controller.PutAll(txn, rt.renderRuleChains(pod, podIP, ingress, egress))
		}
	}

	return rt
}

// Commit is currently NOOP since the config was added into the event transaction in render phase,
// it will be committed as a part of the event transaction.
func (rt *RendererTxn) Commit() error {
	return nil
}

// renderRuleChains transform set of rules for a given pod into iptables rule
func (rt *RendererTxn) renderRuleChains(podID podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) controller.KeyValuePairs {
	res := make(map[string]proto.Message)

	pod, exists := rt.renderer.PodManager.GetLocalPods()[podID]
	if !exists {
		rt.Log.Warnf("pod %v not found in local pods list", podID)
		return res
	}

	if len(ingress) > 0 {
		c := &linux_iptables.RuleChain{}
		c.Name = rt.chainName(podID, true)
		c.Namespace = &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		}
		c.Protocol = rt.ruleChainProtocolForIP(podIP)
		c.Table = linux_iptables.RuleChain_FILTER
		c.ChainType = linux_iptables.RuleChain_OUTPUT
		for _, i := range ingress {
			c.Rules = append(c.Rules, rt.contivRuleToIPtables(i))
		}
		res[linux_iptables.RuleChainKey(rt.chainName(podID, true))] = c
	}

	if len(egress) > 0 {
		c := &linux_iptables.RuleChain{}
		c.Name = rt.chainName(podID, false)
		c.Namespace = &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		}
		c.Protocol = rt.ruleChainProtocolForIP(podIP)
		c.Table = linux_iptables.RuleChain_FILTER
		c.ChainType = linux_iptables.RuleChain_INPUT
		for _, e := range egress {
			c.Rules = append(c.Rules, rt.contivRuleToIPtables(e))
		}
		res[linux_iptables.RuleChainKey(rt.chainName(podID, false))] = c
	}

	return res
}

// contivRuleToIPtables transforms single ContiveRule to iptables rule
func (rt *RendererTxn) contivRuleToIPtables(rule *renderer.ContivRule) string {
	var parts []string
	// protocol must listed before --dport argument
	parts = append(parts, fmt.Sprintf("-p %v", rt.protocolToStr(rule.Protocol)))

	if rule.SrcNetwork != nil && len(rule.SrcNetwork.IP) > 0 {
		parts = append(parts, fmt.Sprintf("-s %v", rule.SrcNetwork.String()))
	}
	if rule.SrcPort != 0 {
		parts = append(parts, fmt.Sprintf("--sport %v", rule.SrcPort))
	}
	if rule.DestNetwork != nil && len(rule.DestNetwork.IP) > 0 {
		parts = append(parts, fmt.Sprintf("-d %v", rule.DestNetwork.String()))
	}
	if rule.DestPort != 0 {
		parts = append(parts, fmt.Sprintf("--dport %v", rule.DestPort))
	}
	parts = append(parts, fmt.Sprintf("-j %v", rt.actionToStr(rule.Action)))
	return strings.Join(parts, " ")
}

// chainName returns name of the NB chain for a given pod
func (rt *RendererTxn) chainName(pod podmodel.ID, isIngress bool) string {
	name := "rule-"
	if isIngress {
		name += "ingress-"
	} else {
		name += "eagress-"
	}
	name += pod.Namespace + pod.Name
	return name
}

func (rt *RendererTxn) protocolToStr(p renderer.ProtocolType) string {
	if p == renderer.TCP {
		return "tcp"
	}
	if p == renderer.UDP {
		return "udp"
	}
	return "all"
}

func (rt *RendererTxn) actionToStr(a renderer.ActionType) string {
	if a == renderer.ActionPermit {
		return "ACCEPT"
	}
	return "DROP"
}

func (rt *RendererTxn) ruleChainProtocolForIP(ipNet *net.IPNet) linux_iptables.RuleChain_Protocol {
	if strings.Contains(ipNet.String(), ":") {
		return linux_iptables.RuleChain_IPv6
	}
	return linux_iptables.RuleChain_IPv4
}
