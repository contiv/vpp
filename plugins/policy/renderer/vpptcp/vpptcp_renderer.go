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

//go:generate binapi-generator --input-file=/usr/share/vpp/api/session.api.json --output-dir=bin_api

package vpptcp

import (
	"bytes"
	"errors"
	"net"

	govpp "git.fd.io/govpp.git/api"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/bin_api/session"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/cache"
)

// SessionRuleTag is used to tag session rules created for the implementation of
// K8s policies.
const SessionRuleTag = "contiv/vpp-policy"

// Renderer renders Contiv Rules into VPP Session rules.
// Session rules are configured into VPP directly via binary API using govpp.
type Renderer struct {
	Deps

	cache *cache.SessionRuleCache
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log        logging.Logger
	LogFactory logging.LogFactory /* optional */
	Contiv     contiv.API         /* for GetNsIndex() */
	GoVPPChan  *govpp.Channel
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	cacheTxn cache.Txn
	renderer *Renderer
	resync   bool
}

// Init initializes the VPPTCP Renderer.
func (r *Renderer) Init() error {
	// Init the cache
	r.cache = &cache.SessionRuleCache{}
	if r.LogFactory != nil {
		r.cache.Log = r.LogFactory.NewLogger("-vpptcpCache")
	} else {
		r.cache.Log = r.Log
	}
	r.cache.Init(r.dumpRules)
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. Rollback is not yet supported however.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one. Otherwise, the change is performed incrementally,
// i.e. interfaces not mentioned in the transaction are left unaffected.
func (r *Renderer) NewTxn(resync bool) renderer.Txn {
	return &RendererTxn{cacheTxn: r.cache.NewTxn(resync), renderer: r, resync: resync}
}

// dumpRules queries VPP to get the currently installed set of rules.
func (r *Renderer) dumpRules() (cache.SessionRuleList, error) {
	rules := cache.NewSessionRuleList(0)
	// Send request to dump all installed rules.
	req := &session.SessionRulesDump{}
	reqContext := r.GoVPPChan.SendMultiRequest(req)
	// Receive details about each installed rule.
	for {
		msg := &session.SessionRulesDetails{}
		stop, err := reqContext.ReceiveReply(msg)
		if err != nil {
			r.Log.WithField("err", err).Error("Failed to get a session rule details")
			return rules, err
		}
		if stop {
			break
		}
		tagLen := bytes.IndexByte(msg.Tag, 0)
		tag := string(msg.Tag[:tagLen])
		if tag != SessionRuleTag {
			// Skip rules not installed by this renderer.
			continue
		}
		sessionRule := &cache.SessionRule{
			TransportProto: msg.TransportProto,
			IsIP4:          msg.IsIP4,
			LclIP:          msg.LclIP,
			LclPlen:        msg.LclPlen,
			RmtIP:          msg.RmtIP,
			RmtPlen:        msg.RmtPlen,
			LclPort:        msg.LclPort,
			RmtPort:        msg.RmtPort,
			ActionIndex:    msg.ActionIndex,
			AppnsIndex:     msg.AppnsIndex,
			Scope:          msg.Scope,
			Tag:            msg.Tag,
		}
		rules.Insert(sessionRule)
	}

	return rules, nil
}

// makeSessionRuleAddDelReq creates an instance of SessionRuleAddDel bin API
// request.
func (r *Renderer) makeSessionRuleAddDelReq(rule *cache.SessionRule, add bool) *govpp.VppRequest {
	isAdd := uint8(0)
	if add {
		isAdd = uint8(1)
	}
	msg := &session.SessionRuleAddDel{
		TransportProto: rule.TransportProto,
		IsIP4:          rule.IsIP4,
		LclIP:          rule.LclIP,
		LclPlen:        rule.LclPlen,
		RmtIP:          rule.RmtIP,
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		IsAdd:          isAdd,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
		Tag:            rule.Tag,
	}
	req := &govpp.VppRequest{
		Message: msg,
	}
	return req
}

// updateRules adds/removes selected rules to/from VPP Session rule tables.
func (r *Renderer) updateRules(add, remove []*cache.SessionRule) error {
	const errMsg = "failed to update VPPTCP session rule"

	// Prepare VPP requests.
	requests := []*govpp.VppRequest{}
	for _, addRule := range add {
		requests = append(requests, r.makeSessionRuleAddDelReq(addRule, true))
	}
	for _, delRule := range remove {
		requests = append(requests, r.makeSessionRuleAddDelReq(delRule, false))
	}

	// Send all VPP requests at once.
	for _, req := range requests {
		r.GoVPPChan.ReqChan <- req
	}

	// Wait for all VPP responses.
	var wasError error
	for i := 0; i < len(requests); i++ {
		reply := <-r.GoVPPChan.ReplyChan
		if reply.Error != nil {
			r.Log.WithField("err", reply.Error).Error(errMsg)
			wasError = reply.Error
			break
		}
		msg := &session.SessionRuleAddDelReply{}
		err := r.GoVPPChan.MsgDecoder.DecodeMsg(reply.Data, msg)
		if err != nil {
			r.Log.WithField("err", err).Error(errMsg)
			wasError = err
			break
		}
		if msg.Retval != 0 {
			r.Log.WithField("retval", msg.Retval).Error(errMsg)
			wasError = errors.New(errMsg)
			break
		}
	}
	return wasError
}

// Render applies the set of ingress & egress rules for a given pod.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule) renderer.Txn {
	art.renderer.Log.WithFields(logging.Fields{
		"pod":     pod,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("VPPTCP RendererTxn Render()")

	// Get the target namespace index.
	nsIndex, found := art.renderer.Contiv.GetNsIndex(pod.Namespace, pod.Name)
	if !found {
		art.renderer.Log.WithField("pod", pod).Warn("Unable to get the namespace index of the Pod")
		return art
	}

	// Construct ingress rules.
	nsInRules := cache.NewSessionRuleList(len(ingress))
	for _, rule := range ingress {
		sessionRule := &cache.SessionRule{}
		// Transport Protocol
		switch rule.Protocol {
		case renderer.TCP:
			sessionRule.TransportProto = cache.RuleProtoTCP
		case renderer.UDP:
			sessionRule.TransportProto = cache.RuleProtoUDP
		default:
			sessionRule.TransportProto = cache.RuleProtoTCP
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
			sessionRule.RmtIP = rule.DestNetwork.IP
			rmtPlen, _ := rule.DestNetwork.Mask.Size()
			sessionRule.RmtPlen = uint8(rmtPlen)
		}
		// Remote port
		sessionRule.RmtPort = rule.DestPort
		// Action Index
		if rule.Action == renderer.ActionPermit {
			// Action
			sessionRule.ActionIndex = cache.RuleActionAllow
		} else {
			// Action
			sessionRule.ActionIndex = cache.RuleActionDeny
		}
		// Application namespace index
		sessionRule.AppnsIndex = nsIndex
		// Scope
		sessionRule.Scope = cache.RuleScopeLocal
		// Tag
		sessionRule.Tag = []byte(SessionRuleTag)
		// Add rule into the list.
		nsInRules.Insert(sessionRule)
	}

	// Construct egress rules.
	nsEgRules := cache.NewSessionRuleList(len(egress))
	for _, rule := range egress {
		sessionRule := &cache.SessionRule{}
		// Transport Protocol
		switch rule.Protocol {
		case renderer.TCP:
			sessionRule.TransportProto = cache.RuleProtoTCP
		case renderer.UDP:
			sessionRule.TransportProto = cache.RuleProtoUDP
		default:
			sessionRule.TransportProto = cache.RuleProtoTCP
		}
		// Is IPv4
		if len(rule.SrcNetwork.IP) != 0 {
			if rule.SrcNetwork.IP.To4() != nil {
				sessionRule.IsIP4 = 1
			}
		} else {
			if podIP.IP.To4() != nil {
				sessionRule.IsIP4 = 1
			}
		}
		// Local IP
		sessionRule.LclIP = podIP.IP
		lclPlen, _ := podIP.Mask.Size()
		sessionRule.LclPlen = uint8(lclPlen)
		// Local port
		sessionRule.LclPort = rule.DestPort
		// Remote IP
		if len(rule.SrcNetwork.IP) > 0 {
			sessionRule.RmtIP = rule.SrcNetwork.IP
			rmtPlen, _ := rule.SrcNetwork.Mask.Size()
			sessionRule.RmtPlen = uint8(rmtPlen)
		}
		// Remote port
		sessionRule.RmtPort = rule.SrcPort /* it is any */
		// Action Index
		if rule.Action == renderer.ActionPermit {
			// Action
			sessionRule.ActionIndex = cache.RuleActionAllow
		} else {
			// Action
			sessionRule.ActionIndex = cache.RuleActionDeny
		}
		// Application namespace index
		sessionRule.AppnsIndex = nsIndex /* probably irrelevant here */
		// Scope
		sessionRule.Scope = cache.RuleScopeGlobal
		// Tag
		sessionRule.Tag = []byte(SessionRuleTag)
		// Add rule into the list.
		nsEgRules.Insert(sessionRule)
	}

	// Add the rules into the transaction.
	art.cacheTxn.Update(nsIndex, nsInRules, nsEgRules)
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied via binary API using govpp.
func (art *RendererTxn) Commit() error {
	added, removed, err := art.cacheTxn.Changes()
	if err != nil {
		return err
	}
	err = art.renderer.updateRules(added, removed)
	if err != nil {
		return err
	}
	art.cacheTxn.Commit()
	return nil
}
