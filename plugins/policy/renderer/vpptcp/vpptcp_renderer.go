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
	"strings"

	govpp "git.fd.io/govpp.git/api"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/bin_api/session"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/cache"
)

// SessionRuleTagPrefix is used to tag session rules created for the implementation
// of K8s policies.
const SessionRuleTagPrefix = "contiv/vpp-policy-"

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
		r.cache.Log.SetLevel(logging.DebugLevel)
	} else {
		r.cache.Log = r.Log
	}
	r.cache.Init(r.dumpRules, SessionRuleTagPrefix)
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
func (r *Renderer) dumpRules() ([]*cache.SessionRule, error) {
	rules := []*cache.SessionRule{}
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
		if !strings.HasPrefix(tag, SessionRuleTagPrefix) {
			// Skip rules not installed by this renderer.
			continue
		}
		sessionRule := &cache.SessionRule{
			TransportProto: msg.TransportProto,
			IsIP4:          msg.IsIP4,
			LclPlen:        msg.LclPlen,
			RmtPlen:        msg.RmtPlen,
			LclPort:        msg.LclPort,
			RmtPort:        msg.RmtPort,
			ActionIndex:    msg.ActionIndex,
			AppnsIndex:     msg.AppnsIndex,
			Scope:          msg.Scope,
		}
		copy(sessionRule.LclIP[:], msg.LclIP)
		copy(sessionRule.RmtIP[:], msg.RmtIP)
		copy(sessionRule.Tag[:], msg.Tag)
		rules = append(rules, sessionRule)
	}

	r.Log.WithFields(logging.Fields{
		"rules": rules,
	}).Debug("VPPTCP Renderer dumpRules()")
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
		LclIP:          rule.LclIP[:],
		LclPlen:        rule.LclPlen,
		RmtIP:          rule.RmtIP[:],
		RmtPlen:        rule.RmtPlen,
		LclPort:        rule.LclPort,
		RmtPort:        rule.RmtPort,
		ActionIndex:    rule.ActionIndex,
		IsAdd:          isAdd,
		AppnsIndex:     rule.AppnsIndex,
		Scope:          rule.Scope,
		Tag:            rule.Tag[:],
	}
	r.Log.WithField("msg:", *msg).Debug("Sending BIN API Request to VPP.")
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
	for _, delRule := range remove {
		requests = append(requests, r.makeSessionRuleAddDelReq(delRule, false))
	}
	for _, addRule := range add {
		requests = append(requests, r.makeSessionRuleAddDelReq(addRule, true))
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
	// Get the target namespace index.
	nsIndex, found := art.renderer.Contiv.GetNsIndex(pod.Namespace, pod.Name)
	if !found {
		art.renderer.Log.WithField("pod", pod).Warn("Unable to get the namespace index of the Pod")
		return art
	}

	art.renderer.Log.WithFields(logging.Fields{
		"pod":     pod,
		"nsIndex": nsIndex,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("VPPTCP RendererTxn Render()")

	// Add the rules into the transaction.
	art.cacheTxn.Update(nsIndex, podIP, ingress, egress)
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied via binary API using govpp.
func (art *RendererTxn) Commit() error {
	added, removed, err := art.cacheTxn.Changes()
	if err != nil {
		return err
	}
	if len(added) == 0 && len(removed) == 0 {
		art.renderer.Log.Debug("No changes to be rendered in the transaction")
		return nil
	}
	err = art.renderer.updateRules(added, removed)
	if err != nil {
		return err
	}
	art.cacheTxn.Commit()
	return nil
}
