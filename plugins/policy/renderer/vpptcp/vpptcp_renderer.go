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
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
	vpptcprule "github.com/contiv/vpp/plugins/policy/renderer/vpptcp/rule"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/session"
)

// Renderer renders Contiv Rules into VPP Session rules.
// Session rules are configured into VPP directly via binary API using govpp.
type Renderer struct {
	Deps

	cache *cache.RendererCache
}

// Deps lists dependencies of Renderer.
type Deps struct {
	Log              logging.Logger
	LogFactory       logging.LogFactory /* optional */
	Contiv           contiv.API         /* for GetNsIndex() */
	GoVPPChan        *govpp.Channel
	GoVPPChanBufSize int
}

// RendererTxn represents a single transaction of Renderer.
type RendererTxn struct {
	Log      logging.Logger
	cacheTxn cache.Txn
	renderer *Renderer
	resync   bool
}

// Init initializes the VPPTCP Renderer.
func (r *Renderer) Init() error {
	// Init the cache
	r.cache = &cache.RendererCache{}
	if r.LogFactory != nil {
		r.cache.Log = r.LogFactory.NewLogger("-vpptcpCache")
		r.cache.Log.SetLevel(logging.DebugLevel)
	} else {
		r.cache.Log = r.Log
	}
	r.cache.Init(cache.IngressOrientation)
	return nil
}

// NewTxn starts a new transaction. The rendering executes only after Commit()
// is called. Rollback is not yet supported however.
// If <resync> is enabled, the supplied configuration will completely
// replace the existing one. Otherwise, the change is performed incrementally,
// i.e. interfaces not mentioned in the transaction are left unaffected.
func (r *Renderer) NewTxn(resync bool) renderer.Txn {
	return &RendererTxn{
		Log:      r.Log,
		cacheTxn: r.cache.NewTxn(),
		renderer: r,
		resync:   resync,
	}
}

// Render applies the set of ingress & egress rules for a given pod.
// The existing rules are replaced.
// Te actual change is performed only after the commit.
func (art *RendererTxn) Render(pod podmodel.ID, podIP *net.IPNet, ingress []*renderer.ContivRule, egress []*renderer.ContivRule, removed bool) renderer.Txn {
	art.renderer.Log.WithFields(logging.Fields{
		"pod":     pod,
		"ingress": ingress,
		"egress":  egress,
	}).Debug("VPPTCP RendererTxn Render()")

	// Add the rules into the transaction.
	art.cacheTxn.Update(pod, &cache.PodConfig{PodIP: podIP, Ingress: ingress, Egress: egress, Removed: removed})
	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied via binary API using govpp.
func (art *RendererTxn) Commit() error {
	var added, removed []*vpptcprule.SessionRule

	if art.resync {
		// Re-synchronize with VPP first.
		rules, err := art.dumpRules()
		if err != nil {
			return err
		}
		tables := vpptcprule.ImportSessionRules(rules, art.renderer.Contiv, art.Log)
		err = art.renderer.cache.Resync(tables)
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

	// Get list of added and removed rules in the local tables.
	for pod := range art.cacheTxn.GetUpdatedPods() {
		var newContivRules, removedContivRules []*renderer.ContivRule

		// -> get pod configuration
		podCfg := art.cacheTxn.GetPodConfig(pod)
		if podCfg.Removed {
			podCfg = art.renderer.cache.GetPodConfig(pod)
			if podCfg == nil {
				// removed pod which does not exist
				continue
			}
		}

		// -> compare the original and the new local table
		origLocalTable := art.renderer.cache.GetLocalTableByPod(pod)
		newLocalTable := art.cacheTxn.GetLocalTableByPod(pod)
		if origLocalTable == nil && newLocalTable != nil {
			// newly assigned local table
			newContivRules = newLocalTable.Rules[:newLocalTable.NumOfRules]
		}
		if origLocalTable != nil && newLocalTable == nil {
			// removed local table
			removedContivRules = origLocalTable.Rules[:origLocalTable.NumOfRules]
		}
		if origLocalTable != nil && newLocalTable != nil && origLocalTable.ID != newLocalTable.ID {
			// changed table
			removedContivRules, newContivRules = origLocalTable.DiffRules(newLocalTable)
		}

		// -> export new session rules
		newSessionRules := vpptcprule.ExportSessionRules(
			newContivRules, &pod, podCfg.PodIP.IP, art.renderer.Contiv, art.Log)
		added = append(added, newSessionRules...)

		// -> export removed session rules.
		removedSessionRules := vpptcprule.ExportSessionRules(
			removedContivRules, &pod, podCfg.PodIP.IP, art.renderer.Contiv, art.Log)
		removed = append(removed, removedSessionRules...)
	}

	// Get list of added and removed rules in the global table.
	origGlobalTable := art.renderer.cache.GetGlobalTable()
	newGlobalTable := art.cacheTxn.GetGlobalTable()
	removedContivRules, newContivRules := origGlobalTable.DiffRules(newGlobalTable)
	newSessionRules := vpptcprule.ExportSessionRules(newContivRules, nil, nil, art.renderer.Contiv, art.Log)
	added = append(added, newSessionRules...)
	removedSessionRules := vpptcprule.ExportSessionRules(removedContivRules, nil, nil, art.renderer.Contiv, art.Log)
	removed = append(removed, removedSessionRules...)

	if len(added) == 0 && len(removed) == 0 {
		art.renderer.Log.Debug("No changes to be rendered in the transaction")
	} else {
		err := art.renderer.updateRules(added, removed)
		if err != nil {
			return err
		}
	}

	return art.cacheTxn.Commit()
}

// dumpRules queries VPP to get the currently installed set of session rules.
func (art *RendererTxn) dumpRules() (rules []*vpptcprule.SessionRule, err error) {
	// Send request to dump all installed rules.
	req := &session.SessionRulesDump{}
	reqContext := art.renderer.GoVPPChan.SendMultiRequest(req)
	// Receive details about each installed rule.
	for {
		msg := &session.SessionRulesDetails{}
		stop, err := reqContext.ReceiveReply(msg)
		if err != nil {
			art.Log.WithField("err", err).Error("Failed to get a session rule details")
			break
		}
		if stop {
			break
		}
		tagLen := bytes.IndexByte(msg.Tag, 0)
		tag := string(msg.Tag[:tagLen])
		if !strings.HasPrefix(tag, vpptcprule.SessionRuleTagPrefix) {
			// Skip rules not installed by this renderer.
			continue
		}
		// Export session rule from the message.
		sessionRule := &vpptcprule.SessionRule{
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

	art.Log.WithFields(logging.Fields{
		"rules": rules,
	}).Debug("VPPTCP Renderer dumpRules()")
	return rules, nil
}

// makeSessionRuleAddDelReq creates an instance of SessionRuleAddDel bin API
// request.
func (r *Renderer) makeSessionRuleAddDelReq(rule *vpptcprule.SessionRule, add bool) *govpp.VppRequest {
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
func (r *Renderer) updateRules(add, remove []*vpptcprule.SessionRule) error {
	const errMsg = "failed to update VPPTCP session rule"

	// Prepare VPP requests.
	requests := []*govpp.VppRequest{}
	for _, delRule := range remove {
		requests = append(requests, r.makeSessionRuleAddDelReq(delRule, false))
	}
	for _, addRule := range add {
		requests = append(requests, r.makeSessionRuleAddDelReq(addRule, true))
	}

	chanBufSize := 100
	if r.GoVPPChanBufSize != 0 {
		chanBufSize = r.GoVPPChanBufSize
	}

	var wasError error
	for i := 0; i < len(requests); {
		// Send multiple VPP requests at once, but no more than what govpp request
		// reply channels can buffer.
		j := 0
		for ; i+j < len(requests) && j < chanBufSize; j++ {
			r.GoVPPChan.ReqChan <- requests[i+j]
		}
		i += j

		// Wait for VPP responses.
		r.Log.WithField("count", j).Debug("Waiting for a bunch of BIN API responses")
		for ; j > 0; j-- {
			reply := <-r.GoVPPChan.ReplyChan
			r.Log.WithField("reply", reply).Debug("Received BIN API response")
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
		if wasError != nil {
			break
		}
	}

	r.Log.WithField("count", len(requests)).Debug("All BIN API responses were received")
	return wasError
}
