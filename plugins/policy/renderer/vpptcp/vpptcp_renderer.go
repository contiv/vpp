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
	"net"

	govpp "git.fd.io/govpp.git/api"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/vpptcp/cache"
)

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
func (r *Renderer) dumpRules() cache.SessionRuleList {
	// TODO
	return nil
}

// updateRules adds/removes selected rules to/from VPP Session rule tables.
func (r *Renderer) updateRules(add, remove []*cache.SessionRule) error {
	// TODO
	return nil
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

	// TODO: construct rules
	var nsInRules cache.SessionRuleList
	var nsEgRules cache.SessionRuleList
	art.cacheTxn.Update(nsIndex, nsInRules, nsEgRules)

	return art
}

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using ContivRuleCache and applied via binary API using govpp.
func (art *RendererTxn) Commit() error {
	added, removed := art.cacheTxn.Changes()
	err := art.renderer.updateRules(added, removed)
	if err != nil {
		return err
	}
	art.cacheTxn.Commit()
	return nil
}
