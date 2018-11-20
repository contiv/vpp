//  Copyright (c) 2018 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"log"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/db/keyval/bolt"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/servicelabel"

	plugin "github.com/contiv/vpp/plugins/controller"
	"github.com/contiv/vpp/plugins/controller/api"

	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/contiv/model/nodeinfo"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"fmt"
)

/*
	This example is a demonstration for Contiv-Controller plugin.
*/

func main() {
	ksrServicelabel := servicelabel.NewPlugin(servicelabel.UseLabel(ksr.MicroserviceLabel))
	ksrServicelabel.SetName("ksrServiceLabel")

	controller := plugin.NewPlugin(plugin.UseDeps(func(deps *plugin.Deps) {
		deps.LocalDB = &bolt.DefaultPlugin
		deps.RemoteDB = &etcd.DefaultPlugin
		deps.DBResources = []api.DBResource{
			{
				Keyword:          nodeinfo.Keyword,
				ProtoMessageName: proto.MessageName((*nodeinfo.NodeInfo)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nodeinfo.AllocatedIDsKeyPrefix,
			},
			{
				Keyword:          nodemodel.NodeKeyword,
				ProtoMessageName: proto.MessageName((*nodemodel.Node)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nodemodel.KeyPrefix(),
			},
			{
				Keyword:          podmodel.PodKeyword,
				ProtoMessageName: proto.MessageName((*podmodel.Pod)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + podmodel.KeyPrefix(),
			},
			{
				Keyword:          nsmodel.NamespaceKeyword,
				ProtoMessageName: proto.MessageName((*nsmodel.Namespace)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nsmodel.KeyPrefix(),
			},
			{
				Keyword:          policymodel.PolicyKeyword,
				ProtoMessageName: proto.MessageName((*policymodel.Policy)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + policymodel.KeyPrefix(),
			},
			{
				Keyword:          svcmodel.ServiceKeyword,
				ProtoMessageName: proto.MessageName((*svcmodel.Service)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + svcmodel.KeyPrefix(),
			},
			{
				Keyword:          epmodel.EndpointsKeyword,
				ProtoMessageName: proto.MessageName((*epmodel.Endpoints)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + epmodel.KeyPrefix(),
			},
		}
		deps.EventHandlers = []api.EventHandler{
			NewExampleEventHandler("handler1"),
			NewExampleEventHandler("handler2"),
			NewExampleEventHandler("handler3"),
		}
	}))

	ep := &ExamplePlugin{
		Controller: controller,
	}

	a := agent.NewAgent(
		agent.AllPlugins(ep),
	)
	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}

// ExamplePlugin is the main plugin in this example.
type ExamplePlugin struct {
	Controller   *plugin.Controller
}

// String returns plugin name
func (p *ExamplePlugin) String() string {
	return "controller-example"
}

// Init handles initialization phase.
func (p *ExamplePlugin) Init() error {
	return nil
}

// Close releases allocated resources.
func (p *ExamplePlugin) Close() error {
	return nil
}

// ExampleEventHandler is a mock event handler.
type ExampleEventHandler struct {
	name string
}

// NewExampleEventHandler is the constructor for ExampleEventHandler.
func NewExampleEventHandler(name string) api.EventHandler {
	return &ExampleEventHandler{name: name}
}

// String identifies the handler for the Controller and in the logs.
// Note: Plugins already implement Stringer.
func (h *ExampleEventHandler) String() string {
	return h.name
}

// HandlesEvent is used by Controller to check if the event is being handled
// by this handler.
func (h *ExampleEventHandler) HandlesEvent(event api.Event) bool {
	return true
}

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (h *ExampleEventHandler) Resync(event api.Event, txn api.ResyncOperations, kubeStateData api.KubeStateData, resyncCount int) error {
	fmt.Printf("Handler %s received Resync no. %d for event %s\n", h.String(), resyncCount, event.GetName())
	return nil
}

// Update is called by Controller to handle event that can be reacted to by
// an incremental change.
// <changeDescription> should be human-readable description of changes that
// have to be performed (via txn or internally) - can be empty.
func (h *ExampleEventHandler) Update(event api.Event, txn api.UpdateOperations) (changeDescription string, err error) {
	fmt.Printf("Handler %s received Update for event %s\n", h.String(), event.GetName())
	return fmt.Sprintf("handler %s has changed nothing", h.String()), nil
}

// Revert is called to revert already executed internal changes (in the plugin
// itself, not in VPP/Linux network stack) for a RevertOnFailure event that
// has failed in the processing.
func (h *ExampleEventHandler) Revert(event api.Event) error {
	fmt.Printf("Handler %s received Revert for event %s\n", h.String(), event.GetName())
	return nil
}