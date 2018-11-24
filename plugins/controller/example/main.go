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
	"fmt"
	"log"

	//"github.com/go-errors/errors"

	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/db/keyval/bolt"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/ligato/vpp-agent/plugins/kvscheduler"

	plugin "github.com/contiv/vpp/plugins/controller"
	"github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ksr"
)

/*
	This example is a demonstration for Contiv-Controller plugin.
*/

func main() {
	// disable status check for etcd - Controller monitors its status now
	etcd.DefaultPlugin.StatusCheck = nil

	ksrServicelabel := servicelabel.NewPlugin(servicelabel.UseLabel(ksr.MicroserviceLabel))
	ksrServicelabel.SetName("ksrServiceLabel")

	watcher := &datasync.KVProtoWatchers{local.Get()}
	kvscheduler.DefaultPlugin.Watcher = watcher

	controller := plugin.NewPlugin(plugin.UseDeps(func(deps *plugin.Deps) {
		deps.LocalDB = &bolt.DefaultPlugin
		deps.RemoteDB = &etcd.DefaultPlugin
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
	Controller *plugin.Controller
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

var totalHandlers int

// ExampleEventHandler is a mock event handler.
type ExampleEventHandler struct {
	name          string
	id            int
	updateCounter int
}

// NewExampleEventHandler is the constructor for ExampleEventHandler.
func NewExampleEventHandler(name string) api.EventHandler {
	totalHandlers++
	return &ExampleEventHandler{name: name, id: totalHandlers - 1}
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
	fmt.Printf("Handler '%s' received Resync no. %d for event '%s'\n", h.String(), resyncCount, event.GetName())
	return nil
}

// Update is called by Controller to handle event that can be reacted to by
// an incremental change.
// <changeDescription> should be human-readable description of changes that
// have to be performed (via txn or internally) - can be empty.
func (h *ExampleEventHandler) Update(event api.Event, txn api.UpdateOperations) (changeDescription string, err error) {
	fmt.Printf("Handler '%s' received Update for event '%s'\n", h.String(), event.GetName())
	h.updateCounter++
	/*
		if h.updateCounter % totalHandlers == h.id  {
			err := errors.New("Update has failed")
			return "", err
		}
	*/
	txn.Delete("random-key")
	return fmt.Sprintf("handler %s has changed nothing", h.String()), nil
}

// Revert is called to revert already executed internal changes (in the plugin
// itself, not in VPP/Linux network stack) for a RevertOnFailure event that
// has failed in the processing.
func (h *ExampleEventHandler) Revert(event api.Event) error {
	fmt.Printf("Handler '%s' received Revert for event '%s'\n", h.String(), event.GetName())
	return nil
}
