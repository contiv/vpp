// Copyright (c) 2018 Cisco and/or its affiliates.
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

package bgpreflector

import (
	"sync"

	"github.com/ligato/cn-infra/infra"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
)

// BGPReflector plugin implements IP address allocation for Contiv.
type BGPReflector struct {
	Deps

	mutex sync.RWMutex
}

// Deps lists dependencies of the BGPReflector plugin.
type Deps struct {
	infra.PluginDeps
	ContivConf contivconf.API
	EventLoop  controller.EventLoop
}

// Init is NOOP - the plugin is initialized during the first resync.
func (br *BGPReflector) Init() (err error) {
	return nil
}

// HandlesEvent selects:
//   - any Resync event
func (br *BGPReflector) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}

	// unhandled event
	return false
}

// Resync resynchronizes BGPReflector against the configuration and Kubernetes state data.
// A set of already allocated pod IPs is updated.
func (br *BGPReflector) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	// return any error as fatal
	defer func() {
		if err != nil {
			err = controller.NewFatalError(err)
		}
	}()

	return
}

// Update is NOOP - never called.
func (br *BGPReflector) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	return "", nil
}

// Revert is NOOP - never called.
func (br *BGPReflector) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP.
func (br *BGPReflector) Close() error {
	return nil
}
