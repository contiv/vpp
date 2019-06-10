/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

package processor

import (
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/ligato/cn-infra/datasync"
)

// ServiceProcessorAPI defines the API of the Service Processor.
//
// The processor receives RESYNC and data-change events for endpoints and services
// from the service plugin. The state of the K8s configuration is internally
// cached (since the last RESYNC). The cache is used to match subsets of endpoints
// with the corresponding service definition (including ports).
// Based on the service type, the list of addresses on which the service should
// be exposed is determined.
//
// Processor also maintains the set of interfaces connecting frontends (physical
// interfaces and pods that do not run any service) and backends (pods which act
// as endpoints of at least one service). The set of physical interfaces and
// interfaces connecting pods are learned from the Contiv plugin.
//
// The combined service and endpoint state/configuration data are passed
// further to all registered renderers. The processor allows to register multiple
// renderers at once, each receiving the same set of data.
type ServiceProcessorAPI interface {
	// Update processes a datasync change event associated with the state data
	// of K8s pods, endpoints, services and nodes.
	// The data change is stored into the cache and all registered renderers
	// are notified about any changes related to services that need to be
	// reflected in the underlying network stack(s).
	Update(dataChngEv datasync.ChangeEvent) error

	// Resync processes a datasync resync event associated with the state data
	// of K8s pods, endpoints, services and nodes.
	// The cache content is fully replaced and all registered renderers
	// receive a full snapshot of Contiv Services at the present state to be
	// (re)installed.
	Resync(resyncEv datasync.ResyncEvent) error

	// RegisterRenderer registers a new service renderer.
	// The renderer will be receiving updates for all services on the cluster.
	RegisterRenderer(renderer renderer.SFCRendererAPI) error
}
