/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
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

// SFCProcessorAPI defines the API of the Service Function Chain Processor.
type SFCProcessorAPI interface {
	// Update processes a datasync change event associated with the state data
	// of K8s pods and SFC and custom network CRDs.
	// The data change is stored into the cache and all registered renderers
	// are notified about any changes related to service function chains
	// that need to be reflected in the underlying network stack(s).
	Update(dataChngEv datasync.ChangeEvent) error

	// Resync processes a datasync resync event associated with the state data
	// of K8s pods and SFC and custom network CRDs.
	// The cache content is fully replaced and all registered renderers
	// receive a full snapshot of service function chains at the present
	// state to be (re)installed.
	Resync(resyncEv datasync.ResyncEvent) error

	// RegisterRenderer registers a new service function chain renderer.
	// The renderer will be receiving updates for all SFCs on the cluster.
	RegisterRenderer(renderer renderer.SFCRendererAPI) error
}
