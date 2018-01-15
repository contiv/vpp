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
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/service/configurator"
	//epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	//svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ServiceProcessor implements ServiceProcessorAPI.
type ServiceProcessor struct {
	Deps
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	Contiv       contiv.API /* to get the Node IP and all interface names */
	Configurator configurator.ServiceConfiguratorAPI
}

// Init initializes service processor.
func (sc *ServiceProcessor) Init() error {
	return nil
}

// Update processes a datasync change event associated with the state data
// of K8s pods, endpoints and services.
// The data change is stored into the cache and the configurator
// is notified about any changes related to services that need to be reflected
// in the VPP NAT configuration.
func (sc *ServiceProcessor) Update(dataChngEv datasync.ChangeEvent) error {
	return nil
}

// Resync processes a datasync resync event associated with the state data
// of K8s pods, endpoints and services.
// The cache content is fully replaced and the configurator receives a full
// snapshot of Contiv Services at the present state to be (re)installed.
func (sc *ServiceProcessor) Resync(resyncEv datasync.ResyncEvent) error {
	return nil
}

// Close deallocates resource held by the processor.
func (sc *ServiceProcessor) Close() error {
	return nil
}
