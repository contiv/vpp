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

package l2xconn

import (
	"net"

	govpp "git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
)

// Renderer implements rendering of services for IPv4 in VPP.
type Renderer struct {
	Deps

	/* dynamic SNAT */
	defaultIfName string
	defaultIfIP   net.IP
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	GoVPPChan        govpp.Channel      /* used for direct NAT binary API calls */
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
// Set <snatOnly> to true if the renderer should only configure SNAT and leave
// services to another renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {

	return nil
}

// AddService installs destination-NAT rules for a newly added service.
func (rndr *Renderer) AddChain(chain *renderer.ContivSFC) error {

	rndr.Log.Infof("Add chain: %v", chain)

	//dnat := rndr.contivServiceToDNat(service)
	//txn := rndr.UpdateTxnFactory(fmt.Sprintf("add service '%v'", service.ID))
	//txn.Put(vpp_nat.DNAT44Key(dnat.Label), dnat)
	return nil
}

// UpdateService updates destination-NAT rules for a changed service.
func (rndr *Renderer) UpdateChain(oldChain, newChain *renderer.ContivSFC) error {

	rndr.Log.Infof("Update chain: %v", newChain)

	//newDNAT := rndr.contivServiceToDNat(newService)
	//txn := rndr.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))
	//txn.Put(vpp_nat.DNAT44Key(newDNAT.Label), newDNAT)
	return nil
}

// DeleteService removes destination-NAT configuration associated with a freshly
// un-deployed service.
func (rndr *Renderer) DeleteChain(chain *renderer.ContivSFC) error {

	rndr.Log.Infof("Delete chain: %v", chain)

	//txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))
	//txn.Delete(vpp_nat.DNAT44Key(service.ID.String()))
	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {

	// TODO

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}
