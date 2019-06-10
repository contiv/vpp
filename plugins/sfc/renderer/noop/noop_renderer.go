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

package noop

import (
	"fmt"
	"net"

	govpp "git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/vpp/nat"
)

// Renderer implements rendering of services for IPv4 in VPP.
//
// The renderer maps ContivService instances into corresponding NAT44-DNAT model
// instances, installed into VPP by the Ligato/VPP-agent as a set of static mappings.
// Frontends and Backends are reflected in the global NAT44 configuration
// as `in` & `out` interface features, respectively.
//
// NAT global configuration and DNAT instances generated in the Renderer are
// sent to the Ligato/VPP-agent via the local client interface. The Ligato/VPP-agent
// in turn updates the VPP-NAT44 configuration through binary APIs. For each
// transaction, the agent's vpp/ifplugin determines the minimum set of operations
// that need to be executed to reflect the configuration changes.
//
// To allow access from service to itself, the Contiv plugin is asked to provide
// the virtual NAT loopback IP address, which is then inserted into the `TwiceNAT`
// address pool. `self-twice-nat` feature is enabled for every static mapping.
//
// Until VPP supports timing-out of NAT sessions, the renderer also performs
// periodic cleanup of inactive NAT sessions.
//
// An extra feature of the renderer, outside the scope of services, is a management
// of the dynamic source-NAT for node-outbound traffic, configured to enable
// Internet access even for pods with private IPv4 addresses.
// If dynamic SNAT is enabled in the Contiv configuration, the default interface
// IP (interface used to connect the node with the default GW) is added into
// the NAT main address pool and the interface itself is switched into
// the post-routing NAT mode (`output` feature) - both during Resync.
//
// For more implementation details, please study the developer's guide for
// services: `docs/dev-guide/SERVICES.md` from the top directory.
type Renderer struct {
	Deps

	snatOnly     bool /* do not render services, only dynamic SNAT */
	natGlobalCfg *vpp_nat.Nat44Global
	nodeIPs      *renderer.IPAddresses

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
	rndr.snatOnly = snatOnly
	rndr.natGlobalCfg = &vpp_nat.Nat44Global{
		Forwarding: true,
	}
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	// run async NAT session cleanup routine
	go rndr.idleNATSessionCleanup()
	return nil
}

// AddService installs destination-NAT rules for a newly added service.
func (rndr *Renderer) AddService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	dnat := rndr.contivServiceToDNat(service)
	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add service '%v'", service.ID))
	txn.Put(vpp_nat.DNAT44Key(dnat.Label), dnat)
	return nil
}

// UpdateService updates destination-NAT rules for a changed service.
func (rndr *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}
	newDNAT := rndr.contivServiceToDNat(newService)
	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))
	txn.Put(vpp_nat.DNAT44Key(newDNAT.Label), newDNAT)
	return nil
}

// DeleteService removes destination-NAT configuration associated with a freshly
// un-deployed service.
func (rndr *Renderer) DeleteService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))
	txn.Delete(vpp_nat.DNAT44Key(service.ID.String()))
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
