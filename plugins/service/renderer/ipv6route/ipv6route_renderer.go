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

package ipv6route

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipv4net"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/ligato/cn-infra/logging"
	linux_if "github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
)

// Renderer implements rendering of services for IPv6 in VPP using static routes.
type Renderer struct {
	Deps

	snatOnly bool /* do not render services, only dynamic SNAT */
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	ConfigRetriever  controller.ConfigRetriever
	IPAM             ipam.API
	IPv4Net          ipv4net.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
}

// Init initializes the renderer.
// Set <snatOnly> to true if the renderer should only configure SNAT and leave
// services to another renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	rndr.snatOnly = snatOnly
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit is NOOP.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddService installs VPP config for a newly added service.
func (rndr *Renderer) AddService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add service '%v'", service.ID))

	config := rndr.renderService(service)
	controller.PutAll(txn, config)

	return nil
}

// UpdateService updates VPP config for a changed service.
func (rndr *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))

	config := rndr.renderService(newService)
	controller.PutAll(txn, config)

	// TODO: render both oldService and newService, Put diff

	return nil
}

// DeleteService removes VPP config associated with a freshly un-deployed service.
func (rndr *Renderer) DeleteService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))

	config := rndr.renderService(service)
	controller.DeleteAll(txn, config)

	return nil
}

// UpdateNodePortServices is NOOP.
func (rndr *Renderer) UpdateNodePortServices(nodeIPs *renderer.IPAddresses,
	npServices []*renderer.ContivService) error {

	if rndr.snatOnly {
		return nil
	}

	return nil
}

// UpdateLocalFrontendIfs is NOOP.
func (rndr *Renderer) UpdateLocalFrontendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}

	return nil
}

// UpdateLocalBackendIfs is NOOP.
func (rndr *Renderer) UpdateLocalBackendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}

	return nil
}

// Resync completely replaces the current VPP service configuration with the provided
// full state of K8s services.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// In case the renderer is supposed to configure only the dynamic source-NAT,
	// just pretend there are no services, frontends and backends to be configured.
	if rndr.snatOnly {
		resyncEv = renderer.NewResyncEventData()
	}

	// Resync service configuration
	for _, service := range resyncEv.Services {
		config := rndr.renderService(service)
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// renderService renders Contiv service to VPP configuration
func (rndr *Renderer) renderService(service *renderer.ContivService) controller.KeyValuePairs {
	config := make(controller.KeyValuePairs)

	localBackends := make([]net.IP, 0)
	hasHostNetworkLocalBackend := false

	for portName := range service.Ports {
		for _, backend := range service.Backends[portName] {
			if backend.Local {
				if backend.HostNetwork {
					hasHostNetworkLocalBackend = true
				} else {
					localBackends = append(localBackends, backend.IP)
				}
			}
		}
	}

	// TODO: external IPs

	// for local backends with hostNetwork, route ClusterIPs towards towards the host
	if hasHostNetworkLocalBackend {
		for _, clusterIP := range service.ClusterIPs.List() {
			route := &vpp_l3.Route{
				DstNetwork:        clusterIP.String() + "/128",
				NextHopAddr:       rndr.IPAM.HostInterconnectIPInLinux().String(),
				OutgoingInterface: rndr.IPv4Net.GetHostInterconnectIfName(),
				VrfId:             rndr.ContivConf.GetRoutingConfig().MainVRFID,
			}
			key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
			config[key] = route
		}
	}

	//  for local backends (with non-hostNetwork), route ClusterIPs towards the PODs
	for _, backendIP := range localBackends {
		// connect local backend
		podID, found := rndr.IPAM.GetPodFromIP(backendIP)
		if found {
			vppIfName, linuxIfName, exists := rndr.IPv4Net.GetPodIfName(podID.Namespace, podID.Name)
			if exists {
				for _, clusterIP := range service.ClusterIPs.List() {
					// cluster IP in POD
					key := linux_if.InterfaceKey(linuxIfName)
					val := rndr.ConfigRetriever.GetConfig(key)
					if val == nil {
						rndr.Log.Warnf("Interface to pod %v/%v not found", podID.Namespace, podID.Name)
						continue
					}
					intf := val.(*linux_if.Interface)
					intf.IpAddresses = append(intf.IpAddresses, clusterIP.String()+"/128")
					config[key] = intf

					// route to POD
					route := &vpp_l3.Route{
						DstNetwork:        clusterIP.String() + "/128",
						NextHopAddr:       backendIP.String(),
						OutgoingInterface: vppIfName,
						VrfId:             rndr.ContivConf.GetRoutingConfig().PodVRFID,
					}
					key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
					config[key] = route
				}
			}
		}
	}

	// TODO: (only) in case of no local backends, route to VXLANs towards nodes with some backend

	return config
}
