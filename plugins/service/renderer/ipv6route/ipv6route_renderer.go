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

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipv4net"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/vishvananda/netlink"
)

const (
	ipv6HostPrefix = "/128"
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
	PodManager       podmanager.API
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

	oldConfig := rndr.renderService(oldService)
	newConfig := rndr.renderService(newService)

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

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
	return nil
}

// UpdateLocalFrontendIfs is NOOP.
func (rndr *Renderer) UpdateLocalFrontendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	return nil
}

// UpdateLocalBackendIfs is NOOP.
func (rndr *Renderer) UpdateLocalBackendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
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

	rndr.Log.Debugf("Rendering %s", service.String())

	config := make(controller.KeyValuePairs)
	localBackends := make([]net.IP, 0)
	hasHostNetworkLocalBackend := false
	remoteBackendNodes := make(map[uint32]bool)

	for portName := range service.Ports {
		for _, backend := range service.Backends[portName] {
			if backend.Local {
				if backend.HostNetwork {
					if rndr.isLocalNodeOrHostIP(backend.IP) {
						hasHostNetworkLocalBackend = true
					}
				} else {
					localBackends = append(localBackends, backend.IP)
				}
			} else {
				if backend.HostNetwork {
					// TODO: node ID from host IP ??? / this should be already routed ???
				} else {
					nodeID, err := rndr.IPAM.NodeIDFromPodIP(backend.IP)
					if err != nil {
						rndr.Log.Warnf("Error by extracting node ID from pod IP: %v", err)
					} else {
						remoteBackendNodes[nodeID] = true
					}
				}
			}
		}
	}

	rndr.Log.WithFields(logging.Fields{
		"service":                    service.ID,
		"localBackends":              localBackends,
		"hasHostNetworkLocalBackend": hasHostNetworkLocalBackend,
		"remoteBackendNodes":         remoteBackendNodes,
	}).Debugf("Processing service backends")

	// TODO: external IPs

	//  for local backends (with non-hostNetwork), route ClusterIPs towards the PODs
	for _, backendIP := range localBackends {
		// connect local backend
		podID, found := rndr.IPAM.GetPodFromIP(backendIP)
		if found {
			vppIfName, _, exists := rndr.IPv4Net.GetPodIfName(podID.Namespace, podID.Name)
			if exists {
				for _, clusterIP := range service.ClusterIPs.List() {
					// cluster IP in POD
					//key := linux_if.InterfaceKey(linuxIfName)
					//val := rndr.ConfigRetriever.GetConfig(key)
					//if val == nil {
					//	rndr.Log.Warnf("Interface to pod %v/%v not found", podID.Namespace, podID.Name)
					//	continue
					//}
					//intf := val.(*linux_if.Interface)
					//ip := clusterIP.String() + ipv6HostPrefix
					//if !contains(intf.IpAddresses, ip) {
					//	intf.IpAddresses = append(intf.IpAddresses, ip)
					//	config[key] = intf
					//}
					// TODO: temporary for testing, should be replaced with vpp-agent NB API
					pod, exists := rndr.PodManager.GetLocalPods()[podID]
					if !exists {
						rndr.Log.Warnf("POD %v node found in local pods list", podID)
						continue
					}
					err := addAddressToLoopback(pod.NetworkNamespace, &net.IPNet{IP: clusterIP, Mask: net.CIDRMask(128, 128)})
					if err != nil {
						rndr.Log.Errorf("Error by adding IP to POD loopback: %v", err)
					}

					// route to POD
					route := &vpp_l3.Route{
						DstNetwork:        clusterIP.String() + ipv6HostPrefix,
						NextHopAddr:       backendIP.String(),
						OutgoingInterface: vppIfName,
						VrfId:             rndr.ContivConf.GetRoutingConfig().PodVRFID,
					}
					key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
					config[key] = route
				}
			}
		}
	}

	// for local backends with hostNetwork, route ClusterIPs towards towards the host
	if hasHostNetworkLocalBackend {
		for _, clusterIP := range service.ClusterIPs.List() {
			route := &vpp_l3.Route{
				DstNetwork:        clusterIP.String() + ipv6HostPrefix,
				NextHopAddr:       rndr.IPAM.HostInterconnectIPInLinux().String(),
				OutgoingInterface: rndr.IPv4Net.GetHostInterconnectIfName(),
				VrfId:             rndr.ContivConf.GetRoutingConfig().MainVRFID,
			}
			key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
			config[key] = route
		}
	}

	// (only) in case of no local backends, route to VXLANs towards nodes with some backend
	if len(localBackends) == 0 && !hasHostNetworkLocalBackend {
		for _, clusterIP := range service.ClusterIPs.List() {
			for nodeID := range remoteBackendNodes {
				nextHop, _, _ := rndr.IPAM.VxlanIPAddress(nodeID)
				route := &vpp_l3.Route{
					DstNetwork:        clusterIP.String() + ipv6HostPrefix,
					NextHopAddr:       nextHop.String(),
					OutgoingInterface: ipv4net.VxlanBVIInterfaceName,
					VrfId:             rndr.ContivConf.GetRoutingConfig().PodVRFID,
				}
				key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
				config[key] = route
			}
		}
	}

	return config
}

// isLocalNodeOrHostIP returns true if the given IP is current node's node (VPP) or host (mgmt) IP, false otherwise.
func (rndr *Renderer) isLocalNodeOrHostIP(ip net.IP) bool {
	nodeIP, _ := rndr.IPv4Net.GetNodeIP()
	if ip.Equal(nodeIP) {
		return true
	}
	for _, hostIP := range rndr.IPv4Net.GetHostIPs() {
		if hostIP.Equal(ip) {
			return true
		}
	}
	return false
}

// contains returns tru if provided slice contains provided value, false otherwise.
func contains(slice []string, value string) bool {
	for _, i := range slice {
		if i == value {
			return true
		}
	}
	return false
}

func addAddressToLoopback(namespace string, ip *net.IPNet) error {
	ifName := "lo"
	err := ns.WithNetNSPath(namespace, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return err // not tested
		}

		addr := &netlink.Addr{IPNet: ip}
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return err // not tested
		}

		return nil
	})
	if err != nil {
		return err // not tested
	}
	return nil
}
