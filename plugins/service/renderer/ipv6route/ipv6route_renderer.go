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
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/iptables"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
)

const (
	ipv6HostPrefix = "/128"
)

// operation represents type of operation on a service
type operation int

const (
	serviceAdd operation = iota
	serviceDel
)

// Renderer implements rendering of services for IPv6 in VPP using static routes.
type Renderer struct {
	Deps

	snatOnly bool // do not render services, only dynamic SNAT
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	NodeSync         nodesync.API
	PodManager       podmanager.API
	IPAM             ipam.API
	IPv4Net          ipv4net.API
	ConfigRetriever  controller.ConfigRetriever
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
}

// portForward represents a port forward entry from a service port to an application port in a pod.
type portForward struct {
	proto renderer.ProtocolType
	from  uint16
	to    uint16
}

// localBackend holds information about a node-local service backend.
type localBackend struct {
	ip           net.IP
	portForwards []*portForward
}

// String converts localBackend into a human-readable string.
func (lb localBackend) String() string {
	portForwards := ""
	for idx, pf := range lb.portForwards {
		portForwards += fmt.Sprintf("<proto: %v, from: %d to: %d>", pf.proto, pf.from, pf.to)
		if idx < len(lb.portForwards)-1 {
			portForwards += ", "
		}
	}
	return fmt.Sprintf("localBackend IP: %s portForwards: %s", lb.ip.String(), portForwards)
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

	addDelConfig, updateConfig := rndr.renderService(service, serviceAdd)
	controller.PutAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	return nil
}

// UpdateService updates VPP config for a changed service.
func (rndr *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))

	addDelConfig, updateConfig := rndr.renderService(oldService, serviceDel)
	controller.DeleteAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	addDelConfig, updateConfig = rndr.renderService(newService, serviceAdd)
	controller.PutAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	return nil
}

// DeleteService removes VPP config associated with a freshly un-deployed service.
func (rndr *Renderer) DeleteService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))

	addDelConfig, updateConfig := rndr.renderService(service, serviceDel)
	controller.DeleteAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

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
		addDelConfig, updateConfig := rndr.renderService(service, serviceAdd)
		controller.PutAll(txn, addDelConfig)
		controller.PutAll(txn, updateConfig)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// renderService renders Contiv service to VPP configuration.
// addDelConfig sliceContains KV pairs that should be added/deleted,
// updateConfig sliceContains KV pair that should be updated.
func (rndr *Renderer) renderService(service *renderer.ContivService, oper operation) (
	addDelConfig controller.KeyValuePairs, updateConfig controller.KeyValuePairs) {

	rndr.Log.Debugf("Rendering %s", service.String())

	addDelConfig = make(controller.KeyValuePairs)
	updateConfig = make(controller.KeyValuePairs)
	localBackends := make([]*localBackend, 0)
	hasHostNetworkLocalBackend := false
	remoteBackendNodes := make(map[uint32]bool)

	// collect info about the backends
	for servicePortName, servicePort := range service.Ports {
		for _, backend := range service.Backends[servicePortName] {
			if backend.Local {
				// collect local backend info
				if backend.HostNetwork {
					hasHostNetworkLocalBackend = true
				} else {
					lb := &localBackend{ip: backend.IP}
					if servicePort.Port != backend.Port {
						lb.portForwards = append(lb.portForwards, &portForward{
							proto: servicePort.Protocol,
							from:  servicePort.Port,
							to:    backend.Port,
						})
					}
					localBackends = append(localBackends, lb)
				}
			} else {
				// collect remote backend info
				if backend.HostNetwork {
					nodeID, err := rndr.nodeIDFromNodeOrHostIP(backend.IP)
					if err != nil {
						rndr.Log.Warnf("Error by extracting node ID from host IP: %v", err)
					} else {
						remoteBackendNodes[nodeID] = true
					}
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

	serviceIPs := append(service.ClusterIPs.List(), service.ExternalIPs.List()...)

	// for local backends (with non-hostNetwork), route serviceIPs towards the pods
	for _, backend := range localBackends {
		// connect local backend
		podID, found := rndr.IPAM.GetPodFromIP(backend.ip)
		if !found {
			rndr.Log.Warnf("Unable to get pod info for backend IP %v", backend.ip)
			continue
		}
		vppIfName, _, loopIfName, exists := rndr.IPv4Net.GetPodIfNames(podID.Namespace, podID.Name)
		if !exists {
			rndr.Log.Warnf("Unable to get interfaces for pod %v", podID)
			continue
		}
		for _, serviceIP := range serviceIPs {
			// route serviceIP to pod
			route := &vpp_l3.Route{
				DstNetwork:        serviceIP.String() + ipv6HostPrefix,
				NextHopAddr:       backend.ip.String(),
				OutgoingInterface: vppIfName,
				VrfId:             rndr.ContivConf.GetRoutingConfig().PodVRFID,
			}
			key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
			addDelConfig[key] = route

			// assign serviceIP on the pod loopback
			key = linux_interfaces.InterfaceKey(loopIfName)
			val := rndr.ConfigRetriever.GetConfig(key)
			if val == nil {
				rndr.Log.Warnf("Loopback interface for pod %v not found", podID)
				continue
			}
			loop := val.(*linux_interfaces.Interface)
			ip := serviceIP.String() + ipv6HostPrefix
			if oper == serviceAdd {
				loop.IpAddresses = sliceAddIfNotExists(loop.IpAddresses, ip)
			} else {
				loop.IpAddresses = sliceRemove(loop.IpAddresses, ip)
			}
			updateConfig[key] = loop

			// port forward service port to application port in pod
			pod, exists := rndr.PodManager.GetLocalPods()[podID]
			if !exists {
				rndr.Log.Warnf("pod %v not found in local pods list", podID)
				continue
			}
			for _, pf := range backend.portForwards {
				// add / del an iptables rule into pod's PREROUTING chain (external traffic)
				// and OUTPUT chain (local, pod-to-itself traffic)
				extRuleCh := rndr.getPodPFRuleChain(pod, linux_iptables.RuleChain_PREROUTING)
				localRuleCh := rndr.getPodPFRuleChain(pod, linux_iptables.RuleChain_OUTPUT)
				rule := rndr.getServicePortForwardRule(serviceIP, pf)
				if oper == serviceAdd {
					extRuleCh.Rules = sliceAddIfNotExists(extRuleCh.Rules, rule)
					localRuleCh.Rules = sliceAddIfNotExists(localRuleCh.Rules, rule)
				} else {
					extRuleCh.Rules = sliceRemove(extRuleCh.Rules, rule)
					localRuleCh.Rules = sliceRemove(localRuleCh.Rules, rule)
				}
				key = linux_iptables.RuleChainKey(extRuleCh.Name)
				updateConfig[key] = extRuleCh
				key = linux_iptables.RuleChainKey(localRuleCh.Name)
				updateConfig[key] = localRuleCh
			}
		}
	}

	// for local backends with hostNetwork, route serviceIPs towards towards the host
	if hasHostNetworkLocalBackend {
		for _, serviceIP := range serviceIPs {
			route := &vpp_l3.Route{
				DstNetwork:        serviceIP.String() + ipv6HostPrefix,
				NextHopAddr:       rndr.IPAM.HostInterconnectIPInLinux().String(),
				OutgoingInterface: rndr.IPv4Net.GetHostInterconnectIfName(),
				VrfId:             rndr.ContivConf.GetRoutingConfig().MainVRFID,
			}
			key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
			addDelConfig[key] = route
		}
	}

	// (only) in case of no local backends, route serviceIPs to VXLANs towards nodes with some backend
	if len(localBackends) == 0 && !hasHostNetworkLocalBackend {
		for _, serviceIP := range serviceIPs {
			for nodeID := range remoteBackendNodes {
				nextHop, _, _ := rndr.IPAM.VxlanIPAddress(nodeID)
				route := &vpp_l3.Route{
					DstNetwork:        serviceIP.String() + ipv6HostPrefix,
					NextHopAddr:       nextHop.String(),
					OutgoingInterface: ipv4net.VxlanBVIInterfaceName,
					VrfId:             rndr.ContivConf.GetRoutingConfig().PodVRFID,
				}
				key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
				addDelConfig[key] = route
			}
		}
	}

	return addDelConfig, updateConfig
}

// nodeIDFromNodeOrHostIP returns node ID matching with the provided node (VPP) or host (mgmt) IP.
// If no match is found for provided IP, error is returned.
func (rndr *Renderer) nodeIDFromNodeOrHostIP(ip net.IP) (uint32, error) {
	for _, node := range rndr.NodeSync.GetAllNodes() {
		for _, vppIP := range node.VppIPAddresses {
			if ip.Equal(vppIP.Address) {
				return node.ID, nil
			}
		}
		for _, mgmtIP := range node.MgmtIPAddresses {
			if ip.Equal(mgmtIP) {
				return node.ID, nil
			}
		}
	}
	return 0, fmt.Errorf("node with IP %v not found", ip)
}

// getPodPFRuleChain returns the config of the pod-local iptables rule chain of given chain type -
// either retrieved from the controller (if it already exists), or an empty one.
func (rndr *Renderer) getPodPFRuleChain(
	pod *podmanager.LocalPod, chainType linux_iptables.RuleChain_ChainType) *linux_iptables.RuleChain {

	rchName := fmt.Sprintf("port-forward-%s-%s", pod.ContainerID, chainType.String())

	// retrieve the rule chainType if it already exists
	key := linux_iptables.RuleChainKey(rchName)
	val := rndr.ConfigRetriever.GetConfig(key)
	if val != nil {
		return val.(*linux_iptables.RuleChain)
	}

	// return empty chainType if not retrieved
	ruleChain := &linux_iptables.RuleChain{
		Name: rchName,
		Namespace: &linux_namespace.NetNamespace{
			Type:      linux_namespace.NetNamespace_FD,
			Reference: pod.NetworkNamespace,
		},
		Protocol:  linux_iptables.RuleChain_IPv6,
		Table:     linux_iptables.RuleChain_NAT,
		ChainType: chainType,
	}
	return ruleChain
}

// getServicePortForwardRule returns iptables port forward rule for specified service IP and port forward data.
func (rndr *Renderer) getServicePortForwardRule(serviceIP net.IP, pf *portForward) string {
	proto := "tcp"
	if pf.proto == renderer.UDP {
		proto = "udp"
	}
	return fmt.Sprintf("-d %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d",
		serviceIP.String()+ipv6HostPrefix, proto, proto, pf.from, pf.to)
}

// sliceContains returns true if provided slice contains provided value, false otherwise.
func sliceContains(slice []string, value string) bool {
	for _, i := range slice {
		if i == value {
			return true
		}
	}
	return false
}

// sliceAddIfNotExists adds an item into the provided slice (if it does not already exists in the slice).
func sliceAddIfNotExists(slice []string, value string) []string {
	if !sliceContains(slice, value) {
		slice = append(slice, value)
	}
	return slice
}

// sliceRemove removes an item from provided slice (if it exists in the slice).
func sliceRemove(slice []string, value string) []string {
	for i, val := range slice {
		if val == value {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
