// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
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

package srv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/iptables"
	"github.com/ligato/vpp-agent/api/models/linux/namespace"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/srv6"
	"github.com/ligato/vpp-agent/pkg/models"
)

// operation represents type of operation on a service
type operation int

const (
	serviceAdd operation = iota
	serviceDel
)

const (
	ipv6HostPrefix   = "/128"
	ipv6PodSidPrefix = "/128"
	ipv6AddrAny      = "::"
)

// Renderer implements rendering of services for SRv6 in VPP.
type Renderer struct {
	Deps

	policyBSIDs map[string]net.IP // map[ContivService.ID.String()]=policyBsid
	backendSIDs map[string]net.IP // map[backend.ip.String()]=sid
	snatOnly    bool              // do not render services, only dynamic SNAT
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	ContivConf       contivconf.API
	NodeSync         nodesync.API
	PodManager       podmanager.API
	IPAM             ipam.API
	IPNet            ipnet.API
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
	ip             net.IP
	portForwards   []*portForward
	useHostNetwork bool
}

// remoteBackend holds information about a service backend located on remote node.
type remoteBackend struct {
	ip             net.IP
	nodeID         uint32
	nodeIP         net.IP
	useHostNetwork bool
}

type localBackendKey [16]byte  // 16-byte IP
type remoteBackendKey [20]byte // 16-byte IP and 4-byte nodeID

// Init initializes the renderer.
// Set <snatOnly> to true if the renderer should only configure SNAT and leave
// services to another renderer.
func (r *Renderer) Init(snatOnly bool) error {
	r.snatOnly = snatOnly
	r.policyBSIDs = make(map[string]net.IP)
	r.backendSIDs = make(map[string]net.IP)
	return nil
}

// AfterInit is NOOP.
func (r *Renderer) AfterInit() error {
	return nil
}

// Close deallocates resources held by the renderer.
func (r *Renderer) Close() error {
	return nil
}

// AddService installs VPP config for a newly added service.
func (r *Renderer) AddService(service *renderer.ContivService) error {
	if r.snatOnly {
		return nil
	}

	txn := r.UpdateTxnFactory(fmt.Sprintf("add service '%v'", service.ID))

	addDelConfig, updateConfig := r.renderService(service, serviceAdd)
	controller.PutAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	return nil
}

// UpdateService updates VPP config for a changed service.
func (r *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if r.snatOnly {
		return nil
	}

	txn := r.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))

	addDelConfig, updateConfig := r.renderService(oldService, serviceDel)
	controller.DeleteAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	addDelConfig, updateConfig = r.renderService(newService, serviceAdd)
	controller.PutAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	return nil
}

// DeleteService removes VPP config associated with a freshly un-deployed service.
func (r *Renderer) DeleteService(service *renderer.ContivService) error {
	if r.snatOnly {
		return nil
	}

	txn := r.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))

	addDelConfig, updateConfig := r.renderService(service, serviceDel)
	controller.DeleteAll(txn, addDelConfig)
	controller.PutAll(txn, updateConfig)

	return nil
}

// UpdateNodePortServices is called whenever the set of node IPs in the cluster
// changes.
func (r *Renderer) UpdateNodePortServices(nodeIPs *renderer.IPAddresses, npServices []*renderer.ContivService) error {
	return nil
}

// UpdateLocalFrontendIfs gives an update about a changed set of Frontend
// interfaces (VPP specific).
func (r *Renderer) UpdateLocalFrontendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	return nil
}

// UpdateLocalBackendIfs gives an updated about a changed set of backend
// interfaces (VPP specific).
func (r *Renderer) UpdateLocalBackendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	return nil
}

// Resync completely replaces the current VPP service configuration with the provided
// full state of K8s services.
func (r *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := r.ResyncTxnFactory()

	// add configuration for current services (resync should return desired state, not remove previous state)
	for _, service := range resyncEv.Services {
		addDelConfig, updateConfig := r.renderService(service, serviceAdd)
		controller.PutAll(txn, addDelConfig)
		controller.PutAll(txn, updateConfig)
	}

	return nil
}

// renderService renders Contiv service to VPP configuration.
// addDelConfig sliceContains KV pairs that should be added/deleted,
// updateConfig sliceContains KV pair that should be updated.
func (r *Renderer) renderService(service *renderer.ContivService, oper operation) (
	addDelConfig controller.KeyValuePairs, updateConfig controller.KeyValuePairs) {

	r.Log.Debugf("Rendering %s", service.String())

	addDelConfig = make(controller.KeyValuePairs)
	updateConfig = make(controller.KeyValuePairs)
	localBackends := make(map[localBackendKey]*localBackend, 0)
	hasHostNetworkLocalBackend := false
	remoteBackends := make(map[remoteBackendKey]*remoteBackend, 0)

	// collect info about the backends
	for servicePortName, servicePort := range service.Ports {
		for _, backend := range service.Backends[servicePortName] {
			if backend.Local {
				// collect local backend info
				if backend.HostNetwork {
					hasHostNetworkLocalBackend = true
					lb := &localBackend{
						useHostNetwork: true,
						ip:             backend.IP,
					}
					localBackends[lb.Key()] = lb
				} else {
					lb := &localBackend{ip: backend.IP}
					if servicePort.Port != backend.Port {
						previousForwards := lb.portForwards
						if previousLB, exists := localBackends[lb.Key()]; exists {
							previousForwards = previousLB.portForwards
						}
						lb.portForwards = append(previousForwards, &portForward{
							proto: servicePort.Protocol,
							from:  servicePort.Port,
							to:    backend.Port,
						})
					}
					localBackends[lb.Key()] = lb
				}
			} else {
				// collect remote backend info
				var nodeID uint32
				var err error
				if backend.HostNetwork {
					nodeID, err = r.nodeIDFromNodeOrHostIP(backend.IP)
					if err != nil {
						r.Log.Warnf("Error by extracting node ID from host IP: %v", err)
						continue
					}
				} else {
					nodeID, err = r.IPAM.NodeIDFromPodIP(backend.IP)
					if err != nil {
						r.Log.Warnf("Error by extracting node ID from pod ID: %v", err)
						continue
					}
				}
				nodeIP, _, err := r.IPAM.NodeIPAddress(nodeID)
				if err != nil {
					r.Log.Warnf("Error by extracting node IP from node ID %v due to: %v", nodeID, err)
				} else {
					rb := &remoteBackend{
						ip:             backend.IP,
						nodeID:         nodeID,
						nodeIP:         nodeIP,
						useHostNetwork: backend.HostNetwork,
					}
					remoteBackends[rb.Key()] = rb
				}
			}
		}
	}

	r.Log.WithFields(logging.Fields{
		"service":                    service.ID,
		"localBackends":              stringForLocalBackends(localBackends),
		"hasHostNetworkLocalBackend": hasHostNetworkLocalBackend,
		"remoteBackends":             remoteBackends,
	}).Debugf("Processing service backends")

	// ignore services without backend (can't create SRv6 policy without segment lists to backends anyway, vppagent would
	// fail to add such a policy and this is due to VPP not able to create SRv6 policy without at least one segment list)
	// Note: if backend is added later, service update is triggered and service is recreated (delete old and create new)
	// so we can safely ignore services without backends
	if len(localBackends) == 0 && (len(remoteBackends) == 0 || service.TrafficPolicy != renderer.ClusterWide) {
		info := "traffic policy is ClusterWide, so remote backends pods are accounted for"
		if service.TrafficPolicy != renderer.ClusterWide {
			if len(remoteBackends) > 0 {
				info = "please consider whether you want to use non-ClusterWide traffic policy, because there are some remote backends and no local backends"
			} else {
				info = "traffic policy is set to non-ClusterWide traffic policy, but there are no remote backends anyway so it doesn't matter"
			}
		}
		r.Log.Warnf("ignoring service %s because it has no backend pods (%v)", service.ID, info)
		return
	}

	serviceIPs := append(service.ClusterIPs.List(), service.ExternalIPs.List()...)

	// steer packets into service's SRv6 policy (one service = one SRv6 policy) (packet entry part)
	bsid := r.IPAM.BsidForServicePolicy(serviceIPs)
	for _, serviceIP := range serviceIPs {
		steering := &vpp_srv6.Steering{
			Name: "forK8sService-" + service.ID.Namespace + "-" + service.ID.Name, // avoiding "/" to not hit special cases for key handling in vpp-agent
			Traffic: &vpp_srv6.Steering_L3Traffic_{
				L3Traffic: &vpp_srv6.Steering_L3Traffic{
					PrefixAddress:     serviceIP.String() + ipv6HostPrefix,
					InstallationVrfId: r.ContivConf.GetRoutingConfig().PodVRFID,
				},
			},
			PolicyRef: &vpp_srv6.Steering_PolicyBsid{
				PolicyBsid: bsid.String(),
			},
		}
		addDelConfig[models.Key(steering)] = steering
	}

	// create Srv6 policy with segment list for each backend (loadbalancing and packet switching part)
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	for _, localBackend := range localBackends {
		var segments []string
		if localBackend.useHostNetwork {
			segments = []string{r.IPAM.SidForServiceHostLocalsid().String()}
		} else {
			segments = []string{r.IPAM.SidForServicePodLocalsid(localBackend.ip).String()}
		}
		segmentLists = append(segmentLists,
			&vpp_srv6.Policy_SegmentList{
				Weight:   1,
				Segments: segments,
			})
	}
	if service.TrafficPolicy == renderer.ClusterWide { // use remote backends only if traffic policy allows it
		for _, remoteBackend := range remoteBackends {
			segments := []string{r.IPAM.SidForServiceNodeLocalsid(remoteBackend.nodeIP).String()}
			if remoteBackend.useHostNetwork {
				segments = append(segments, r.IPAM.SidForServiceHostLocalsid().String())
			} else {
				segments = append(segments, r.IPAM.SidForServicePodLocalsid(remoteBackend.ip).String())
			}
			segmentLists = append(segmentLists,
				&vpp_srv6.Policy_SegmentList{
					Weight:   1,
					Segments: segments,
				})
		}
	}
	policy := &vpp_srv6.Policy{
		InstallationVrfId: r.ContivConf.GetRoutingConfig().MainVRFID,
		Bsid:              bsid.String(),
		SegmentLists:      segmentLists,
		SprayBehaviour:    false, // loadbalance packets and not duplicate(spray) it to all segment lists
		SrhEncapsulation:  true,
	}
	addDelConfig[models.Key(policy)] = policy

	// create localSIDs/inter-vrf routes/... for local pod backends (after IPv6 routing of packets emitted from policy, localSIDs will catch them in correct node and send to local backend pods)
	for _, backend := range localBackends {
		if backend.useHostNetwork {
			continue // hostNetwork local backends handled separatelly
		}

		// adding route from main VRF to pod VRF for cases when service backend should be reachable by service client from other node
		route := &vpp_l3.Route{
			Type:        vpp_l3.Route_INTER_VRF,
			DstNetwork:  r.IPAM.SidForServicePodLocalsid(backend.ip).String() + ipv6PodSidPrefix,
			VrfId:       r.ContivConf.GetRoutingConfig().MainVRFID,
			ViaVrfId:    r.ContivConf.GetRoutingConfig().PodVRFID,
			NextHopAddr: ipv6AddrAny,
		}
		key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
		addDelConfig[key] = route

		// getting more info about local backend
		podID, found := r.IPAM.GetPodFromIP(backend.ip)
		if !found {
			r.Log.Warnf("Unable to get pod info for backend IP %v", backend.ip)
			continue
		}
		vppIfName, _, loopIfName, exists := r.IPNet.GetPodIfNames(podID.Namespace, podID.Name)
		if !exists {
			r.Log.Warnf("Unable to get interfaces for pod %v", podID)
			continue
		}

		// adding LocalSID
		localSID := &vpp_srv6.LocalSID{
			Sid:               r.IPAM.SidForServicePodLocalsid(backend.ip).String(),
			InstallationVrfId: r.ContivConf.GetRoutingConfig().PodVRFID,
			EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           backend.ip.String(),
				OutgoingInterface: vppIfName,
			}},
		}
		addDelConfig[models.Key(localSID)] = localSID

		for _, serviceIP := range serviceIPs {
			// assign serviceIPs on the backend pod loopbacks
			key := linux_interfaces.InterfaceKey(loopIfName)
			val := r.ConfigRetriever.GetConfig(key)
			if val == nil {
				r.Log.Warnf("Loopback interface for pod %v not found", podID)
				continue
			}
			loop := val.(*linux_interfaces.Interface)
			ip := serviceIP.String() + ipv6HostPrefix
			if oper == serviceAdd {
				if !sliceContains(loop.IpAddresses, ip) {
					loop.IpAddresses = append(loop.IpAddresses, ip)
				}
			} else {
				loop.IpAddresses = sliceRemove(loop.IpAddresses, ip)
			}
			updateConfig[key] = loop

			// port forward service port to application port in pod
			pod, exists := r.PodManager.GetLocalPods()[podID]
			if !exists {
				r.Log.Warnf("pod %v not found in local pods list", podID)
				continue
			}
			for _, pf := range backend.portForwards {
				// add / del an iptables rule into pod's PREROUTING chain (external traffic)
				// and OUTPUT chain (local, pod-to-itself traffic)
				extRuleCh := r.getPodPFRuleChain(pod, linux_iptables.RuleChain_PREROUTING, updateConfig)
				localRuleCh := r.getPodPFRuleChain(pod, linux_iptables.RuleChain_OUTPUT, updateConfig)
				rule := r.getServicePortForwardRule(serviceIP, pf)
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

	// create localsids/inter-vrf routes for local host backends
	if hasHostNetworkLocalBackend {
		// Note: in case of clients of service being local pods, traffic is steered from pod vrf table, but pushed out from
		// policy in main vrf table -> no need to for inter-vrf table route like in ipv6 renderer

		// from main VRF to host (create localsid with decapsulation and crossconnect to the host (DX6 end function))
		nextHop := r.IPAM.HostInterconnectIPInLinux()
		if r.ContivConf.InSTNMode() {
			nextHop, _ = r.IPNet.GetNodeIP()
		}
		localSID := &vpp_srv6.LocalSID{
			Sid:               r.IPAM.SidForServiceHostLocalsid().String(),
			InstallationVrfId: r.ContivConf.GetRoutingConfig().MainVRFID,
			EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           nextHop.String(),
				OutgoingInterface: r.IPNet.GetHostInterconnectIfName(),
			}},
		}
		addDelConfig[models.Key(localSID)] = localSID
	}

	return addDelConfig, updateConfig
}

// getPodPFRuleChain returns the config of the pod-local iptables rule chain of given chain type -
// At first it is looked up in currentConfig. If it is not found it's
// retrieved from the controller (if it already exists), or an empty one.
func (r *Renderer) getPodPFRuleChain(
	pod *podmanager.LocalPod, chainType linux_iptables.RuleChain_ChainType, currentConfig controller.KeyValuePairs) *linux_iptables.RuleChain {

	rchName := fmt.Sprintf("port-forward-%s-%s", pod.ContainerID, chainType.String())

	// retrieve the rule chainType if it already exists
	key := linux_iptables.RuleChainKey(rchName)

	val, exists := currentConfig[key]
	if exists && val != nil {
		return val.(*linux_iptables.RuleChain)
	}

	val = r.ConfigRetriever.GetConfig(key)
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
func (r *Renderer) getServicePortForwardRule(serviceIP net.IP, pf *portForward) string {
	proto := "tcp"
	if pf.proto == renderer.UDP {
		proto = "udp"
	}
	return fmt.Sprintf("-d %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d",
		serviceIP.String()+ipv6HostPrefix, proto, proto, pf.from, pf.to)
}

// nodeIDFromNodeOrHostIP returns node ID matching with the provided node (VPP) or host (mgmt) IP.
// If no match is found for provided IP, error is returned.
func (r *Renderer) nodeIDFromNodeOrHostIP(ip net.IP) (uint32, error) {
	for _, node := range r.NodeSync.GetAllNodes() {
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

func (lb localBackend) Key() localBackendKey {
	var key localBackendKey
	copy(key[:], lb.ip.To16())
	return key
}

func (rb remoteBackend) Key() remoteBackendKey {
	var key remoteBackendKey
	copy(key[:], rb.ip.To16())
	binary.LittleEndian.PutUint32(key[16:], rb.nodeID)
	return key
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

func stringForLocalBackends(localBeckends map[localBackendKey]*localBackend) string {
	var sb strings.Builder
	for _, lb := range localBeckends {
		sb.WriteString(fmt.Sprintf("%+v", *lb))
	}
	return sb.String()
}
