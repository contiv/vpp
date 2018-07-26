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

package renderer

import (
	"fmt"
	"net"

	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ServiceRendererAPI defines the API of Service Renderer.
//
// Service Renderer is a pluggable component of the service plugin, sitting below
// the processor and implementing rendering of ContivService instances into
// the configuration of the target network stack. The idea is to allow to have
// alternative and/or complementary Kubernetes service implementations. For example,
// IPv4 and IPv6 protocols could be handled separately by two different renderers.
// Similarly, the set of supported vswitches in the data plane can be extended
// simply by adding new renderers for services and policies. Another use-case is
// to provide alternative implementation of Kubernetes services for the same
// stack - one being the default, others possibly experimental or tailor-made
// for specific applications. The set of renderers to be activated can be
// configurable or determined from the environment. Every active renderer is
// given the same set of data from the processor.
//
// ServiceRendererAPI is the interface that connects processor's southbound
// with the renderer's northbound. For a single Kubernetes service, all relevant
// configuration and state data are wrapped into a single instance of ContivService.
// The renderer learns the set of external IPs and ports on which the service
// should be exposed together with corresponding sets of backends (= endpoints).
// AddService(), DeleteService(), UpdateService() are called every time a service
// is created, removed or its state/configuration data has changed, respectively.
// ContivService is referenced by ID unique across all namespaces.
//
// The processor also monitors the set of all node IPs in the cluster. Every time
// a new IP is assigned to any node inside the cluster or an existing node has been
// deleted, UpdateNodePortServices() is called with the latest list of all node
// IPs together with a set of NodePort services.
//
// Additionally, the processor distinguishes interfaces connecting VPP with
// potential service clients - denoted as Frontends - from those connecting
// vswitch with service endpoints - denoted as Backends. Interface can be both
// Frontend and Backend. The sets of Frontend and Backend interfaces are refreshed
// by the processor every time a pod is created, destroyed, assigned to a service
// for the first time, or no longer acting as a service endpoint. For Renderer
// this classification of interfaces may or may not be useful. It is up to the
// renderer to either leverage or completely ignore events UpdateLocalFrontendIfs()
// and UpdateLocalBackendIfs(). Please note that the sets of Frontend & Backend
// interfaces are specific to the VPP-based networking and not relevant for
// a different vswitch / network stack.
//
// Resync() is used to pass the current snapshot of all data provided
// by the processor. Upon receipt, the renderer is supposed to make sure that
// the renderered configuration matches the state of Kubernetes services and
// to resolve any discrepancies. Resync() is always called on the agent startup,
// but may also be triggered during the runtime - in case a potential data loss
// between the agent and the data store or the vswitch has been detected.
//
// To integrate (VPP-specific) renderer with the ACL-based policies
// (plugins/policy/renderer/acl), it is required to perform the service address
// translation for both directions in-between the VPP nodes: `acl-plugin-in-ip4-fa`
// and `acl-plugin-out-ip4-fa` (i.e. after ingress ACLs, but before egress ACLs).
type ServiceRendererAPI interface {
	// AddService is called for a newly added service.
	AddService(service *ContivService) error

	// UpdateService informs renderer about a change in the configuration
	// or in the state of a service.
	UpdateService(oldService, newService *ContivService) error

	// DeleteService is called for every removed service.
	DeleteService(service *ContivService) error

	// UpdateNodePortServices is called whenever the set of node IPs in the cluster
	// changes.
	UpdateNodePortServices(nodeIPs *IPAddresses, npServices []*ContivService) error

	// UpdateLocalFrontendIfs gives an update about a changed set of Frontend
	// interfaces (VPP specific).
	UpdateLocalFrontendIfs(oldIfNames, newIfNames Interfaces) error

	// UpdateLocalBackendIfs gives an updated about a changed set of backend
	// interfaces (VPP specific).
	UpdateLocalBackendIfs(oldIfNames, newIfNames Interfaces) error

	// Resync provides a complete snapshot of all service-related data.
	// The render should resolve any discrepancies between the state of K8s
	// services and the currently rendered configuration.
	Resync(resyncEv *ResyncEventData) error
}

// ContivService is a less-abstract, free of indirect references representation
// of K8s Service.
// It has:
//   - endpoints combined with services
//   - the full list of IP addresses on which the service should be exposed
//     on this node
type ContivService struct {
	// ID uniquely identifies service across all namespaces.
	ID svcmodel.ID

	// TrafficPolicy decides if traffic is routed cluster-wide or node-local only.
	TrafficPolicy TrafficPolicyType

	// ExternalIPs is a set of all IP addresses on which the service
	// should be exposed on this node (aside from node IPs for NodePorts, which
	// are provided separately via the ServiceRendererAPI.UpdateNodePortServices()
	// method).
	ExternalIPs *IPAddresses

	// Ports is a map of all ports exposed for this service.
	Ports map[string] /* service port name */ *ServicePort

	// Backends map external service ports with corresponding backends (= endpoints).
	Backends map[string] /*service port name */ []*ServiceBackend
}

// TrafficPolicyType is either Cluster-wide routing or Node-local only routing.
type TrafficPolicyType int

const (
	// ClusterWide allows to load-balance traffic across all backends.
	ClusterWide TrafficPolicyType = 0

	// NodeLocal allows to load-balance traffic only across node-local backends.
	NodeLocal TrafficPolicyType = 1
)

// NewContivService is a constructor for ContivService.
func NewContivService() *ContivService {
	return &ContivService{
		ExternalIPs: NewIPAddresses(),
		Ports:       make(map[string]*ServicePort),
		Backends:    make(map[string][]*ServiceBackend),
	}
}

// String converts ContivService into a human-readable string.
func (cs ContivService) String() string {
	externalIPs := ""
	for idx, ip := range cs.ExternalIPs.list {
		externalIPs += ip.String()
		if idx < len(cs.ExternalIPs.list)-1 {
			externalIPs += ", "
		}
	}
	allBackends := ""
	idx := 0
	for port, svcBackends := range cs.Backends {
		backends := ""
		for idx2, svcBackend := range svcBackends {
			backends += svcBackend.String()
			if idx2 < len(svcBackends)-1 {
				backends += ", "
			}
		}
		allBackends += fmt.Sprintf("%s->[%s]", cs.Ports[port].String(), backends)
		if idx < len(cs.Backends)-1 {
			allBackends += ", "
		}
		idx++
	}
	return fmt.Sprintf("ContivService %s <Traffic-Policy:%s ExternalIPs:[%s] Backends:{%s}>",
		cs.ID.String(), cs.TrafficPolicy.String(), externalIPs, allBackends)
}

// String converts TrafficPolicyType into a human-readable string.
func (tpt TrafficPolicyType) String() string {
	switch tpt {
	case ClusterWide:
		return "cluster-wide"
	case NodeLocal:
		return "node-local"
	}
	return "INVALID"
}

// HasNodePort returns true if service is also exposed on the Node IP.
func (cs ContivService) HasNodePort() bool {
	for _, port := range cs.Ports {
		if port.NodePort != 0 {
			return true
		}
	}
	return false
}

// ServicePort contains information on service's port.
type ServicePort struct {
	Protocol ProtocolType /* protocol type */
	Port     uint16       /* port that will be exposed by this service */
	NodePort uint16       /* port on which this service is exposed for Node IP (0 if none) */
}

// String converts ServicePort into a human-readable string.
func (sp ServicePort) String() string {
	if sp.NodePort == 0 {
		return fmt.Sprintf("%d/%s", sp.Port, sp.Protocol.String())
	}
	return fmt.Sprintf("%d:%d/%s", sp.Port, sp.NodePort, sp.Protocol.String())
}

// ProtocolType is either TCP or UDP.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = 6

	// UDP protocol.
	UDP ProtocolType = 17
)

// String converts ProtocolType into a human-readable string.
func (pt ProtocolType) String() string {
	switch pt {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	}
	return "INVALID"
}

// ServiceBackend represents a single service backend (= endpoint).
type ServiceBackend struct {
	IP          net.IP /* internal IP address of the backend */
	Port        uint16 /* backend-local port on which the service listens */
	Local       bool   /* true if the backend is deployed on this node (can be leveraged for smart load-balancing) */
	HostNetwork bool   /* true if the backend uses host networking */
}

// String converts Backend into a human-readable string.
func (sb ServiceBackend) String() string {
	return fmt.Sprintf("<IP:%s Port:%d, Local:%t>", sb.IP, sb.Port, sb.Local)
}

// IPAddresses is a set of IP addresses.
type IPAddresses struct {
	list []net.IP
}

// NewIPAddresses is a constructor for IPAddresses.
func NewIPAddresses(addrs ...net.IP) *IPAddresses {
	ipAddresses := &IPAddresses{
		list: []net.IP{},
	}
	for _, addr := range addrs {
		ipAddresses.list = append(ipAddresses.list, addr)
	}
	return ipAddresses
}

// List returns the set as a slice which can be iterated through.
func (addrs *IPAddresses) List() []net.IP {
	return addrs.list
}

// Add IP address into the set.
func (addrs *IPAddresses) Add(addr net.IP) {
	if !addrs.Has(addr) {
		addrs.list = append(addrs.list, addr)
	}
}

// Del IP address from the set.
func (addrs *IPAddresses) Del(addr net.IP) {
	newAddrs := []net.IP{}
	for _, addr2 := range addrs.list {
		if !addr2.Equal(addr) {
			newAddrs = append(newAddrs, addr2)
		}
	}
	addrs.list = newAddrs
}

// Copy creates a deep copy of the set.
func (addrs *IPAddresses) Copy() *IPAddresses {
	addrsCopy := NewIPAddresses()
	for _, addr := range addrs.list {
		addrsCopy.list = append(addrsCopy.list, addr)
	}
	return addrsCopy
}

// Has returns true if the given IP address is in the set.
func (addrs *IPAddresses) Has(addr net.IP) bool {
	for _, addr2 := range addrs.list {
		if addr2.Equal(addr) {
			return true
		}
	}
	return false
}

// String converts a set of IP addresses into a human-readable string.
func (addrs IPAddresses) String() string {
	str := "{"
	for idx, addr := range addrs.list {
		str += addr.String()
		if idx < len(addrs.list)-1 {
			str += ", "
		}
	}
	str += "}"
	return str
}

// Interfaces is a set of interface names.
type Interfaces map[string]struct{}

// NewInterfaces is a constructor for Interfaces.
func NewInterfaces(ifNames ...string) Interfaces {
	interfaces := make(Interfaces)
	for _, ifName := range ifNames {
		interfaces.Add(ifName)
	}
	return interfaces
}

// Add interface name into the set.
func (ifs Interfaces) Add(ifName string) {
	ifs[ifName] = struct{}{}
}

// Del interface name from the set.
func (ifs Interfaces) Del(ifName string) {
	if ifs.Has(ifName) {
		delete(ifs, ifName)
	}
}

// Copy creates a deep copy of the set.
func (ifs Interfaces) Copy() Interfaces {
	ifsCopy := NewInterfaces()
	for intf := range ifs {
		ifsCopy.Add(intf)
	}
	return ifsCopy
}

// Has returns true if the given interface name is in the set.
func (ifs Interfaces) Has(ifName string) bool {
	_, has := ifs[ifName]
	return has
}

// String converts a set of interface names into a human-readable string.
func (ifs Interfaces) String() string {
	str := "{"
	idx := 0
	for ifName := range ifs {
		str += ifName
		if idx < len(ifs)-1 {
			str += ", "
		}
		idx++
	}
	str += "}"
	return str
}

// ResyncEventData wraps an entire state of K8s services as provided by the Processor.
type ResyncEventData struct {
	// NodeIPs is a list of IP addresses of all nodes in the cluster.
	NodeIPs *IPAddresses

	// Services is a list of all currently deployed services.
	Services []*ContivService

	// FrontendIfs is a set of all interfaces connecting clients with VPP
	// (VPP specific).
	FrontendIfs Interfaces

	// BackendIfs is a set of all interfaces connecting service backends with VPP
	// (VPP specific).
	BackendIfs Interfaces
}

// NewResyncEventData is a constructor for ResyncEventData.
func NewResyncEventData() *ResyncEventData {
	return &ResyncEventData{
		NodeIPs:     NewIPAddresses(),
		Services:    []*ContivService{},
		FrontendIfs: NewInterfaces(),
		BackendIfs:  NewInterfaces(),
	}
}

// String converts ResyncEventData into a human-readable string.
func (red ResyncEventData) String() string {
	services := ""
	for idx, service := range red.Services {
		services += service.String()
		if idx < len(red.Services)-1 {
			services += ", "
		}
	}
	return fmt.Sprintf("ResyncEventData <NodeIPs:[%s] Services:[%s], FrontendIfs:%s BackendIfs:%s>",
		red.NodeIPs.String(), services, red.FrontendIfs.String(), red.BackendIfs.String())
}
