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

package configurator

import (
	"fmt"
	"net"

	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
)

// ServiceConfiguratorAPI defines the API of Service Configurator.
// Until we have NAT44 supported in the vpp-agent, the configurator installs
// the configuration directly via VPP/NAT plugin binary API:
//   - translates ContivService into the corresponding NAT configuration
//   - applies out2in and in2out VPP/NAT's features on interfaces connecting
//     frontends and backends, respectivelly
//   - for each change, calculates the minimal diff, i.e. the smallest set
//     of binary API request that need to be executed to get the NAT
//     configuration in-sync with the state of K8s services
type ServiceConfiguratorAPI interface {
	// AddService installs NAT rules for a newly added service.
	AddService(service *ContivService) error

	// UpdateService reflects a change in the configuration of a service with
	// the smallest number of VPP/NAT binary API calls necessary.
	UpdateService(oldService, newService *ContivService) error

	// DeleteService removes NAT configuration associated with a newly undeployed
	// service.
	DeleteService(service *ContivService) error

	// UpdateLocalFrontendIfs updates the list of interfaces connecting clients
	// with VPP (enabled out2in VPP/NAT feature).
	UpdateLocalFrontendIfs(oldIfNames, newIfNames Interfaces) error

	// UpdateLocalBackendIfs updates the list of interfaces connecting service
	// backends with VPP (enabled in2out VPP/NAT feature).
	UpdateLocalBackendIfs(oldIfNames, newIfNames Interfaces) error

	// Resync completely replaces the current NAT configuration with the provided
	// full state of K8s services.
	Resync(services []*ContivService, frontendIfs, backendIfs Interfaces) error
}

// ContivService is a less-abstract, free of indirect references representation
// of K8s Service.
// It has:
//   - endpoints combined with services
//   - the full list of IP addresses on which the service should be exposed
//     on this node
// It is produced in this form and passed to Configurator by Service Processor.
type ContivService struct {
	// ID should uniquely identify service across all namespaces.
	ID svcmodel.ID

	// SNAT when enabled will make IPs of client acessing this service will
	// get NAT-ed to the Node IP.
	// Learn more about this subject here: https://kubernetes.io/docs/tutorials/services/source-ip/
	SNAT bool

	// ExternalIPs is a list of all IP addresses on which the service
	// should be exposed on this node.
	ExternalIPs []net.IP

	// Ports is a map of all ports exposed for this service.
	Ports map[string]*ServicePort

	// Backends map external service ports with corresponding backends.
	Backends map[string] /*service port*/ []*ServiceBackend
}

// String converts ContivService into a human-readable string.
func (cs ContivService) String() string {
	externalIPs := ""
	for idx, ip := range cs.ExternalIPs {
		externalIPs += ip.String()
		if idx < len(cs.ExternalIPs)-1 {
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
		idx++
		if idx < len(cs.Backends) {
			allBackends += ", "
		}
	}
	return fmt.Sprintf("ContivService %s <SNAT:%t ExternalIPs:[%s] Backends:{%s}>",
		cs.ID.String(), cs.SNAT, externalIPs, allBackends)
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
	TCP ProtocolType = iota

	// UDP protocol.
	UDP
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

// ServiceBackend represents a single service backend.
type ServiceBackend struct {
	IP    net.IP /* internal IP address of the backend */
	Port  uint16 /* backend-local port on which the service listens */
	Local bool   /* true if the backend is installed on this node */
}

// String converts Backend into a human-readable string.
func (sb ServiceBackend) String() string {
	return fmt.Sprintf("<IP:%s Port:%d, Local:%t>", sb.IP, sb.Port, sb.Local)
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
		idx++
		if idx < len(ifs) {
			str += ", "
		}
	}
	str += "}"
	return str
}
