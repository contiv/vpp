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

	// UpdateFrontends updates the list of interfaces with the enabled out2in
	// VPP/NAT feature.
	UpdateFrontends(oldIfNames []string, newIfNames []string) error

	// UpdateBackends updates the list of interfaces with the enabled in2out
	// VPP/NAT feature.
	UpdateBackends(oldIfNames []string, newIfNames []string) error

	// Resync completely replaces the current NAT configuration with the provided
	// full state of K8s services.
	Resync(services []*ContivService, frontends []string, backendIfs []string) error
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

	// ExternalIPs is a list of all IP addresses on which the service
	// should be exposed on this node.
	ExternalIPs []net.IP

	// Backends map external service ports with corresponding backends.
	Backends map[uint16] /*service port*/ ServiceBackend
}

// String converts ContivService into a human-readable string.
func (cs ContivService) String() string {
	return "TODO"
}

// ServiceBackend represents a single service backend.
type ServiceBackend struct {
	IP    net.IP /* internal IP address of the backend */
	Port  uint16 /* backend-local port on which the service listens */
	Local bool   /* true if the backend is installed on this node */
}

// String converts Backend into a human-readable string.
func (sb ServiceBackend) String() string {
	return "TODO"
}
