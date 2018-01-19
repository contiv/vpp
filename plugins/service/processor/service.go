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
	"net"

	"github.com/ligato/cn-infra/logging"

	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/service/configurator"
)

// Service is used to combine data from the service model with the endpoints.
type Service struct {
	sp            *ServiceProcessor
	meta          *svcmodel.Service
	endpoints     *epmodel.Endpoints
	contivSvc     *configurator.ContivService
	localBackends []podmodel.ID
	refreshed     bool
}

// NewService is a constructor for Service.
func NewService(sp *ServiceProcessor) *Service {
	return &Service{
		sp:            sp,
		localBackends: []podmodel.ID{},
	}
}

// SetMetadata initializes or changes metadata for the service.
func (s *Service) SetMetadata(meta *svcmodel.Service) {
	s.meta = meta
	s.refreshed = false
}

// SetEndpoints initializes or changes endpoints for the service.
func (s *Service) SetEndpoints(endpoints *epmodel.Endpoints) {
	s.endpoints = endpoints
	s.refreshed = false
}

// GetContivService returns the service data represented as ContivService.
// Returns nil if there are not enough available data.
func (s *Service) GetContivService() *configurator.ContivService {
	if !s.refreshed {
		s.Refresh()
	}
	return s.contivSvc
}

// GetLocalBackends returns the set of IDs od all local backends of this service.
// Returns empty array if there are not enough available data.
func (s *Service) GetLocalBackends() []podmodel.ID {
	if !s.refreshed {
		s.Refresh()
	}
	return s.localBackends
}

// Refresh combines metadata with endpoints to get ContivService representation
// and the list of local backends.
func (s *Service) Refresh() {
	if s.meta == nil || s.endpoints == nil {
		s.contivSvc = nil
		s.localBackends = []podmodel.ID{}
		s.refreshed = true
		return
	}

	s.contivSvc = configurator.NewContivService()
	s.localBackends = []podmodel.ID{}

	s.contivSvc.ID = svcmodel.GetID(s.meta)
	if s.meta.ExternalTrafficPolicy != "Local" {
		s.contivSvc.SNAT = true
	}

	// Collect all IP addresses on which the service should be exposed.
	if s.meta.ClusterIp != "" && s.meta.ClusterIp != "None" {
		clusterIP := net.ParseIP(s.meta.ClusterIp)
		if clusterIP != nil {
			s.contivSvc.ExternalIPs.Add(clusterIP)
		} else {
			s.sp.Log.WithFields(logging.Fields{
				"service":   s.contivSvc.ID,
				"clusterIP": clusterIP,
			}).Warn("Failed to parse clusterIP")
		}
	}

	for _, externalIPStr := range s.meta.ExternalIps {
		externalIP := net.ParseIP(externalIPStr)
		if externalIP != nil {
			s.contivSvc.ExternalIPs.Add(externalIP)
		} else {
			s.sp.Log.WithFields(logging.Fields{
				"service":    s.contivSvc.ID,
				"externalIP": externalIPStr,
			}).Warn("Failed to parse external IP")
		}
	}

	// Fill up the map of service ports.
	for _, port := range s.meta.Port {
		sp := &configurator.ServicePort{
			Port:     uint16(port.GetPort()),
			NodePort: uint16(port.GetNodePort()),
		}
		if port.GetProtocol() == "TCP" {
			sp.Protocol = configurator.TCP
		} else {
			sp.Protocol = configurator.UDP
		}
		s.contivSvc.Ports[port.Name] = sp
	}

	// Fill up the map of service backends.
	for port := range s.contivSvc.Ports {
		s.contivSvc.Backends[port] = []*configurator.ServiceBackend{}
	}
	for _, epSubSet := range s.endpoints.GetEndpointSubsets() {
		epPorts := epSubSet.GetPorts()
		epAddrs := epSubSet.GetAddresses()
		for _, epAddr := range epAddrs {
			var local bool
			epIP := net.ParseIP(epAddr.GetIp())
			if epIP == nil {
				s.sp.Log.WithFields(logging.Fields{
					"service":    s.contivSvc.ID,
					"endpointIP": epAddr.GetIp(),
				}).Warn("Failed to parse endpoint IP")
				continue
			}
			if epAddr.GetNodeName() == "" || epAddr.GetNodeName() == s.sp.ServiceLabel.GetAgentLabel() {
				local = true
			}
			for _, epPort := range epPorts {
				port := epPort.GetName()
				if _, exposedPort := s.contivSvc.Ports[port]; exposedPort {
					sb := &configurator.ServiceBackend{}
					sb.IP = epIP
					sb.Port = uint16(epPort.GetPort())
					sb.Local = local
					s.contivSvc.Backends[port] = append(s.contivSvc.Backends[port], sb)
				}
			}
			if local {
				// Get interface name and add it to the set of local backends.
				targetPod := epAddr.GetTargetRef()
				if targetPod.GetKind() == "Pod" {
					s.localBackends = append(s.localBackends,
						podmodel.ID{Name: targetPod.GetName(), Namespace: targetPod.GetNamespace()})
				}
			}
		}
	}

	s.refreshed = true
}
