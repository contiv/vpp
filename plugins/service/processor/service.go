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

	"github.com/contiv/vpp/plugins/ipnet"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/service/renderer"
)

// Service is used to combine data from the service model with the endpoints.
type Service struct {
	sp            *ServiceProcessor
	meta          *svcmodel.Service
	endpoints     *epmodel.Endpoints
	contivSvc     *renderer.ContivService
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
func (s *Service) GetContivService() *renderer.ContivService {
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

	s.contivSvc = renderer.NewContivService()
	s.localBackends = []podmodel.ID{}

	s.contivSvc.ID = svcmodel.GetID(s.meta)
	if s.meta.ExternalTrafficPolicy == "Local" {
		s.contivSvc.TrafficPolicy = renderer.NodeLocal
	} else {
		s.contivSvc.TrafficPolicy = renderer.ClusterWide
	}

	if s.meta.SessionAffinity == "ClientIP" {
		s.contivSvc.SessionAffinityTimeout = s.meta.SessionAffinityTimeout
	}

	// Collect all IP addresses on which the service should be exposed.
	if s.meta.ClusterIp != "" && s.meta.ClusterIp != "None" {
		clusterIP := net.ParseIP(s.meta.ClusterIp)
		if clusterIP != nil {
			s.contivSvc.ClusterIPs.Add(clusterIP)
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

	if s.meta.ServiceType == "LoadBalancer" {
		for _, lbIngressIPStr := range s.meta.LbIngressIps {
			lbIngressIP := net.ParseIP(lbIngressIPStr)
			if lbIngressIP != nil {
				s.contivSvc.ExternalIPs.Add(lbIngressIP)
			} else {
				s.sp.Log.WithFields(logging.Fields{
					"service":     s.contivSvc.ID,
					"LBIngressIP": lbIngressIPStr,
				}).Warn("Failed to parse LB Ingress IP")
			}
		}
	}

	// Fill up the map of service ports.
	for _, port := range s.meta.Port {
		sp := &renderer.ServicePort{
			Port:     uint16(port.GetPort()),
			NodePort: uint16(port.GetNodePort()),
		}
		if port.GetProtocol() == "TCP" {
			sp.Protocol = renderer.TCP
		} else {
			sp.Protocol = renderer.UDP
		}
		s.contivSvc.Ports[port.Name] = sp
	}

	// Fill up the map of service backends.
	for port := range s.contivSvc.Ports {
		s.contivSvc.Backends[port] = []*renderer.ServiceBackend{}
	}
	for _, epSubSet := range s.endpoints.GetEndpointSubsets() {
		epPorts := epSubSet.GetPorts()
		epAddrs := epSubSet.GetAddresses()
		for _, epAddr := range epAddrs {
			var local bool
			var hostNetwork bool
			epIP := net.ParseIP(epAddr.GetIp())
			if epIP == nil {
				s.sp.Log.WithFields(logging.Fields{
					"service":    s.contivSvc.ID,
					"endpointIP": epAddr.GetIp(),
				}).Warn("Failed to parse endpoint IP")
				continue
			}
			if redirIP, isRedirected := s.sp.epRedirects[epAddr.GetIp()]; isRedirected {
				epIP = net.ParseIP(redirIP)
			}
			if s.sp.IPAM.PodSubnetThisNode(ipnet.DefaultPodNetworkName).Contains(epIP) {
				local = true
			}
			if !s.sp.IPAM.PodSubnetAllNodes(ipnet.DefaultPodNetworkName).Contains(epIP) {
				hostNetwork = true
				if s.isLocalNodeOrHostIP(epIP) {
					local = true
				}
			}

			for _, epPort := range epPorts {
				port := epPort.GetName()
				if _, exposedPort := s.contivSvc.Ports[port]; exposedPort {
					sb := &renderer.ServiceBackend{}
					sb.IP = epIP
					sb.Port = uint16(epPort.GetPort())
					sb.Local = local
					sb.HostNetwork = hostNetwork
					s.contivSvc.Backends[port] = append(s.contivSvc.Backends[port], sb)
				}
			}
			if local {
				// Get target pod and add it to the set of local backends.
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

// isLocalNodeOrHostIP returns true if the given IP is current node's node (VPP) or host (mgmt) IP, false otherwise.
func (s *Service) isLocalNodeOrHostIP(ip net.IP) bool {
	nodeIP, _ := s.sp.IPNet.GetNodeIP()
	if ip.Equal(nodeIP) {
		return true
	}
	for _, hostIP := range s.sp.IPNet.GetHostIPs() {
		if hostIP.Equal(ip) {
			return true
		}
	}
	return false
}
