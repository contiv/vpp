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
	"errors"
	"net"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"

	"github.com/contiv/vpp/plugins/contiv"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/service/configurator"
)

// ServiceProcessor implements ServiceProcessorAPI.
type ServiceProcessor struct {
	Deps

	nodeInternalIP net.IP

	/* internal maps */
	services map[svcmodel.ID]*Service
	localEps map[podmodel.ID]*LocalEndpoint

	/* local frontend and backend interfaces */
	frontendIfs configurator.Interfaces
	backendIfs  configurator.Interfaces
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	Contiv       contiv.API         /* to get all interface names and pod IP network */
	VPP          defaultplugins.API /* interface IP addresses */
	Configurator configurator.ServiceConfiguratorAPI
}

// LocalEndpoint represents a node-local endpoint.
type LocalEndpoint struct {
	ifName   string
	svcCount int /* number of services running on this endpoint. */
}

// Init initializes service processor.
func (sp *ServiceProcessor) Init() error {
	sp.reset()
	sp.Contiv.RegisterPodPreRemovalHook(sp.processDeletingPod)
	return nil
}

// reset clears the state of the processor.
func (sp *ServiceProcessor) reset() error {
	sp.services = make(map[svcmodel.ID]*Service)
	sp.localEps = make(map[podmodel.ID]*LocalEndpoint)
	sp.frontendIfs = configurator.NewInterfaces()
	sp.backendIfs = configurator.NewInterfaces()
	return nil
}

// Update processes a datasync change event associated with the state data
// of K8s pods, endpoints and services.
// The data change is stored into the cache and the configurator
// is notified about any changes related to services that need to be reflected
// in the VPP NAT configuration.
func (sp *ServiceProcessor) Update(dataChngEv datasync.ChangeEvent) error {
	return sp.propagateDataChangeEv(dataChngEv)
}

// Resync processes a datasync resync event associated with the state data
// of K8s pods, endpoints and services.
// The cache content is fully replaced and the configurator receives a full
// snapshot of Contiv Services at the present state to be (re)installed.
func (sp *ServiceProcessor) Resync(resyncEv datasync.ResyncEvent) error {
	resyncEvData := sp.parseResyncEv(resyncEv)
	return sp.processResyncEvent(resyncEvData)
}

func (sp *ServiceProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	sp.Log.WithFields(logging.Fields{
		"pod": *pod,
	}).Debug("ServiceProcessor - processUpdatedPod()")

	if pod.IpAddress == "" {
		return nil
	}
	podIPAddress := net.ParseIP(pod.IpAddress)
	if podIPAddress == nil || !sp.Contiv.GetPodNetwork().Contains(podIPAddress) {
		/* ignore pods deployed on other nodes */
		return nil
	}

	podID := podmodel.ID{Name: pod.Name, Namespace: pod.Namespace}
	localEp := sp.getLocalEndpoint(podID)
	if localEp.ifName != "" {
		/* already processed */
		return nil
	}
	ifName, ifExists := sp.Contiv.GetIfName(podID.Namespace, podID.Name)
	if !ifExists {
		sp.Log.WithFields(logging.Fields{
			"pod-ns":   podID.Namespace,
			"pod-name": podID.Name,
		}).Warn("Failed to get pod interface name")
		return nil
	}

	localEp.ifName = ifName
	if localEp.svcCount > 0 {
		newBackendIfs := sp.backendIfs.Copy()
		newBackendIfs.Add(ifName)
		sp.Configurator.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
		sp.backendIfs = newBackendIfs
	}
	newFrontendIfs := sp.frontendIfs.Copy()
	newFrontendIfs.Add(ifName)
	sp.Configurator.UpdateLocalFrontendIfs(sp.frontendIfs, newFrontendIfs)
	sp.frontendIfs = newFrontendIfs
	return nil
}

func (sp *ServiceProcessor) processDeletingPod(podNamespace string, podName string) error {
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	sp.Log.WithFields(logging.Fields{
		"podID": podID,
	}).Debug("ServiceProcessor - processDeletingPod()")

	localEp, hasEntry := sp.localEps[podID]
	if !hasEntry {
		return nil
	}
	ifName := sp.localEps[podID].ifName
	if ifName == "" {
		return nil
	}

	if localEp.svcCount > 0 {
		newBackendIfs := sp.backendIfs.Copy()
		newBackendIfs.Del(ifName)
		sp.Configurator.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
		sp.backendIfs = newBackendIfs
	}
	newFrontendIfs := sp.frontendIfs.Copy()
	newFrontendIfs.Del(ifName)
	sp.Configurator.UpdateLocalFrontendIfs(sp.frontendIfs, newFrontendIfs)
	sp.frontendIfs = newFrontendIfs
	delete(sp.localEps, podID)
	return nil
}

func (sp *ServiceProcessor) processNewEndpoints(eps *epmodel.Endpoints) error {
	sp.Log.WithFields(logging.Fields{
		"eps": *eps,
	}).Debug("ServiceProcessor - processNewEndpoints()")

	svcID := svcmodel.ID{Namespace: eps.Namespace, Name: eps.Name}
	svc := sp.getService(svcID)
	svc.SetEndpoints(eps)
	return sp.configureService(svc, nil, []podmodel.ID{})
}

func (sp *ServiceProcessor) processUpdatedEndpoints(eps *epmodel.Endpoints) error {
	sp.Log.WithFields(logging.Fields{
		"eps": *eps,
	}).Debug("ServiceProcessor - processUpdatedEndpoints()")

	svcID := svcmodel.ID{Namespace: eps.Namespace, Name: eps.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetEndpoints(eps)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processDeletedEndpoints(epsID epmodel.ID) error {
	sp.Log.WithFields(logging.Fields{
		"epsID": epsID,
	}).Debug("ServiceProcessor - processDeletedEndpoints()")

	svcID := svcmodel.ID{Namespace: epsID.Namespace, Name: epsID.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetEndpoints(nil)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processNewService(service *svcmodel.Service) error {
	sp.Log.WithFields(logging.Fields{
		"service": *service,
	}).Debug("ServiceProcessor - processNewService()")

	svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
	svc := sp.getService(svcID)
	svc.SetMetadata(service)
	return sp.configureService(svc, nil, []podmodel.ID{})
}

func (sp *ServiceProcessor) processUpdatedService(service *svcmodel.Service) error {
	sp.Log.WithFields(logging.Fields{
		"service": *service,
	}).Debug("ServiceProcessor - processUpdatedService()")

	svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetMetadata(service)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processDeletedService(serviceID svcmodel.ID) error {
	sp.Log.WithFields(logging.Fields{
		"serviceID": serviceID,
	}).Debug("ServiceProcessor - processDeletedService()")

	svcID := svcmodel.ID{Namespace: serviceID.Namespace, Name: serviceID.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetMetadata(nil)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processNewNode(node *nodemodel.Node) error {
	sp.Log.WithFields(logging.Fields{
		"node": *node,
	}).Debug("ServiceProcessor - processNewNode()")

	nodeInternalIP := sp.getNodeInternalIP(node)
	if nodeInternalIP != nil {
		sp.nodeInternalIP = nodeInternalIP
		sp.reconfigureNodePorts()
	}
	return nil
}

func (sp *ServiceProcessor) processUpdatedNode(node *nodemodel.Node) error {
	sp.Log.WithFields(logging.Fields{
		"node": *node,
	}).Debug("ServiceProcessor - processUpdatedNode()")

	nodeInternalIP := sp.getNodeInternalIP(node)
	if nodeInternalIP != nil {
		if sp.nodeInternalIP == nil || !sp.nodeInternalIP.Equal(nodeInternalIP) {
			// added/changed node IP
			sp.nodeInternalIP = nodeInternalIP
			sp.reconfigureNodePorts()
		}
	} else if sp.nodeInternalIP != nil {
		// lost node IP
		sp.nodeInternalIP = nil
		sp.reconfigureNodePorts()
	}
	return nil
}

// configureService makes all the calls to configurator necessary to get K8s state
// data of a given service in-sync with VPP NAT configuration.
func (sp *ServiceProcessor) configureService(svc *Service, oldContivSvc *configurator.ContivService, oldBackends []podmodel.ID) error {
	var err error
	newContivSvc := svc.GetContivService()
	newBackends := svc.GetLocalBackends()

	// Configure service.
	if newContivSvc != nil {
		if oldContivSvc == nil {
			err = sp.Configurator.AddService(newContivSvc)
			if err != nil {
				return err
			}
		} else {
			err = sp.Configurator.UpdateService(oldContivSvc, newContivSvc)
			if err != nil {
				return err
			}
		}
	} else {
		if oldContivSvc != nil {
			err = sp.Configurator.DeleteService(oldContivSvc)
			if err != nil {
				return err
			}
		}
	}

	// Configure local Backends.
	newBackendIfs := sp.backendIfs.Copy()
	updateBackends := false
	// -> handle new backend interfaces
	for _, newBackend := range newBackends {
		new := true
		for _, oldBackend := range oldBackends {
			if newBackend == oldBackend {
				new = false
				break
			}
		}
		if new {
			localEp := sp.getLocalEndpoint(newBackend)
			localEp.svcCount++
			if localEp.ifName != "" && localEp.svcCount == 1 {
				newBackendIfs.Add(localEp.ifName)
				updateBackends = true
			}
		}
	}
	// -> handle removed backend interfaces
	for _, oldBackend := range oldBackends {
		removed := true
		for _, newBackend := range newBackends {
			if newBackend == oldBackend {
				removed = false
				break
			}
		}
		if removed {
			localEp := sp.getLocalEndpoint(oldBackend)
			localEp.svcCount--
			if localEp.ifName != "" && localEp.svcCount == 0 {
				newBackendIfs.Del(localEp.ifName)
				updateBackends = true
			}
		}
	}
	// -> update local backends
	if updateBackends {
		err = sp.Configurator.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
		sp.backendIfs = newBackendIfs
	}

	return err
}

// reconfigureNodePorts reconfigures all services with a node port.
func (sp *ServiceProcessor) reconfigureNodePorts() error {
	sp.Log.Debug("ServiceProcessor - reconfigureNodePorts()")

	var npServices []*configurator.ContivService
	for _, svc := range sp.services {
		contivSvc := svc.GetContivService()
		if contivSvc == nil {
			continue
		}
		if contivSvc.HasNodePort() {
			npServices = append(npServices, contivSvc)
		}
	}
	return sp.Configurator.UpdateNodePortServices(sp.nodeInternalIP, npServices)
}

func (sp *ServiceProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	sp.Log.WithFields(logging.Fields{
		"resyncEv": resyncEv,
	}).Debug("ServiceProcessor - processResyncEvent()")
	sp.reset()

	// Re-build the current state.
	confResyncEv := configurator.NewResyncEventData()
	confResyncEv.NodeInternalIP = resyncEv.NodeInternalIP

	// Try to get Node IP.
	nodeIP, nodeNet := sp.Contiv.GetNodeIP()
	if nodeIP == nil {
		return errors.New("failed to get Node IP")
	}

	// Get default gateway IP address.
	gwIP := sp.Contiv.GetDefaultGatewayIP()

	// Fill up the set of frontend/backend interfaces and local endpoints.
	// With physical interfaces also build SNAT configuration.
	// -> VXLAN BVI interface
	vxlanBVIIf := sp.Contiv.GetVxlanBVIIfName()
	if vxlanBVIIf != "" {
		sp.frontendIfs.Add(vxlanBVIIf)
		sp.backendIfs.Add(vxlanBVIIf)
	}
	// -> main physical interfaces
	mainPhysIf := sp.Contiv.GetMainPhysicalIfName()
	if mainPhysIf != "" {
		sp.frontendIfs.Add(mainPhysIf)
		if vxlanBVIIf == "" {
			sp.backendIfs.Add(mainPhysIf)
		}
		if sp.Contiv.NatExternalTraffic() && vxlanBVIIf != "" && gwIP != nil {
			// If the interface connects node with the default GW, SNAT all egress traffic.
			// For main interface this is supported only with VXLANs enabled.
			if nodeNet.Contains(gwIP) {
				confResyncEv.ExternalSNAT.ExternalIfName = mainPhysIf
				confResyncEv.ExternalSNAT.ExternalIP = nodeIP
			}
		}
	}
	// -> other physical interfaces
	for _, physIf := range sp.Contiv.GetOtherPhysicalIfNames() {
		ipAddresses := sp.getInterfaceIPs(physIf)
		sp.frontendIfs.Add(physIf)
		// If the interface connects node with the default GW, SNAT all egress traffic.
		if sp.Contiv.NatExternalTraffic() && gwIP != nil {
			for _, ipAddr := range ipAddresses {
				if ipAddr.Network.Contains(gwIP) {
					confResyncEv.ExternalSNAT.ExternalIfName = physIf
					confResyncEv.ExternalSNAT.ExternalIP = ipAddr.IP
					break
				}
			}
		}
	}
	// -> host interconnect
	hostInterconnect := sp.Contiv.GetHostInterconnectIfName()
	if hostInterconnect != "" {
		sp.frontendIfs.Add(hostInterconnect)
		sp.backendIfs.Add(hostInterconnect)
	}
	// -> pods
	for _, pod := range resyncEv.Pods {
		podID := podmodel.ID{Name: pod.Name, Namespace: pod.Namespace}
		if pod.IpAddress == "" {
			continue
		}
		podIPAddress := net.ParseIP(pod.IpAddress)
		if podIPAddress == nil || !sp.Contiv.GetPodNetwork().Contains(podIPAddress) {
			continue
		}
		ifName, ifExists := sp.Contiv.GetIfName(podID.Namespace, podID.Name)
		if !ifExists {
			sp.Log.WithFields(logging.Fields{
				"pod-ns":   podID.Namespace,
				"pod-name": podID.Name,
			}).Warn("Failed to get pod interface name")
			continue
		}
		localEp := sp.getLocalEndpoint(podID)
		localEp.ifName = ifName
		sp.frontendIfs.Add(ifName)
	}

	// Combine the service metadata with endpoints.
	for _, eps := range resyncEv.Endpoints {
		svcID := svcmodel.ID{Namespace: eps.Namespace, Name: eps.Name}
		svc := sp.getService(svcID)
		svc.SetEndpoints(eps)
	}
	for _, service := range resyncEv.Services {
		svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
		svc := sp.getService(svcID)
		svc.SetMetadata(service)
	}

	// Iterate over services with complete data to get backend interfaces.
	for _, svc := range sp.services {
		contivSvc := svc.GetContivService()
		backends := svc.GetLocalBackends()
		if contivSvc == nil {
			continue
		}
		confResyncEv.Services = append(confResyncEv.Services, contivSvc)
		for _, backend := range backends {
			localEp := sp.getLocalEndpoint(backend)
			localEp.svcCount++
			if localEp.ifName != "" {
				sp.backendIfs.Add(localEp.ifName)
			}
		}
	}

	confResyncEv.FrontendIfs = sp.frontendIfs
	confResyncEv.BackendIfs = sp.backendIfs
	return sp.Configurator.Resync(confResyncEv)
}

// Close deallocates resource held by the processor.
func (sp *ServiceProcessor) Close() error {
	return nil
}

/**** Helper methods ****/

func (sp *ServiceProcessor) getService(svcID svcmodel.ID) *Service {
	_, hasEntry := sp.services[svcID]
	if !hasEntry {
		sp.services[svcID] = NewService(sp)
	}
	return sp.services[svcID]
}

func (sp *ServiceProcessor) getLocalEndpoint(podID podmodel.ID) *LocalEndpoint {
	_, hasEntry := sp.localEps[podID]
	if !hasEntry {
		sp.localEps[podID] = &LocalEndpoint{}
	}
	return sp.localEps[podID]
}

// InterfaceIPAddress encapsulates interface IP address and the network implied by the IP
// and prefix length.
type InterfaceIPAddress struct {
	IP      net.IP
	Network *net.IPNet
}

// getInterfaceIPs returns all IP addresses the interface has assigned.
func (sp *ServiceProcessor) getInterfaceIPs(ifName string) []InterfaceIPAddress {
	networks := []InterfaceIPAddress{}
	_, meta, exists := sp.VPP.GetSwIfIndexes().LookupIdx(ifName)
	if !exists || meta == nil {
		sp.Log.WithFields(logging.Fields{
			"ifName": ifName,
		}).Warn("failed to get interface metadata")
		return networks
	}
	for _, ipAddr := range meta.IpAddresses {
		ip, ipNet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			sp.Log.WithFields(logging.Fields{
				"ifName": ifName,
				"err":    err,
			}).Warn("failed to parse interface IP")
			continue
		}
		networks = append(networks, InterfaceIPAddress{IP: ip, Network: ipNet})
	}
	return networks
}

// getNodeInternalIP extracts internal node IP from the K8s node data.
func (sp *ServiceProcessor) getNodeInternalIP(node *nodemodel.Node) net.IP {
	var internalIP string
	for i := range node.Addresses {
		if node.Addresses[i].Type == nodemodel.NodeAddress_NodeInternalIP {
			internalIP = node.Addresses[i].Address
			return net.ParseIP(internalIP)
		}
	}
	return nil
}
