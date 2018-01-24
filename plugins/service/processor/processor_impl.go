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

	"github.com/contiv/vpp/plugins/contiv"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/service/configurator"
	"github.com/ligato/cn-infra/servicelabel"
)

// ServiceProcessor implements ServiceProcessorAPI.
type ServiceProcessor struct {
	Deps

	/* internal maps */
	services      map[svcmodel.ID]*Service
	localEps      map[podmodel.ID]*LocalEndpoint
	externalAddrs map[string]*ExternalAddress

	/* frontend addresses */
	frontendAddrs *configurator.IPAddresses

	/* local frontend and backend interfaces */
	frontendIfs configurator.Interfaces
	backendIfs  configurator.Interfaces
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	Contiv       contiv.API /* to get all interface names and pod IP network */
	Configurator configurator.ServiceConfiguratorAPI
}

// LocalEndpoint represents a node-local endpoint.
type LocalEndpoint struct {
	ifName   string
	svcCount int /* number of services running on this endpoint. */
}

// ExternalAddress represents IP address on which service(s) is/are exposed.
type ExternalAddress struct {
	address  net.IP
	svcCount int /* number of services exposed on this address */
}

// Init initializes service processor.
func (sp *ServiceProcessor) Init() error {
	sp.reset()
	return nil
}

// reset clears the state of the processor.
func (sp *ServiceProcessor) reset() error {
	sp.services = make(map[svcmodel.ID]*Service)
	sp.localEps = make(map[podmodel.ID]*LocalEndpoint)
	sp.externalAddrs = make(map[string]*ExternalAddress)
	sp.frontendAddrs = configurator.NewIPAddresses()
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

func (sp *ServiceProcessor) processDeletedPod(podID podmodel.ID) error {
	sp.Log.WithFields(logging.Fields{
		"podID": podID,
	}).Debug("ServiceProcessor - processDeletedPod()")

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

// configureService makes all the calls to configurator necessary to get K8s state
// data of a given service in-sync with VPP NAT configuration.
func (sp *ServiceProcessor) configureService(svc *Service, oldContivSvc *configurator.ContivService, oldBackends []podmodel.ID) error {
	var err error
	newContivSvc := svc.GetContivService()
	newBackends := svc.GetLocalBackends()
	newHasNodePort := (newContivSvc != nil && newContivSvc.HasNodePort())
	oldHasNodePort := (oldContivSvc != nil && oldContivSvc.HasNodePort())

	// Try to get Node IP.
	nodeIP := sp.Contiv.GetNodeIP()
	if nodeIP == nil {
		return errors.New("failed to get Node IP")
	}

	// Configure new frontend addresses.
	// -> handle enabled NodePort
	if newHasNodePort && !oldHasNodePort {
		if sp.extAddrUsageIncAndFetch(nodeIP, 1) == 1 {
			sp.frontendAddrs.Add(nodeIP)
			err = sp.Configurator.AddFrontendAddr(nodeIP)
			if err != nil {
				return err
			}
		}
	}
	// -> handle new External IPs
	if newContivSvc != nil {
		for _, newAddr := range newContivSvc.ExternalIPs.List() {
			new := true
			if oldContivSvc != nil {
				for _, oldAddr := range oldContivSvc.ExternalIPs.List() {
					if newAddr.Equal(oldAddr) {
						new = false
						break
					}
				}
			}
			if new {
				if sp.extAddrUsageIncAndFetch(newAddr, 1) == 1 {
					sp.frontendAddrs.Add(newAddr)
					err = sp.Configurator.AddFrontendAddr(newAddr)
					if err != nil {
						return err
					}
				}
			}
		}
	}

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

	// Unconfigure obsolete frontend addresses.
	// -> handle disabled NodePort
	if !newHasNodePort && oldHasNodePort {
		if sp.extAddrUsageIncAndFetch(nodeIP, -1) == 0 {
			sp.frontendAddrs.Del(nodeIP)
			err = sp.Configurator.DelFrontendAddr(nodeIP)
			if err != nil {
				return err
			}
		}
	}
	// -> handle removed External IPs
	if oldContivSvc != nil {
		for _, oldAddr := range oldContivSvc.ExternalIPs.List() {
			removed := true
			if newContivSvc != nil {
				for _, newAddr := range newContivSvc.ExternalIPs.List() {
					if newAddr.Equal(oldAddr) {
						removed = false
						break
					}
				}
			}
			if removed {
				if sp.extAddrUsageIncAndFetch(oldAddr, -1) == 0 {
					sp.frontendAddrs.Del(oldAddr)
					err = sp.Configurator.DelFrontendAddr(oldAddr)
					if err != nil {
						return err
					}
				}
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

func (sp *ServiceProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	sp.Log.WithFields(logging.Fields{
		"resyncEv": resyncEv,
	}).Debug("ServiceProcessor - processResyncEvent()")
	sp.reset()

	// Try to get Node IP.
	nodeIP := sp.Contiv.GetNodeIP()
	if nodeIP == nil {
		return errors.New("failed to get Node IP")
	}

	// Re-build the current state.
	confResyncEv := configurator.NewResyncEventData()

	// Fill up the set of frontend/backend interfaces and local endpoints.
	// -> physical interfaces
	for _, physIf := range sp.Contiv.GetPhysicalIfNames() {
		sp.frontendIfs.Add(physIf)
		sp.backendIfs.Add(physIf)
	}
	// -> VXLAN BVI interface
	vxlanBVIIf := sp.Contiv.GetVxlanBVIIfName()
	if vxlanBVIIf != "" {
		sp.frontendIfs.Add(vxlanBVIIf)
		sp.backendIfs.Add(vxlanBVIIf)
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

	// Iterate over services with complete data to get backend interfaces
	// and frontend addresses.
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
		// Add Node IP to the set of frontend IP addresses if service is of type NodePort.
		if contivSvc.HasNodePort() {
			sp.extAddrUsageIncAndFetch(nodeIP, 1)
			sp.frontendAddrs.Add(nodeIP)
		}
		// Add external IPs to the set of frontend IP addresses.
		for _, extAddr := range contivSvc.ExternalIPs.List() {
			sp.extAddrUsageIncAndFetch(extAddr, 1)
			sp.frontendAddrs.Add(extAddr)
		}
	}

	confResyncEv.FrontendAddrs = sp.frontendAddrs
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

func (sp *ServiceProcessor) extAddrUsageIncAndFetch(addr net.IP, increment int) int {
	addrStr := addr.String()
	if _, hasEntry := sp.externalAddrs[addrStr]; !hasEntry {
		sp.externalAddrs[addrStr] = &ExternalAddress{
			address:  addr,
			svcCount: 0,
		}
	}
	sp.externalAddrs[addrStr].svcCount += increment
	return sp.externalAddrs[addrStr].svcCount
}
