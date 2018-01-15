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

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/service/configurator"
)

// ServiceProcessor implements ServiceProcessorAPI.
type ServiceProcessor struct {
	Deps

	services map[svcmodel.ID]*Service
	localEps map[podmodel.ID]*LocalEndpoint

	/* local frontend and backend interfaces */
	frontendIfs configurator.Interfaces
	backendIfs  configurator.Interfaces
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	Contiv       contiv.API /* to get all interface names and pod IP network */
	Configurator configurator.ServiceConfiguratorAPI
}

// LocalEndpoint represents a node-local endpoint.
type LocalEndpoint struct {
	ifName   string
	svcCount uint /* number of services running on this endpoint. */
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
	svcID := svcmodel.ID{Namespace: eps.Namespace, Name: eps.Name}
	svc := sp.getService(svcID)
	svc.SetEndpoints(eps)
	return sp.configureService(svc, configurator.NewContivService(), []podmodel.ID{})
}

func (sp *ServiceProcessor) processUpdatedEndpoints(eps *epmodel.Endpoints) error {
	svcID := svcmodel.ID{Namespace: eps.Namespace, Name: eps.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetEndpoints(eps)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processDeletedEndpoints(epsID epmodel.ID) error {
	svcID := svcmodel.ID{Namespace: epsID.Namespace, Name: epsID.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetEndpoints(nil)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processNewService(service *svcmodel.Service) error {
	svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
	svc := sp.getService(svcID)
	svc.SetMetadata(service)
	return sp.configureService(svc, configurator.NewContivService(), []podmodel.ID{})
}

func (sp *ServiceProcessor) processUpdatedService(service *svcmodel.Service) error {
	svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetMetadata(service)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processDeletedService(serviceID svcmodel.ID) error {
	svcID := svcmodel.ID{Namespace: serviceID.Namespace, Name: serviceID.Name}
	svc := sp.getService(svcID)
	oldContivSvc := svc.GetContivService()
	oldBackends := svc.GetLocalBackends()
	svc.SetMetadata(nil)
	return sp.configureService(svc, oldContivSvc, oldBackends)
}

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

	if updateBackends {
		err = sp.Configurator.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
		sp.backendIfs = newBackendIfs
	}
	return err
}

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

func (sp *ServiceProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	// Store the previous state of services before reset.
	prevState := configurator.NewResyncEventData()
	prevState.FrontendIfs = sp.frontendIfs.Copy()
	prevState.BackendIfs = sp.backendIfs.Copy()
	for _, svc := range sp.services {
		contivSvc := svc.GetContivService()
		if contivSvc != nil {
			prevState.Services = append(prevState.Services, contivSvc)
		}
	}
	sp.reset()

	// Re-build the current state.
	curState := configurator.NewResyncEventData()

	// Fill up the set of frontends and local endpoints.
	for _, physIf := range sp.Contiv.GetPhysicalIfNames() {
		sp.frontendIfs.Add(physIf)
	}
	hostInterconnect := sp.Contiv.GetHostInterconnectIfName()
	if hostInterconnect != "" {
		sp.frontendIfs.Add(hostInterconnect)
	}

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

	// Iterate over services with complete data.
	for _, svc := range sp.services {
		contivSvc := svc.GetContivService()
		backends := svc.GetLocalBackends()
		if contivSvc != nil {
			curState.Services = append(curState.Services, contivSvc)
		}
		for _, backend := range backends {
			localEp := sp.getLocalEndpoint(backend)
			localEp.svcCount++
			if localEp.ifName != "" {
				sp.backendIfs.Add(localEp.ifName)
			}
		}
	}

	curState.FrontendIfs = sp.frontendIfs
	curState.BackendIfs = sp.backendIfs
	return sp.Configurator.Resync(prevState, curState)
}

// Close deallocates resource held by the processor.
func (sp *ServiceProcessor) Close() error {
	return nil
}
