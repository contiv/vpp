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
	"strings"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipv4net"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/contivconf"
)

// ServiceProcessor implements ServiceProcessorAPI.
type ServiceProcessor struct {
	Deps

	renderers []renderer.ServiceRendererAPI

	/* internal maps */
	services map[svcmodel.ID]*Service
	localEps map[podmodel.ID]*LocalEndpoint

	/* local frontend and backend interfaces */
	frontendIfs renderer.Interfaces
	backendIfs  renderer.Interfaces
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	NodeSync     nodesync.API
	PodManager   podmanager.API
	IPAM         ipam.API
	IPv4Net      ipv4net.API
}

// LocalEndpoint represents a node-local endpoint.
type LocalEndpoint struct {
	ifName   string
	svcCount int /* number of services running on this endpoint. */
}

// Init initializes service processor.
func (sp *ServiceProcessor) Init() error {
	sp.reset()
	return nil
}

// AfterInit does nothing for the processor.
func (sp *ServiceProcessor) AfterInit() error {
	return nil
}

// reset clears the state of the processor.
func (sp *ServiceProcessor) reset() error {
	sp.services = make(map[svcmodel.ID]*Service)
	sp.localEps = make(map[podmodel.ID]*LocalEndpoint)
	sp.frontendIfs = renderer.NewInterfaces()
	sp.backendIfs = renderer.NewInterfaces()
	return nil
}

// Update is called for:
//  - KubeStateChange for service-related data
//  - AddPod & DeletePod
//  - NodeUpdate event
func (sp *ServiceProcessor) Update(event controller.Event) error {
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		return sp.propagateDataChangeEv(ksChange)
	}

	if addPod, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return sp.ProcessNewPod(addPod.Pod.Namespace, addPod.Pod.Name)
	}
	if deletePod, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return sp.ProcessDeletingPod(deletePod.Pod.Namespace, deletePod.Pod.Name)
	}

	if _, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return sp.renderNodePorts()
	}

	return nil
}

// Revert is called for failed AddPod event.
func (sp *ServiceProcessor) Revert(event controller.Event) error {
	if addPod, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return sp.ProcessDeletingPod(addPod.Pod.Namespace, addPod.Pod.Name)
	}
	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv Services at the present state to be
// (re)installed.
func (sp *ServiceProcessor) Resync(kubeStateData controller.KubeStateData) error {
	resyncEvData := sp.parseResyncEv(kubeStateData)
	return sp.processResyncEvent(resyncEvData)
}

// RegisterRenderer registers a new service renderer.
// The renderer will be receiving updates for all services on the cluster.
func (sp *ServiceProcessor) RegisterRenderer(renderer renderer.ServiceRendererAPI) error {
	sp.renderers = append(sp.renderers, renderer)
	return nil
}

// ProcessNewPod is called when connectivity to pod is being established.
func (sp *ServiceProcessor) ProcessNewPod(podNamespace string, podName string) error {
	sp.Log.WithFields(logging.Fields{
		"name":      podName,
		"namespace": podNamespace,
	}).Debug("ServiceProcessor - processNewPod()")
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}

	localEp := sp.getLocalEndpoint(podID)

	ifName, ifExists := sp.IPv4Net.GetIfName(podID.Namespace, podID.Name)
	if !ifExists {
		sp.Log.WithFields(logging.Fields{
			"pod-ns":   podID.Namespace,
			"pod-name": podID.Name,
		}).Warn("Failed to get pod interface name")
		return nil
	}

	localEp.ifName = ifName

	newFrontendIfs := sp.frontendIfs.Copy()
	newFrontendIfs.Add(ifName)
	for _, renderer := range sp.renderers {
		err := renderer.UpdateLocalFrontendIfs(sp.frontendIfs, newFrontendIfs)
		if err != nil {
			return err
		}
	}
	sp.frontendIfs = newFrontendIfs
	return nil
}

// ProcessDeletingPod is called during pod removal.
func (sp *ServiceProcessor) ProcessDeletingPod(podNamespace string, podName string) error {
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
		for _, renderer := range sp.renderers {
			/* ignore errors */
			renderer.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
		}
		sp.backendIfs = newBackendIfs
	}
	newFrontendIfs := sp.frontendIfs.Copy()
	newFrontendIfs.Del(ifName)
	for _, renderer := range sp.renderers {
		/* ignore errors */
		renderer.UpdateLocalFrontendIfs(sp.frontendIfs, newFrontendIfs)
	}
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
	return sp.renderService(svc, nil, []podmodel.ID{})
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
	return sp.renderService(svc, oldContivSvc, oldBackends)
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
	return sp.renderService(svc, oldContivSvc, oldBackends)
}

func (sp *ServiceProcessor) processNewService(service *svcmodel.Service) error {
	sp.Log.WithFields(logging.Fields{
		"service": *service,
	}).Debug("ServiceProcessor - processNewService()")

	svcID := svcmodel.ID{Namespace: service.Namespace, Name: service.Name}
	svc := sp.getService(svcID)
	svc.SetMetadata(service)
	return sp.renderService(svc, nil, []podmodel.ID{})
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
	return sp.renderService(svc, oldContivSvc, oldBackends)
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
	return sp.renderService(svc, oldContivSvc, oldBackends)
}

// renderService reacts to added/removed/changed service.
func (sp *ServiceProcessor) renderService(svc *Service, oldContivSvc *renderer.ContivService,
	oldBackends []podmodel.ID) error {

	var err error
	newContivSvc := svc.GetContivService()
	newBackends := svc.GetLocalBackends()

	// Render service.
	if newContivSvc != nil {
		if oldContivSvc == nil {
			for _, renderer := range sp.renderers {
				if err = renderer.AddService(newContivSvc); err != nil {
					return err
				}
			}
		} else {
			for _, renderer := range sp.renderers {
				if err = renderer.UpdateService(oldContivSvc, newContivSvc); err != nil {
					return err
				}
			}
		}
	} else {
		if oldContivSvc != nil {
			for _, renderer := range sp.renderers {
				if err = renderer.DeleteService(oldContivSvc); err != nil {
					return err
				}
			}
		}
	}

	// Render local Backends.
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
		for _, renderer := range sp.renderers {
			err = renderer.UpdateLocalBackendIfs(sp.backendIfs, newBackendIfs)
			if err != nil {
				return err
			}
		}
		sp.backendIfs = newBackendIfs
	}

	return err
}

// renderNodePorts re-renders all services with a node port.
func (sp *ServiceProcessor) renderNodePorts() error {
	sp.Log.Debug("ServiceProcessor - renderNodePorts()")

	var npServices []*renderer.ContivService
	for _, svc := range sp.services {
		contivSvc := svc.GetContivService()
		if contivSvc == nil {
			continue
		}
		if contivSvc.HasNodePort() {
			npServices = append(npServices, contivSvc)
		}
	}
	for _, renderer := range sp.renderers {
		err := renderer.UpdateNodePortServices(sp.getNodeIPs(), npServices)
		if err != nil {
			return err
		}
	}
	return nil
}

// getNodeIPs returns a slice of IP addresses of all nodes in the cluster
// without duplicities.
func (sp *ServiceProcessor) getNodeIPs() *renderer.IPAddresses {
	nodeIPs := renderer.NewIPAddresses()

	for _, node := range sp.NodeSync.GetAllNodes() {
		for _, vppIP := range node.VppIPAddresses {
			nodeIPs.Add(vppIP.Address)
		}
		for _, mgmtIP := range node.MgmtIPAddresses {
			nodeIPs.Add(mgmtIP)
		}
	}

	return nodeIPs
}

func (sp *ServiceProcessor) trimIPAddrPrefix(ip string) string {
	if strings.Contains(ip, "/") {
		return ip[:strings.Index(ip, "/")]
	}
	return ip
}

func (sp *ServiceProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	sp.reset()

	// Re-build the current state.
	confResyncEv := renderer.NewResyncEventData()

	// Collect IP addresses of all nodes in the cluster.
	confResyncEv.NodeIPs = sp.getNodeIPs()

	// Fill up the set of frontend/backend interfaces and local endpoints.
	// With physical interfaces also build SNAT configuration.
	// -> VXLAN BVI interface
	vxlanBVIIf := sp.IPv4Net.GetVxlanBVIIfName()
	if vxlanBVIIf != "" {
		sp.frontendIfs.Add(vxlanBVIIf)
		sp.backendIfs.Add(vxlanBVIIf)
	}
	// -> main physical interfaces
	mainPhysIf := sp.ContivConf.GetMainInterfaceName()
	if mainPhysIf != "" {
		if vxlanBVIIf == "" {
			sp.backendIfs.Add(mainPhysIf)
		}
		sp.frontendIfs.Add(mainPhysIf)
	}
	// -> other physical interfaces
	for _, physIf := range sp.ContivConf.GetOtherVPPInterfaces() {
		sp.frontendIfs.Add(physIf.InterfaceName)
	}
	// -> host interconnect
	hostInterconnect := sp.IPv4Net.GetHostInterconnectIfName()
	if hostInterconnect != "" {
		sp.frontendIfs.Add(hostInterconnect)
		sp.backendIfs.Add(hostInterconnect)
	}
	// -> pods
	for _, podID := range resyncEv.Pods {
		// -> pod interface
		ifName, ifExists := sp.IPv4Net.GetIfName(podID.Namespace, podID.Name)
		if !ifExists {
			// not an error, this is just pod deployed in the host networking
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

	// Build resync data for service renderers.
	confResyncEv.FrontendIfs = sp.frontendIfs
	confResyncEv.BackendIfs = sp.backendIfs
	for _, renderer := range sp.renderers {
		if err := renderer.Resync(confResyncEv); err != nil {
			return err
		}
	}
	return nil
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
