/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
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
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	extifmodel "github.com/contiv/vpp/plugins/crd/handler/externalinterface/model"
	sfcmodel "github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/sfc/renderer"
)

// SFCProcessor implements SFCProcessorAPI.
type SFCProcessor struct {
	Deps

	renderers []renderer.SFCRendererAPI

	/* internal maps */
	configuredSFCs map[string]*sfcmodel.ServiceFunctionChain // maps sfc name to NB (configured) SFC
	renderedSFCs   map[string]*sfcmodel.ServiceFunctionChain // maps sfc name to SB (rendered) SFC
	externalIfs    map[string]*extifmodel.ExternalInterface  // maps external interface name to NB external intf. data
}

// Deps lists dependencies of SFC Processor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	NodeSync     nodesync.API
	PodManager   podmanager.API
	IPAM         ipam.API
	IPNet        ipnet.API
}

// Init initializes SFC processor.
func (sp *SFCProcessor) Init() error {
	sp.reset()
	return nil
}

// reset (re)initializes all internal maps.
func (sp *SFCProcessor) reset() {
	sp.configuredSFCs = make(map[string]*sfcmodel.ServiceFunctionChain)
	sp.renderedSFCs = make(map[string]*sfcmodel.ServiceFunctionChain)
	sp.externalIfs = make(map[string]*extifmodel.ExternalInterface)
}

// AfterInit does nothing for the SFC processor.
func (sp *SFCProcessor) AfterInit() error {
	return nil
}

// Update is called for:
//  - KubeStateChange for SFC-related an pod-related data
func (sp *SFCProcessor) Update(event controller.Event) error {

	if k8sChange, isK8sChange := event.(*controller.KubeStateChange); isK8sChange {
		switch k8sChange.Resource {

		case sfcmodel.Keyword:
			if k8sChange.NewValue != nil {
				sfc := k8sChange.NewValue.(*sfcmodel.ServiceFunctionChain)
				if k8sChange.PrevValue == nil {
					return sp.processNewSFC(sfc)
				}
				oldSfc := k8sChange.PrevValue.(*sfcmodel.ServiceFunctionChain)
				return sp.processUpdatedSFC(oldSfc, sfc, nil)
			}
			sfc := k8sChange.PrevValue.(*sfcmodel.ServiceFunctionChain)
			return sp.processDeletedSFC(sfc)

		case podmodel.PodKeyword:
			if k8sChange.NewValue != nil {
				pod := k8sChange.NewValue.(*podmodel.Pod)
				if k8sChange.PrevValue == nil {
					return sp.processNewPod(pod)
				}
				return sp.processUpdatedPod(pod)
			}
			pod := k8sChange.PrevValue.(*podmodel.Pod)
			return sp.processDeletedPod(pod)

		case extifmodel.Keyword:
			if k8sChange.NewValue != nil {
				extIf := k8sChange.NewValue.(*extifmodel.ExternalInterface)
				if k8sChange.PrevValue == nil {
					return sp.processNewExtInterface(extIf)
				}
				return sp.processUpdatedExtInterface(extIf)
			}
			extIf := k8sChange.PrevValue.(*extifmodel.ExternalInterface)
			return sp.processDeletedExtInterface(extIf)
		}
	}

	if podCustomIfUpdate, isPodCustomIfUpdate := event.(*ipnet.PodCustomIfUpdate); isPodCustomIfUpdate {
		return sp.processUpdatedPodCustomIfs(podCustomIfUpdate)
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv SFCs at the present state to be (re)installed.
func (sp *SFCProcessor) Resync(kubeStateData controller.KubeStateData) error {

	// reset internal state
	sp.reset()
	confResyncEv := &renderer.ResyncEventData{}

	// rebuild external interfaces
	for _, extIfProto := range kubeStateData[extifmodel.Keyword] {
		extIf := extIfProto.(*extifmodel.ExternalInterface)
		sp.externalIfs[extIf.Name] = extIf
	}

	// rebuild SFCs
	for _, svcProto := range kubeStateData[sfcmodel.Keyword] {
		sfc := svcProto.(*sfcmodel.ServiceFunctionChain)
		sp.configuredSFCs[sfc.Name] = sfc
		contivSFC := sp.renderServiceFunctionChain(sfc, nil)
		if contivSFC != nil {
			confResyncEv.Chains = append(confResyncEv.Chains, contivSFC)
		}
	}

	// call resync on all renderers
	for _, renderer := range sp.renderers {
		if err := renderer.Resync(confResyncEv); err != nil {
			return err
		}
	}
	return nil
}

// RegisterRenderer registers a new SFC renderer.
// The renderer will be receiving updates for all SFCs on the cluster.
func (sp *SFCProcessor) RegisterRenderer(renderer renderer.SFCRendererAPI) error {
	sp.renderers = append(sp.renderers, renderer)
	return nil
}

// Close does nothing for the SFC processor.
func (sp *SFCProcessor) Close() error {
	return nil
}

// processNewPod handles the event of adding of a new pod.
func (sp *SFCProcessor) processNewPod(pod *podmodel.Pod) error {
	return sp.processUpdatedPod(pod)
}

// processUpdatedPod handles the event of updating runtime state of a pod.
func (sp *SFCProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	sp.Log.Debugf("New / Updated pod: %v", pod)

	podData := sp.PodManager.GetPods()[podmodel.GetID(pod)]
	if podData == nil {
		return nil
	}

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData, false)

	return err
}

// processDeletedPod handles the event of deletion of a pod.
func (sp *SFCProcessor) processDeletedPod(pod *podmodel.Pod) error {

	sp.Log.Debugf("Delete pod: %v", pod)

	// construct pod info from k8s data (already deleted in PodManager)
	podData := &podmanager.Pod{
		ID:          podmodel.GetID(pod),
		IPAddress:   pod.IpAddress,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
	}

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData, true)

	return err
}

// processUpdatedPodCustomIfs handles the event of updating pod custom interfaces.
func (sp *SFCProcessor) processUpdatedPodCustomIfs(pod *ipnet.PodCustomIfUpdate) error {

	sp.Log.Debugf("Update pod custom ifs: %v", pod)

	podData := sp.PodManager.GetPods()[pod.PodID]
	if podData == nil {
		return nil
	}

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData, false)

	return err
}

// processNewExtInterface handles the event of adding of a new external interface.
func (sp *SFCProcessor) processNewExtInterface(extIf *extifmodel.ExternalInterface) error {
	return sp.processUpdatedExtInterface(extIf)
}

// processUpdatedExtInterface handles the event of updating runtime state of an external interface.
func (sp *SFCProcessor) processUpdatedExtInterface(extIf *extifmodel.ExternalInterface) error {

	sp.Log.Debugf("New / Updated external interface: %+v", extIf)

	sp.externalIfs[extIf.Name] = extIf

	// process SFCs that this ext. interface may be affecting
	return sp.processSFCsForExtIf(extIf)
}

// processDeletedExtInterface handles the event of deletion of an external interface.
func (sp *SFCProcessor) processDeletedExtInterface(extIf *extifmodel.ExternalInterface) error {

	sp.Log.Debugf("Delete external interface: %+v", extIf)

	delete(sp.externalIfs, extIf.Name)

	// process SFCs that this ext. interface may be affecting
	return sp.processSFCsForExtIf(extIf)
}

// processNewSFC handles the event of adding a new service function chain.
func (sp *SFCProcessor) processNewSFC(sfc *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("New SFC: %v", sfc)
	sp.configuredSFCs[sfc.Name] = sfc

	// render the SFC to a less-abstract SFC representation
	contivSFC := sp.renderServiceFunctionChain(sfc, nil)
	if contivSFC == nil {
		return nil
	}

	// call chain add on all renderers
	for _, renderer := range sp.renderers {
		if err := renderer.AddChain(contivSFC); err != nil {
			return err
		}
	}
	sp.renderedSFCs[contivSFC.Name] = sfc

	return nil
}

// processUpdatedSFC handles the event of updating an existing service function chain.
func (sp *SFCProcessor) processUpdatedSFC(oldSFC, newSFC *sfcmodel.ServiceFunctionChain,
	deletedPod *podmanager.Pod) (err error) {

	sp.Log.Infof("Updated SFC: %v", newSFC)
	sp.configuredSFCs[newSFC.Name] = newSFC

	oldContivSFC := sp.renderServiceFunctionChain(oldSFC, nil)
	newContivSFC := sp.renderServiceFunctionChain(newSFC, deletedPod)
	if oldContivSFC == nil && newContivSFC == nil {
		return nil // no-op, old nor new SFC cannot be rendered
	}

	// new SFC renders as nil = delete the old one
	if newContivSFC == nil {
		for _, renderer := range sp.renderers {
			err = renderer.DeleteChain(oldContivSFC)
			if err != nil {
				return err
			}
		}
		delete(sp.renderedSFCs, oldSFC.Name)
		return nil
	}

	// call add / update on all renderers
	for _, renderer := range sp.renderers {
		if _, exists := sp.renderedSFCs[newSFC.Name]; exists {
			err = renderer.UpdateChain(oldContivSFC, newContivSFC)
		} else {
			err = renderer.AddChain(newContivSFC)
		}
		if err != nil {
			return err
		}
	}
	sp.renderedSFCs[newContivSFC.Name] = newSFC

	return nil
}

// processDeletedSFC handles the event of deletion of an existing service function chain.
func (sp *SFCProcessor) processDeletedSFC(sfc *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("Deleted SFC: %v", sfc)
	delete(sp.configuredSFCs, sfc.Name)

	// render the SFC to a less-abstract SFC representation
	contivSFC := sp.renderServiceFunctionChain(sfc, nil)
	if contivSFC == nil {
		return nil
	}

	// call chain del on all renderers
	for _, renderer := range sp.renderers {
		if err := renderer.DeleteChain(contivSFC); err != nil {
			return err
		}
	}
	delete(sp.renderedSFCs, sfc.Name)

	return nil
}

// processSFCsForPod process SFCs that may be affected by presence/absence of the specified pod.
func (sp *SFCProcessor) processSFCsForPod(pod *podmanager.Pod, isDelete bool) (err error) {
	sfcs := sp.getSFCsReferencingPod(pod)

	if len(sfcs) > 1 {
		sp.Log.Debugf("SFCs affected by the pod %s: %d", pod.ID.String(), sfcs)
	}

	for _, sfc := range sfcs {
		oldSFC := sp.renderedSFCs[sfc.Name]

		if isDelete {
			err = sp.processUpdatedSFC(oldSFC, sfc, pod)
		} else {
			err = sp.processUpdatedSFC(oldSFC, sfc, nil)
		}

		if err != nil {
			return err
		}
	}
	return nil
}

// getSFCsReferencingPod returns all SFCs that are referencing given pod.
func (sp *SFCProcessor) getSFCsReferencingPod(pod *podmanager.Pod) []*sfcmodel.ServiceFunctionChain {
	matches := make([]*sfcmodel.ServiceFunctionChain, 0)

	for _, sfc := range sp.configuredSFCs {
		for _, f := range sfc.Chain {
			if f.Type == sfcmodel.ServiceFunctionChain_ServiceFunction_Pod && sp.podMatchesSelector(pod, f.PodSelector) {
				sp.Log.Debugf("Pod %s matches SFC %s", pod.ID.String(), sfc)
				matches = append(matches, sfc)
			}
		}
	}
	return matches
}

// processSFCsForExtIf process SFCs that may be affected by presence/absence of the specified external interface.
func (sp *SFCProcessor) processSFCsForExtIf(extIf *extifmodel.ExternalInterface) (err error) {
	sfcs := sp.getSFCsReferencingExtIf(extIf)

	if len(sfcs) > 1 {
		sp.Log.Debugf("SFCs affected by the external interface %s: %d", extIf.Name, sfcs)
	}

	for _, sfc := range sfcs {
		oldSFC := sp.renderedSFCs[sfc.Name]
		err = sp.processUpdatedSFC(oldSFC, sfc, nil)

		if err != nil {
			return err
		}
	}
	return nil
}

// getSFCsReferencingExtIf returns all SFCs that are referencing given external interface.
func (sp *SFCProcessor) getSFCsReferencingExtIf(extIf *extifmodel.ExternalInterface) []*sfcmodel.ServiceFunctionChain {
	matches := make([]*sfcmodel.ServiceFunctionChain, 0)

	for _, sfc := range sp.configuredSFCs {
		for _, f := range sfc.Chain {
			if f.Type == sfcmodel.ServiceFunctionChain_ServiceFunction_ExternalInterface &&
				(f.Interface == extIf.Name || f.InputInterface == extIf.Name || f.OutputInterface == extIf.Name) {
				sp.Log.Debugf("Interface %s matches SFC %s", extIf.Name, sfc)
				matches = append(matches, sfc)
			}
		}
	}
	return matches
}

// renderServiceFunctionChain renders SFC in NB format to its less-abstract representation intended for the renderers.
func (sp *SFCProcessor) renderServiceFunctionChain(sfc *sfcmodel.ServiceFunctionChain,
	deletedPod *podmanager.Pod) *renderer.ContivSFC {
	if sfc == nil {
		return nil
	}
	contivSFC := &renderer.ContivSFC{
		Name:           sfc.Name,
		Unidirectional: sfc.Unidirectional,
		Network:        sfc.Network,
	}

	for _, serviceFunc := range sfc.Chain {
		switch serviceFunc.Type {
		case sfcmodel.ServiceFunctionChain_ServiceFunction_Pod:
			found := sp.renderServiceFunctionPod(serviceFunc, contivSFC, deletedPod)
			if !found {
				sp.Log.Debugf("No matching pods were found for the service function %v, "+
					"skipping this SFC", serviceFunc)
				return nil
			}
		case sfcmodel.ServiceFunctionChain_ServiceFunction_ExternalInterface:
			found := sp.renderServiceFunctionInterface(serviceFunc, contivSFC)
			if !found {
				sp.Log.Debugf("External interfaces were not found for the service function %v, "+
					"skipping this SFC", serviceFunc)
				return nil
			}
		}
	}

	return contivSFC
}

// renderServiceFunctionPod renders a service function element of pod type.
// Returns true if a matching pod(s) has been found, false otherwise.
func (sp *SFCProcessor) renderServiceFunctionPod(f *sfcmodel.ServiceFunctionChain_ServiceFunction,
	sfc *renderer.ContivSFC, deletedPod *podmanager.Pod) bool {

	sfPods := make([]*renderer.PodSF, 0)

	// if only "interface" is defined, render that as both input and output interface
	inputIfCRDName := f.InputInterface
	outputIfCRDName := f.OutputInterface
	if inputIfCRDName == "" {
		inputIfCRDName = f.Interface
	}
	if outputIfCRDName == "" {
		outputIfCRDName = f.Interface
	}

	// look for matching pods
	for podID, pod := range sp.PodManager.GetPods() {
		inputIfLogicalName := inputIfCRDName   // interface name that will be use in VPP
		outputIfLogicalName := outputIfCRDName // interface name that will be use in VPP
		if sp.podMatchesSelector(pod, f.PodSelector) {
			if deletedPod != nil && deletedPod.ID == podID {
				continue
			}
			if sp.IPAM.GetPodIP(podID) == nil {
				continue
			}
			nodeID, _ := sp.IPAM.NodeIDFromPodIP(net.ParseIP(pod.IPAddress))
			_, isLocal := sp.PodManager.GetLocalPods()[podID]

			if isLocal {
				// process interface names to actual pod interface names
				exists := false
				if inputIfCRDName != "" {
					inputIfLogicalName, _, exists = sp.IPNet.GetPodCustomIfNames(
						pod.ID.Namespace, pod.ID.Name, inputIfCRDName)
					if !exists {
						continue
					}
				}
				if outputIfCRDName != "" {
					outputIfLogicalName, _, exists = sp.IPNet.GetPodCustomIfNames(
						pod.ID.Namespace, pod.ID.Name, outputIfCRDName)
					if !exists {
						continue
					}
				}
			}

			sfPods = append(sfPods, &renderer.PodSF{
				ID:     podID,
				NodeID: nodeID,
				Local:  isLocal,
				InputInterface: &renderer.InterfaceNames{
					LogicalName: inputIfLogicalName,
					CRDName:     inputIfCRDName,
				},
				OutputInterface: &renderer.InterfaceNames{
					LogicalName: outputIfLogicalName,
					CRDName:     outputIfCRDName,
				},
			})
		}
	}

	// if some matching pods found, add into the chain
	if len(sfPods) > 0 {
		sfc.Chain = append(sfc.Chain, &renderer.ServiceFunction{
			Type: renderer.Pod,
			Pods: sfPods,
		})
		return true
	}

	// no matching pods found
	return false
}

// renderServiceFunctionInterface renders a service function element of "external interface" type.
// Returns true if a matching interface(s) has been found, false otherwise.
func (sp *SFCProcessor) renderServiceFunctionInterface(f *sfcmodel.ServiceFunctionChain_ServiceFunction,
	sfc *renderer.ContivSFC) bool {

	sfIfs := make([]*renderer.InterfaceSF, 0)

	// if input or output interface is given instead of just "interface", use those values
	extIfName := f.Interface
	if f.Interface == "" && f.InputInterface != "" {
		extIfName = f.InputInterface
	}
	if f.Interface == "" && f.OutputInterface != "" {
		extIfName = f.OutputInterface
	}

	// check if an external interface with that name is known
	extIf, exists := sp.externalIfs[extIfName]
	if !exists {
		return false
	}

	// process the interfaces with given name
	myNodeName := sp.ServiceLabel.GetAgentLabel()
	for _, nodeIf := range extIf.Nodes {
		local := true
		nodeID := sp.NodeSync.GetNodeID()
		if nodeIf.Node != myNodeName {
			local = false
			node := sp.NodeSync.GetAllNodes()[nodeIf.Node]
			if node == nil {
				continue // unknown node
			}
			nodeID = node.ID
		}
		sfIfs = append(sfIfs, &renderer.InterfaceSF{
			InterfaceName:    sp.IPNet.GetExternalIfName(extIf.Name, nodeIf.Vlan),
			VppInterfaceName: nodeIf.VppInterfaceName,
			NodeID:           nodeID,
			Local:            local,
		})
	}

	// if some matching interfaces were found, add into the chain
	if len(sfIfs) > 0 {
		sfc.Chain = append(sfc.Chain, &renderer.ServiceFunction{
			Type:               renderer.ExternalInterface,
			ExternalInterfaces: sfIfs,
		})
		return true
	}

	// no matching interface found
	return false
}

// podMatchesSelector returns true if the pod matches provided label selector, false otherwise.
func (sp *SFCProcessor) podMatchesSelector(pod *podmanager.Pod, podSelector map[string]string) bool {
	if len(pod.Labels) == 0 {
		return false
	}
	for selKey, selVal := range podSelector {
		match := false
		for podLabelKey, podLabelVal := range pod.Labels {
			if podLabelKey == selKey && podLabelVal == selVal {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}
