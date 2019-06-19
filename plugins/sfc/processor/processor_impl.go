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
	pods           map[podmodel.ID]*podInfo                  // running pod information
	configuredSFCs map[string]*sfcmodel.ServiceFunctionChain // maps sfc name to NB (configured) SFC
	renderedSFCs   map[string]*sfcmodel.ServiceFunctionChain // maps sfc name to SB (rendered) SFC
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

// podInfo holds information about a pod in the local cache.
type podInfo struct {
	id     podmodel.ID
	ip     net.IP
	labels map[string]string
}

// Init initializes SFC processor.
func (sp *SFCProcessor) Init() error {
	sp.reset()
	return nil
}

// reset (re)initializes all internal maps.
func (sp *SFCProcessor) reset() {
	sp.pods = make(map[podmodel.ID]*podInfo)
	sp.configuredSFCs = make(map[string]*sfcmodel.ServiceFunctionChain)
	sp.renderedSFCs = make(map[string]*sfcmodel.ServiceFunctionChain)
}

// AfterInit does nothing for the SFC processor.
func (sp *SFCProcessor) AfterInit() error {
	return nil
}

// Update is called for:
//  - KubeStateChange for SFC-related an pod-related data
func (sp *SFCProcessor) Update(event controller.Event) error {

	if k8sChange, isK8sChange := event.(*controller.KubeStateChange); isK8sChange {
		return sp.propagateDataChangeEv(k8sChange)
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv SFCs at the present state to be (re)installed.
func (sp *SFCProcessor) Resync(kubeStateData controller.KubeStateData) error {
	resyncEvData := sp.parseResyncEv(kubeStateData)
	return sp.processResyncEvent(resyncEvData)
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

func (sp *SFCProcessor) processNewPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	// update pod info
	podData := sp.updatePodInfo(pod)

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData)

	return err
}

func (sp *SFCProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	// update pod info
	podData := sp.updatePodInfo(pod)

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData)

	return err
}

func (sp *SFCProcessor) processDeletedPod(pod *podmodel.Pod) error {

	// update pod info
	podData := sp.updatePodInfo(pod)

	// process SFCs that this pod may be affecting
	err := sp.processSFCsForPod(podData)

	// delete pod info from the internal cache
	delete(sp.pods, podmodel.GetID(pod))

	return err
}

func (sp *SFCProcessor) processNewSFC(sfc *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("New SFC: %v", sfc)
	sp.configuredSFCs[sfc.Name] = sfc

	contivSFC := sp.renderServiceFunctionChain(sfc)
	if contivSFC == nil {
		return nil
	}

	for _, renderer := range sp.renderers {
		if err := renderer.AddChain(contivSFC); err != nil {
			return err
		}
	}
	sp.renderedSFCs[contivSFC.Name] = sfc

	return nil
}

func (sp *SFCProcessor) processUpdatedSFC(oldSFC, newSFC *sfcmodel.ServiceFunctionChain) (err error) {

	sp.Log.Infof("Updated SFC: %v", newSFC)
	sp.configuredSFCs[newSFC.Name] = newSFC

	oldContivSFC := sp.renderServiceFunctionChain(oldSFC)
	newContivSFC := sp.renderServiceFunctionChain(newSFC)
	if oldContivSFC == nil && newContivSFC == nil {
		return nil
	}

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

func (sp *SFCProcessor) processDeletedSFC(sfc *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("Deleted SFC: %v", sfc)
	delete(sp.configuredSFCs, sfc.Name)

	contivSFC := sp.renderServiceFunctionChain(sfc)
	if contivSFC == nil {
		return nil
	}

	for _, renderer := range sp.renderers {
		if err := renderer.DeleteChain(contivSFC); err != nil {
			return err
		}
	}
	delete(sp.renderedSFCs, sfc.Name)

	return nil
}

func (sp *SFCProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	// reset internal state
	sp.reset()

	// re-build the current state
	confResyncEv := &renderer.ResyncEventData{}

	for _, pod := range resyncEv.Pods {
		if pod.IpAddress != "" {
			sp.updatePodInfo(pod)
		}
	}

	for _, sfc := range resyncEv.SFCs {
		contivSFC := sp.renderServiceFunctionChain(sfc)
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

// updatePodInfo updates pod information in the local cache.
func (sp *SFCProcessor) updatePodInfo(pod *podmodel.Pod) *podInfo {
	podID := podmodel.GetID(pod)

	podData := sp.pods[podID]
	if podData == nil {
		podData = &podInfo{
			id:     podID,
			labels: map[string]string{},
		}
		sp.pods[podID] = podData
	}

	for _, l := range pod.Label {
		podData.labels[l.Key] = l.Value
	}
	return podData
}

// processSFCsForPod process SFCs that may be affected by presence/absence of the specified pod.
func (sp *SFCProcessor) processSFCsForPod(pod *podInfo) (err error) {
	sfcs := sp.getSFCsReferencingPod(pod)

	for _, sfc := range sfcs {
		oldSFC := sp.renderedSFCs[sfc.Name]
		err = sp.processUpdatedSFC(oldSFC, sfc)

		if err != nil {
			return err
		}
	}
	return nil
}

// getSFCsReferencingPod returns all SFCs that are referencing given pod.
func (sp *SFCProcessor) getSFCsReferencingPod(pod *podInfo) []*sfcmodel.ServiceFunctionChain {
	matches := make([]*sfcmodel.ServiceFunctionChain, 0)

	for _, sfc := range sp.configuredSFCs {
		for _, f := range sfc.Chain {
			if sp.podMatchesSelector(pod, f.PodSelector) {
				matches = append(matches, sfc)
			}
		}
	}
	return matches
}

// renderServiceFunctionChain renders SFC in NB format to its less-abstract representation intended for the renderers.
func (sp *SFCProcessor) renderServiceFunctionChain(sfc *sfcmodel.ServiceFunctionChain) *renderer.ContivSFC {
	if sfc == nil {
		return nil
	}
	contivSFC := &renderer.ContivSFC{
		Name:    sfc.Name,
		Network: sfc.Network,
	}

	for _, serviceFunc := range sfc.Chain {
		switch serviceFunc.Type {
		case sfcmodel.ServiceFunctionChain_ServiceFunction_Pod:
			found := sp.renderServiceFunctionPod(serviceFunc, contivSFC)
			if !found {
				sp.Log.Debugf("No matching pods were found for the service function %v, "+
					"skipping this SFC", serviceFunc)
				return nil
			}
		case sfcmodel.ServiceFunctionChain_ServiceFunction_ExternalInterface:
			sp.Log.Warnf("External interfaces not yet supported in SFC, ignoring")
			// TODO: external interfaces not yet supported - not rendered at all
		}
	}

	return contivSFC
}

// renderServiceFunctionPod renders a service function element of pod type.
// Returns true if a matching pod(s) has been found, false otherwise.
func (sp *SFCProcessor) renderServiceFunctionPod(f *sfcmodel.ServiceFunctionChain_ServiceFunction,
	sfc *renderer.ContivSFC) bool {

	sfPods := make([]*renderer.PodSF, 0)

	// look for matching pods
	for podID, pod := range sp.pods {
		if sp.podMatchesSelector(pod, f.PodSelector) {
			_, isLocal := sp.PodManager.GetLocalPods()[podID]
			nodeID, _ := sp.IPAM.NodeIDFromPodIP(pod.ip)

			sfPods = append(sfPods, &renderer.PodSF{
				ID:              podID,
				NodeID:          nodeID,
				Local:           isLocal,
				InputInterface:  f.InputInterface,
				OutputInterface: f.OutputInterface,
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

// podMatchesSelector returns true if the pod matches provided label selector, false otherwise.
func (sp *SFCProcessor) podMatchesSelector(pod *podInfo, podSelector map[string]string) bool {
	if len(pod.labels) == 0 {
		return false
	}
	for selKey, selVal := range podSelector {
		match := false
		for podLabelKey, podLabelVal := range pod.labels {
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
