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
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"
	"net"

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
	// TODO
	pods map[podmodel.ID]*podInfo
}

// Deps lists dependencies of ServiceProcessor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	NodeSync     nodesync.API
	PodManager   podmanager.API
	IPAM         ipam.API
	IPNet        ipnet.API
}

// Init initializes service processor.
func (sp *SFCProcessor) Init() error {
	sp.reset()
	return nil
}

func (sp *SFCProcessor) reset() {
	sp.pods = make(map[podmodel.ID]*podInfo)
}

// AfterInit does nothing for the SFC processor.
func (sp *SFCProcessor) AfterInit() error {
	return nil
}

// Update is called for:
//  - KubeStateChange for service-related data
//  - AddPod & DeletePod
//  - NodeUpdate event
func (sp *SFCProcessor) Update(event controller.Event) error {

	if k8sChange, isK8sChange := event.(*controller.KubeStateChange); isK8sChange {
		return sp.propagateDataChangeEv(k8sChange)
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv Services at the present state to be
// (re)installed.
func (sp *SFCProcessor) Resync(kubeStateData controller.KubeStateData) error {
	resyncEvData := sp.parseResyncEv(kubeStateData)
	return sp.processResyncEvent(resyncEvData)
}

// RegisterRenderer registers a new service renderer.
// The renderer will be receiving updates for all services on the cluster.
func (sp *SFCProcessor) RegisterRenderer(renderer renderer.SFCRendererAPI) error {
	sp.renderers = append(sp.renderers, renderer)
	return nil
}

// Close deallocates resource held by the processor.
func (sp *SFCProcessor) Close() error {
	return nil
}

func (sp *SFCProcessor) processNewSFC(sfc *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("New SFC: %+v", sfc)

	sfcSB := &renderer.ContivSFC{
		Name:    sfc.Name,
		Network: sfc.Network,
	}

	// TODO: so far we support only one chain instance

	for _, chainItem := range sfc.Chain {
		if chainItem.Type == sfcmodel.ServiceFunctionChain_ServiceFunction_Pod {
			sfPods := make([]*renderer.PodSF, 0)
			for _, pod := range sp.pods {
				if sp.podMatchesSelector(pod, chainItem.PodSelector) {
					sfPods = append(sfPods, &renderer.PodSF{
						ID: pod.id,
						// TODO: nodeid
						Local:           pod.local,
						InputInterface:  chainItem.InputInterface,
						OutputInterface: chainItem.OutputInterface,
					})
				}
			}
			if len(sfPods) > 0 {
				sfcSB.Chain = append(sfcSB.Chain, &renderer.ServiceFunction{
					Type: renderer.Pod,
					Pods: sfPods,
				})
			}
		}
	}

	for _, renderer := range sp.renderers {
		if err := renderer.AddChain(sfcSB); err != nil {
			return err
		}
	}

	return nil
}

func (sp *SFCProcessor) processUpdatedSFC(chain *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("Updated SFC: %+v", chain)

	return nil
}

func (sp *SFCProcessor) processDeletedSFC(chain *sfcmodel.ServiceFunctionChain) error {

	sp.Log.Infof("Deleted SFC: %+v", chain)

	return nil
}

func (sp *SFCProcessor) processNewPod(pod *pod.Pod) error {

	podID := podmodel.GetID(pod)
	podMeta := &podInfo{
		id:     podID,
		labels: map[string]string{},
	}
	sp.pods[podID] = podMeta

	for _, l := range pod.Label {
		podMeta.labels[l.Key] = l.Value
	}

	if pod.IpAddress != "" && sp.IPAM.PodSubnetThisNode().Contains(net.ParseIP(pod.IpAddress)) {
		podMeta.local = true
	}

	return nil
}

func (sp *SFCProcessor) processUpdatedPod(pod *pod.Pod) error {

	// TODO

	return nil
}

func (sp *SFCProcessor) processDeletedPod(pod *pod.Pod) error {

	delete(sp.pods, podmodel.GetID(pod))

	return nil
}

func (sp *SFCProcessor) processResyncEvent(resyncEv *ResyncEventData) error {
	sp.reset()

	// Re-build the current state.
	confResyncEv := &renderer.ResyncEventData{}

	// TODO: fill confResyncEv

	for _, renderer := range sp.renderers {
		if err := renderer.Resync(confResyncEv); err != nil {
			return err
		}
	}
	return nil
}
