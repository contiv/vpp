/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
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

package cache

import (
	controller "github.com/contiv/vpp/plugins/controller/api"
	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// DataResyncEvent wraps an entire state of K8s that should be reflected into VPP.
type DataResyncEvent struct {
	Namespaces []*namespacemodel.Namespace
	Pods       []*podmodel.Pod
	Policies   []*policymodel.Policy
}

// NewDataResyncEvent creates an empty instance of DataResyncEvent.
func NewDataResyncEvent() *DataResyncEvent {
	return &DataResyncEvent{
		Namespaces: []*namespacemodel.Namespace{},
		Pods:       []*podmodel.Pod{},
		Policies:   []*policymodel.Policy{},
	}
}

// resyncParseEvent parses K8s configuration RESYNC event for use by PolicyCacheWatcher.
func (pc *PolicyCache) resyncParseEvent(kubeStateData controller.KubeStateData) *DataResyncEvent {
	var (
		numNs int
		numPolicy int
		numPod int
	)

	event := NewDataResyncEvent()
	pc.reset()

	// collect pods
	for _, podProto:= range kubeStateData[podmodel.PodKeyword] {
		pod := podProto.(*podmodel.Pod)
		event.Pods = append(event.Pods, pod)
		podID := podmodel.GetID(pod).String()
		pc.configuredPods.RegisterPod(podID, pod)
		numPod++
	}

	// collect namespaces
	for _, nsProto:= range kubeStateData[namespacemodel.NamespaceKeyword] {
		namespace := nsProto.(*namespacemodel.Namespace)
		event.Namespaces = append(event.Namespaces, namespace)
		namespaceID := namespacemodel.GetID(namespace).String()
		pc.configuredNamespaces.RegisterNamespace(namespaceID, namespace)
		numNs++
	}

	// collect policies
	for _, policyProto:= range kubeStateData[policymodel.PolicyKeyword] {
		policy := policyProto.(*policymodel.Policy)
		event.Policies = append(event.Policies, policy)
		policyID := policymodel.GetID(policy).String()
		pc.configuredPolicies.RegisterPolicy(policyID, policy)
		numPolicy++
	}
	return event
}
