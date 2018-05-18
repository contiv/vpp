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
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// getPodsByNSLabelSelector returns the pods that match a collection of Label Selectors in the same namespace
func (pc *PolicyCache) getMatchLabelPodsInsideNs(namespace string, labels []*policymodel.Policy_Label) []string {
	// Check if we have empty labels
	if len(labels) == 0 {
		return []string{}
	}
	prevNSLabelSelector := namespace + "/" + labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByNSLabelSelector(prevNSLabelSelector)
	current := prevPodSet

	for i := 1; i < len(labels); i++ {
		prevPodSet = current
		newNSLabelSelector := namespace + "/" + labels[i].Key + "/" + labels[i].Value
		newPodSet := pc.configuredPods.LookupPodsByNSLabelSelector(newNSLabelSelector)
		current = utils.Intersect(prevPodSet, newPodSet)
		if len(current) == 0 {
			break
		}
	}

	return current
}

// getPodsByLabelSelector returns the pods that match a collection of Namespace (cluster scoped-labels) Label Selectors
func (pc *PolicyCache) getPodsByNsLabelSelector(labels []*policymodel.Policy_Label) []string {
	// Check if we have empty labels
	if len(labels) == 0 {
		return []string{}
	}
	pods := []string{}
	prevNSLabelSelector := labels[0].Key + "/" + labels[0].Value
	prevNamespaceSet := pc.configuredNamespaces.LookupNamespacesByLabelSelector(prevNSLabelSelector)
	current := prevNamespaceSet

	for i := 1; i < len(labels); i++ {
		prevNamespaceSet = current
		newNSLabelSelector := labels[i].Key + "/" + labels[i].Value
		newNamespaceSet := pc.configuredNamespaces.LookupNamespacesByLabelSelector(newNSLabelSelector)
		current = utils.Intersect(prevNamespaceSet, newNamespaceSet)
		if len(current) == 0 {
			break
		}
	}
	for _, namespace := range current {
		pods = append(pods, pc.configuredPods.LookupPodsByNamespace(namespace)...)
	}

	return pods
}
