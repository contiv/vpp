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

// GetPodsByNSLabelSelector returns the pods that match a collection of Label Selectors in the same namespace
func (pc *PolicyCache) getPodsByNSLabelSelector(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {

	prevNSLabelSelector := namespace + "/" + labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByNSLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}

	if len(labels) == 1 {
		return true, prevPodSet
	}

	for i := 1; i < len(labels); i++ {
		newNSLabelSelector := namespace + "/" + labels[i].Key + "/" + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByNSLabelSelector(newNSLabelSelector)

		tmp := utils.Intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}

	return true, newPodSet
}

// GetPodsByNSLabelSelector returns the pods that match a collection of Label Selectors in the same namespace
func (pc *PolicyCache) getPodsByLabelSelector(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {

	prevNSLabelSelector := labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}

	if len(labels) == 1 {
		return true, prevPodSet
	}

	for i := 1; i < len(labels); i++ {
		newLabelSelector := labels[i].Key + "/" + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newLabelSelector)

		tmp := utils.Intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}

	return true, newPodSet
}
