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

package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// isMatchLabel returns true/false if pod labels match a collection of pod selector labels (labels are ANDed).
func (pp *PolicyProcessor) isMatchLabel(pod *podmodel.Pod, matchLabels []*policymodel.Policy_Label, policyNamespace string) bool {
	namespace := pod.Namespace
	podLabels := pod.Label
	labelExists := make(map[string]bool)

	for _, podLabel := range podLabels {
		label := namespace + "/" + podLabel.Key + "/" + podLabel.Value
		labelExists[label] = true
	}

	isMatch := true
	for _, matchLabel := range matchLabels {
		label := policyNamespace + "/" + matchLabel.Key + "/" + matchLabel.Value
		if labelExists[label] != true {
			isMatch = false
			break
		}
	}

	return isMatch

}

// isNamespaceMatchLabel returns true/false if pod namespace matches a collection of namespace selector labels (labels are ANDed).
func (pp *PolicyProcessor) isNamespaceMatchLabel(pod *podmodel.Pod, matchLabels []*policymodel.Policy_Label) bool {

	podNamespace := pod.Namespace
	isMatch := false

	for _, matchLabel := range matchLabels {
		label := matchLabel.Key + "/" + matchLabel.Value
		// Get all namespaces that match namespace label selector
		namespaces := pp.Cache.LookupNamespacesByLabelSelector(label)
		if len(namespaces) == 0 {
			return false
		}
		namespaceExists := false
		// Check if matched namespaces include pod's namespace
		for _, namespace := range namespaces {
			if namespace.String() == podNamespace {
				namespaceExists = true
				break
			}
		}
		// Namespaces are AND'ed, if one is not a match then exit
		if namespaceExists == false {
			isMatch = false
			break
		}
		isMatch = true
	}
	return isMatch
}
