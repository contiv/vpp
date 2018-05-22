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

const (
	in           = policymodel.Policy_LabelSelector_LabelExpression_IN
	notIn        = policymodel.Policy_LabelSelector_LabelExpression_NOT_IN
	exists       = policymodel.Policy_LabelSelector_LabelExpression_EXISTS
	doesNotExist = policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST
)

// getMatchExpressionPodsInsideNs returns all the pods from a given namespace that match a collection of pod label expressions
// (expressions are ANDed).
func (pc *PolicyCache) getMatchExpressionPodsInsideNs(namespace string, expressions []*policymodel.Policy_LabelSelector_LabelExpression) []string {
	var inPodSet, notInPodSet, existsPodSet, notExistPodSet []string
	var finalSet [][]string
	// Check if we have empty expressions
	if len(expressions) == 0 {
		return []string{}
	}

	for _, expression := range expressions {
		switch expression.Operator {
		case in:
			podSet := []string{}
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			for _, label := range labels {
				nsLabelSelector := namespace + "/" + label.Key + "/" + label.Value
				podSet = append(podSet, pc.configuredPods.LookupPodsByNSLabelSelector(nsLabelSelector)...)
			}
			podSet = utils.RemoveDuplicates(podSet)
			// Add all the pods the first time we get an "in" Pod set
			if len(inPodSet) == 0 {
				inPodSet = append(inPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			inPodSet = utils.Intersect(inPodSet, podSet)
			if len(inPodSet) == 0 {
				return []string{}
			}

		case notIn:
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			podSet := []string{}
			for _, label := range labels {
				nsLabelSelector := namespace + "/" + label.Key + "/" + label.Value
				podSet = append(podSet, pc.configuredPods.LookupPodsByNSLabelSelector(nsLabelSelector)...)
			}
			podSet = utils.RemoveDuplicates(podSet)

			podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
			podSet = utils.Difference(podNamespaceAll, podSet)
			// Add all the pods the first time we get an "in" Pod set
			if len(notInPodSet) == 0 {
				notInPodSet = append(notInPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			notInPodSet = utils.Intersect(notInPodSet, podSet)
			if len(notInPodSet) == 0 {
				return []string{}
			}

		case exists:
			podSet := pc.configuredPods.LookupPodsByNSKey(namespace + "/" + expression.Key)
			if len(podSet) == 0 {
				return []string{}
			}
			// Add all the pods the first time we get an "in" Pod set
			if len(existsPodSet) == 0 {
				existsPodSet = append(existsPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			existsPodSet = utils.Intersect(existsPodSet, podSet)
			if len(existsPodSet) == 0 {
				return []string{}
			}

		case doesNotExist:
			podSet := pc.configuredPods.LookupPodsByNSKey(namespace + "/" + expression.Key)

			podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
			podSet = utils.Difference(podNamespaceAll, podSet)

			// Add all the pods the first time we get an "in" Pod set
			if len(notExistPodSet) == 0 {
				notExistPodSet = append(notExistPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			notExistPodSet = utils.Intersect(notExistPodSet, podSet)
			if len(notExistPodSet) == 0 {
				return []string{}
			}
		}
	}

	if len(inPodSet) != 0 {
		finalSet = append(finalSet, inPodSet)
	}
	if len(notInPodSet) != 0 {
		finalSet = append(finalSet, notInPodSet)
	}
	if len(existsPodSet) != 0 {
		finalSet = append(finalSet, existsPodSet)
	}
	if len(notExistPodSet) != 0 {
		finalSet = append(finalSet, notExistPodSet)
	}

	switch len(finalSet) {
	case 1:
		return finalSet[0]
	case 2:
		return utils.Intersect(finalSet[0], finalSet[1])
	case 3:
		return utils.Intersect(finalSet[0], finalSet[1], finalSet[2])
	case 4:
		return utils.Intersect(finalSet[0], finalSet[1], finalSet[2], finalSet[3])
	}

	return []string{}
}

// getPodsByNsMatchExpression returns all pods from namespaces that match a collection of namespace match expressions
// (expressions are ANDed).
func (pc *PolicyCache) getPodsByNsMatchExpression(expressions []*policymodel.Policy_LabelSelector_LabelExpression) []string {
	var inPodSet, notInPodSet, existsPodSet, notExistPodSet []string
	var finalSet [][]string
	// Check if we have empty expressions
	if len(expressions) == 0 {
		return []string{}
	}

	for _, expression := range expressions {
		switch expression.Operator {
		case in:
			nsSet := []string{}
			podSet := []string{}
			nsLabels := utils.ConstructLabels(expression.Key, expression.Value)
			// find all  namespaces that match the namespace label selector
			for _, nsLabel := range nsLabels {
				nsLabelSelector := nsLabel.Key + "/" + nsLabel.Value
				nsSet = append(nsSet, pc.configuredNamespaces.LookupNamespacesByLabelSelector(nsLabelSelector)...)
			}
			nsSet = utils.RemoveDuplicates(nsSet)
			// find all the pods that belong to the namespace set
			for _, ns := range nsSet {
				podSet = append(podSet, pc.configuredPods.LookupPodsByNamespace(ns)...)
			}
			// Add all the pods the first time we get an "in" Pod set
			if len(inPodSet) == 0 {
				inPodSet = append(inPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			inPodSet = utils.Intersect(inPodSet, podSet)
			if len(inPodSet) == 0 {
				return []string{}
			}

		case notIn:
			nsSet := []string{}
			podSet := []string{}
			nsLabels := utils.ConstructLabels(expression.Key, expression.Value)
			// find all  namespaces that match the namespace label selector
			for _, nsLabel := range nsLabels {
				nsLabelSelector := nsLabel.Key + "/" + nsLabel.Value
				nsSet = append(nsSet, pc.configuredNamespaces.LookupNamespacesByLabelSelector(nsLabelSelector)...)
			}
			nsSet = utils.RemoveDuplicates(nsSet)
			allNamespaces := pc.configuredNamespaces.ListAll()
			nsSet = utils.Difference(allNamespaces, nsSet)
			// find all the pods that belong to the namespace set
			for _, ns := range nsSet {
				podSet = append(podSet, pc.configuredPods.LookupPodsByNamespace(ns)...)
			}
			// Add all the pods the first time we get an "in" Pod set
			if len(notInPodSet) == 0 {
				notInPodSet = append(notInPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			notInPodSet = utils.Intersect(notInPodSet, podSet)
			if len(notInPodSet) == 0 {
				return []string{}
			}

		case exists:
			podSet := []string{}
			// find all  namespaces that match the namespace key selector
			nsSet := pc.configuredNamespaces.LookupNamespacesByKey(expression.Key)
			nsSet = utils.RemoveDuplicates(nsSet)
			// find all the pods that belong to the namespace set
			for _, ns := range nsSet {
				podSet = append(podSet, pc.configuredPods.LookupPodsByNamespace(ns)...)
			}
			// Add all the pods the first time we get an "in" Pod set
			if len(existsPodSet) == 0 {
				existsPodSet = append(existsPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			existsPodSet = utils.Intersect(existsPodSet, podSet)
			if len(existsPodSet) == 0 {
				return []string{}
			}

		case doesNotExist:
			podSet := []string{}
			// find all  namespaces that match the namespace label selector
			nsSet := pc.configuredNamespaces.LookupNamespacesByKey(expression.Key)
			nsSet = utils.RemoveDuplicates(nsSet)
			allNamespaces := pc.configuredNamespaces.ListAll()
			nsSet = utils.Difference(allNamespaces, nsSet)
			// find all the pods that belong to the namespace set
			for _, ns := range nsSet {
				podSet = append(podSet, pc.configuredPods.LookupPodsByNamespace(ns)...)
			}
			// Add all the pods the first time we get an "in" Pod set
			if len(notExistPodSet) == 0 {
				notExistPodSet = append(notExistPodSet, podSet...)
			}
			// Common pods for different expressions (values are AND'ed)
			notExistPodSet = utils.Intersect(notExistPodSet, podSet)
			if len(notExistPodSet) == 0 {
				return []string{}
			}
		}
	}

	if len(inPodSet) != 0 {
		finalSet = append(finalSet, inPodSet)
	}
	if len(notInPodSet) != 0 {
		finalSet = append(finalSet, notInPodSet)
	}
	if len(existsPodSet) != 0 {
		finalSet = append(finalSet, existsPodSet)
	}
	if len(notExistPodSet) != 0 {
		finalSet = append(finalSet, notExistPodSet)
	}

	switch len(finalSet) {
	case 1:
		return finalSet[0]
	case 2:
		return utils.Intersect(finalSet[0], finalSet[1])
	case 3:
		return utils.Intersect(finalSet[0], finalSet[1], finalSet[2])
	case 4:
		return utils.Intersect(finalSet[0], finalSet[1], finalSet[2], finalSet[3])
	}

	return []string{}
}
