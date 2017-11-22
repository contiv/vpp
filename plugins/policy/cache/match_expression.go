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

// getMatchExpressionPods returns all the pods that match a collection of expressions (expressions are ANDed)
func (pc *PolicyCache) getMatchExpressionPods(namespace string, expressions []*policymodel.Policy_LabelSelector_LabelExpression) (bool, []string) {
	var inPodSet, notInPodSet, existsPodSet, notExistPodSet []string
	for _, expression := range expressions {
		switch expression.Operator {
		case in:
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			isMatch, podSet := pc.getPodsByNSLabelSelector(namespace, labels)
			if !isMatch {
				return false, nil
			}

			inPodSet = append(inPodSet, podSet...)

		case notIn:
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			isMatch, podSet := pc.getPodsByNSLabelSelector(namespace, labels)
			if !isMatch {
				podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
				if podNamespaceAll == nil {
					return false, nil
				}
				notInPodSet = append(notInPodSet, podNamespaceAll...)
				break
			}

			podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
			pods := utils.Difference(podNamespaceAll, podSet)
			notInPodSet = append(notInPodSet, pods...)
			if notInPodSet == nil {
				return false, nil
			}

		case exists:
			podSet := pc.configuredPods.LookupPodsByNSKey(namespace + "/" + expression.Key)
			if podSet == nil {
				return false, nil
			}

			existsPodSet = append(existsPodSet, podSet...)

		case doesNotExist:
			podSet := pc.configuredPods.LookupPodsByNSKey(namespace + "/" + expression.Key)
			if podSet == nil {
				podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
				if podNamespaceAll == nil {
					return false, nil
				}

				notExistPodSet = append(notExistPodSet, podNamespaceAll...)
				break
			}

			podNamespaceAll := pc.configuredPods.LookupPodsByNamespace(namespace)
			pods := utils.Difference(podNamespaceAll, podSet)
			notExistPodSet = append(notExistPodSet, pods...)
			if notExistPodSet == nil {
				return false, nil
			}

		}
	}
	// Remove duplicates from slices
	inPodSet = utils.RemoveDuplicates(inPodSet)
	notInPodSet = utils.RemoveDuplicates(inPodSet)
	existsPodSet = utils.RemoveDuplicates(inPodSet)
	notExistPodSet = utils.RemoveDuplicates(inPodSet)

	inMatcher := utils.Intersect(inPodSet, notInPodSet)
	if inMatcher == nil {
		return false, nil
	}
	existsMatcher := utils.Intersect(existsPodSet, notExistPodSet)
	if existsMatcher == nil {
		return false, nil
	}

	pods := utils.Intersect(inMatcher, existsMatcher)
	if pods == nil {
		return false, nil
	}
	return true, pods
}
