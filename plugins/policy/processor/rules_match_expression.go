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
	"github.com/contiv/vpp/plugins/policy/utils"
)

const (
	in           = policymodel.Policy_LabelSelector_LabelExpression_IN
	notIn        = policymodel.Policy_LabelSelector_LabelExpression_NOT_IN
	exists       = policymodel.Policy_LabelSelector_LabelExpression_EXISTS
	doesNotExist = policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST
)

// isMatchExpression returns all the pods that match a collection of expressions (expressions are ANDed)
func (pp *PolicyProcessor) isMatchExpression(pod *podmodel.Pod,
	expressions []*policymodel.Policy_LabelSelector_LabelExpression, policyNamespace string) bool {

	podNamespace := pod.Namespace
	podLabels := pod.Label
	podKeyMap := make(map[string]bool)

	for _, podLabel := range podLabels {
		podKey := podNamespace + "/" + podLabel.Key
		podKeyMap[podKey] = true
	}

	for _, expression := range expressions {
		switch expression.Operator {
		case in:
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			isMatch := pp.isMatchLabel(pod, labels, policyNamespace)
			if !isMatch {
				return false
			}

		case notIn:
			labels := utils.ConstructLabels(expression.Key, expression.Value)
			isMatch := pp.isMatchLabel(pod, labels, policyNamespace)
			if isMatch {
				return false
			}

		case exists:
			expressionKey := policyNamespace + "/" + expression.Key
			if podKeyMap[expressionKey] == true {
				return true
			}

		case doesNotExist:
			expressionKey := policyNamespace + "/" + expression.Key
			if podKeyMap[expressionKey] != true {
				return false
			}
		}
	}
	return true
}
