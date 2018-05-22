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
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
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

// isPodLabelSelectorMatch finds if podLabelSelecor matches Pod's labels or not
func (pp *PolicyProcessor) isPodLabelSelectorMatch(
	pod *podmodel.Pod,
	matchPodLabels []*policymodel.Policy_Label,
	matchPodExpressions []*policymodel.Policy_LabelSelector_LabelExpression,
	policyNamespace string) bool {

	// if we have both pod label selectors and expressions,
	// results are AND'ed and both functions must return true. If only one label selector exists
	// then the calling function must be true
	if len(matchPodLabels) > 0 && len(matchPodExpressions) > 0 {
		if pp.isPodLabelMatch(pod, matchPodLabels, policyNamespace) &&
			pp.isPodExpressionMatch(pod, matchPodExpressions, policyNamespace) {
			return true
		}
		return false

	} else if len(matchPodLabels) == 0 && len(matchPodExpressions) > 0 {
		if pp.isPodExpressionMatch(pod, matchPodExpressions, policyNamespace) {
			return true
		}
		return false

	} else if len(matchPodLabels) > 0 && len(matchPodExpressions) == 0 {
		if pp.isPodLabelMatch(pod, matchPodLabels, policyNamespace) {
			return true
		}
		return false

	}
	// Empty label selector (both podLabels and podExpressions)
	// returns true as it matches all the resources
	return true
}

// isPodLabelMatch finds if pod labels match a collection of pod label selectors.
func (pp *PolicyProcessor) isPodLabelMatch(pod *podmodel.Pod,
	matchPodLabels []*policymodel.Policy_Label, policyNamespace string) bool {

	podNamespace := pod.Namespace
	podLabels := pod.Label

	// create a map with current pod's labels
	existMap := make(map[string]bool)
	labelPrefix := policyNamespace + "/"
	for _, podLabel := range podLabels {
		labelExistsKey := podNamespace + podLabel.Key + "/" + podLabel.Value
		existMap[labelExistsKey] = true
	}

	return isMatchLabel(matchPodLabels, existMap, labelPrefix)
}

// isPodExpressionMatch finds if pod labels match a collection of pod selector expressions.
func (pp *PolicyProcessor) isPodExpressionMatch(pod *podmodel.Pod,
	matchPodExpressions []*policymodel.Policy_LabelSelector_LabelExpression, policyNamespace string) bool {

	podNamespace := pod.Namespace
	podLabels := pod.Label

	// create a map with current pod's labels
	existMap := make(map[string]bool)
	labelPrefix := policyNamespace + "/"
	for _, podLabel := range podLabels {
		labelExistsKey := podNamespace + "/" + podLabel.Key + "/" + podLabel.Value
		keyExistsKey := podNamespace + "/" + podLabel.Key
		existMap[keyExistsKey] = true
		existMap[labelExistsKey] = true
	}

	return isMatchExpression(matchPodExpressions, existMap, labelPrefix)
}

// isNsLabelSelectorMatch finds if namespace LabelSelector matches Pod's namespace labels.
func (pp *PolicyProcessor) isNsLabelSelectorMatch(
	pod *podmodel.Pod,
	matchNsLabels []*policymodel.Policy_Label,
	matchNsExpressions []*policymodel.Policy_LabelSelector_LabelExpression) bool {

	// if we have both namespace label selectors and expressions,
	// results are AND'ed and both functions must return true. If only one label selector exists
	// then the calling function must be true
	if len(matchNsLabels) > 0 && len(matchNsExpressions) > 0 {
		if !pp.isNsLabelMatch(pod, matchNsLabels) ||
			!pp.isNsExpressionMatch(pod, matchNsExpressions) {
			return false
		}
		return true

	} else if len(matchNsLabels) == 0 && len(matchNsExpressions) > 0 {
		if !pp.isNsExpressionMatch(pod, matchNsExpressions) {
			return false
		}
		return true

	} else if len(matchNsLabels) > 0 && len(matchNsExpressions) == 0 {
		if !pp.isNsLabelMatch(pod, matchNsLabels) {
			return false
		}
		return true

	}
	// Empty label selector (both podLabels and podExpressions)
	// returns true as it matches all the resources
	return true
}

// isNsLabelMatch finds if pod's namespace labels match a collection of namespace selector labels.
func (pp *PolicyProcessor) isNsLabelMatch(pod *podmodel.Pod,
	matchNsLabels []*policymodel.Policy_Label) bool {

	// Get Pod's namespace labels
	podNamespaceID := nsmodel.ID(pod.Namespace)
	_, nsData := pp.Cache.LookupNamespace(podNamespaceID)
	nsLabels := nsData.Label

	// create a map with current namespace's labels
	existMap := make(map[string]bool)
	labelPrefix := ""
	for _, nsLabel := range nsLabels {
		labelExistsKey := nsLabel.Key + "/" + nsLabel.Value
		existMap[labelExistsKey] = true
	}

	return isMatchLabel(matchNsLabels, existMap, labelPrefix)
}

// isNsExpressionMatch finds if pod's namespace labels match a collection of namespace selector expressions.
func (pp *PolicyProcessor) isNsExpressionMatch(pod *podmodel.Pod,
	matchNsExpressions []*policymodel.Policy_LabelSelector_LabelExpression) bool {

	//Get Pod's namespace labels
	podNamespaceID := nsmodel.ID(pod.Namespace)
	_, nsData := pp.Cache.LookupNamespace(podNamespaceID)
	nsLabels := nsData.Label

	// create a map with current pod's labels
	existMap := make(map[string]bool)
	labelPrefix := ""
	for _, nsLabel := range nsLabels {
		labelExistsKey := nsLabel.Key + "/" + nsLabel.Value
		keyExistsKey := nsLabel.Key
		existMap[labelExistsKey] = true
		existMap[keyExistsKey] = true
	}

	return isMatchExpression(matchNsExpressions, existMap, labelPrefix)
}

// isNsUpdateLabelSelectorMatch finds if pod's namespace labels match a collection of namespace selector labels,
// after an update in namespace labels
func (pp *PolicyProcessor) isNsUpdateLabelSelectorMatch(
	ns *nsmodel.Namespace,
	matchNsUpdateLabels []*policymodel.Policy_Label,
	matchNsUpdateExpressions []*policymodel.Policy_LabelSelector_LabelExpression) bool {

	// if we have both namespace label selectors and expressions,
	// results are AND'ed and both functions must return true. If only one label selector exists
	// then the calling function must be true
	if len(matchNsUpdateLabels) > 0 && len(matchNsUpdateExpressions) > 0 {
		if !pp.isNsUpdateLabelMatch(ns, matchNsUpdateLabels) ||
			!pp.isNsUpdateExpressionMatch(ns, matchNsUpdateExpressions) {
			return false
		}
		return true

	} else if len(matchNsUpdateLabels) == 0 && len(matchNsUpdateExpressions) > 0 {
		if !pp.isNsUpdateExpressionMatch(ns, matchNsUpdateExpressions) {
			return false
		}
		return true

	} else if len(matchNsUpdateLabels) > 0 && len(matchNsUpdateExpressions) == 0 {
		if !pp.isNsUpdateLabelMatch(ns, matchNsUpdateLabels) {
			return false
		}
		return true

	}

	// Empty label selector (both podLabels and podExpressions)
	// returns true as it matches all the resources
	return true
}

// isNsUpdateLabelMatch finds if namespace LabelSelector matches Pod's namespace labels,
// after an update in namespace labels
func (pp *PolicyProcessor) isNsUpdateLabelMatch(ns *nsmodel.Namespace,
	matchNsUpdateLabels []*policymodel.Policy_Label) bool {
	//Get Pod's namespace labels
	_, nsData := pp.Cache.LookupNamespace(nsmodel.GetID(ns))
	nsLabels := nsData.Label

	// create a map with current namespace's labels
	existMap := make(map[string]bool)
	labelPrefix := ""
	for _, nsLabel := range nsLabels {
		labelExistsKey := nsLabel.Key + "/" + nsLabel.Value
		existMap[labelExistsKey] = true
	}

	return isMatchLabel(matchNsUpdateLabels, existMap, labelPrefix)
}

// isNsUpdateExpressionMatch finds if pod's namespace labels match a collection of namespace selector expressions,
// after an update in namespace labels
func (pp *PolicyProcessor) isNsUpdateExpressionMatch(ns *nsmodel.Namespace,
	matchNsUpdateExpressions []*policymodel.Policy_LabelSelector_LabelExpression) bool {

	//Get Pod's namespace labels
	_, nsData := pp.Cache.LookupNamespace(nsmodel.GetID(ns))
	nsLabels := nsData.Label

	// create a map with current pod's labels
	existMap := make(map[string]bool)
	labelPrefix := ""
	for _, nsLabel := range nsLabels {
		labelExistsKey := nsLabel.Key + "/" + nsLabel.Value
		keyExistsKey := nsLabel.Key
		existMap[labelExistsKey] = true
		existMap[keyExistsKey] = true
	}

	return isMatchExpression(matchNsUpdateExpressions, existMap, labelPrefix)
}

// isMatchLabel checks if labels are matching a given map of existing labels that we compare against
func isMatchLabel(matchLabels []*policymodel.Policy_Label, labelExists map[string]bool, matchLabelPrefix string) bool {

	isMatch := true
	for _, matchLabel := range matchLabels {
		labelExistsKey := matchLabelPrefix + matchLabel.Key + "/" + matchLabel.Value
		if labelExists[labelExistsKey] != true {
			isMatch = false
			break
		}
	}

	return isMatch
}

// isMatchExpression checks if expressions are matching a given map of existing expressions that we compare against
func isMatchExpression(matchExpressions []*policymodel.Policy_LabelSelector_LabelExpression,
	existMap map[string]bool, expressionKeyPrefix string) bool {

	isMatch := false
	for _, matchExpression := range matchExpressions {
		switch matchExpression.Operator {
		case in:
			labels := utils.ConstructLabels(matchExpression.Key, matchExpression.Value)
			for _, label := range labels {
				expressionKey := expressionKeyPrefix + label.Key + label.Value
				if existMap[expressionKey] == true {
					isMatch = true
					break
				} else {
					isMatch = false
				}
			}
			if !isMatch {
				return false
			}

		case notIn:
			labels := utils.ConstructLabels(matchExpression.Key, matchExpression.Value)
			for _, label := range labels {
				expressionKey := expressionKeyPrefix + label.Key + label.Value
				if existMap[expressionKey] == true {
					return false
				}
			}
			isMatch = true

		case exists:
			expressionKey := expressionKeyPrefix + matchExpression.Key
			if existMap[expressionKey] == false {
				return false
			}
			isMatch = true

		case doesNotExist:
			expressionKey := expressionKeyPrefix + matchExpression.Key
			if existMap[expressionKey] == true {
				return false
			}
			isMatch = true
		}
	}

	return isMatch
}
