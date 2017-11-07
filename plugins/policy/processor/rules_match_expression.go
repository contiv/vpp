package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache/utils"
)

const (
	In           = policymodel.Policy_LabelSelector_LabelExpression_IN
	NotIn        = policymodel.Policy_LabelSelector_LabelExpression_NOT_IN
	Exists       = policymodel.Policy_LabelSelector_LabelExpression_EXISTS
	DoesNotExist = policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST
)

// getMatchExpressionPods returns all the pods that match a collection of expressions (expressions are ANDed)
func (pp *PolicyProcessor) isMatchExpression(pod *podmodel.Pod,
	expressions []*policymodel.Policy_LabelSelector_LabelExpression, namespace string) bool {

	namespace := pod.Namespace
	podLabels := pod.Label
	labelExists := make(map[string]bool)

	for _, podLabel := range podLabels {
		label := namespace + podLabel.Key + "/" + podLabel.Value
		labelExists[label] = true
	}

	var inPodSet, notInPodSet, existsPodSet, notExistPodSet []string
	for _, expression := range expressions {
		switch expression.Operator {
		case In:
			labels := constructLabels(expression.Key, expression.Value)
			isMatch, podSet := pc.getPodsByNSLabelSelector(namespace, labels)
			if !isMatch {
				return false, nil
			}

			inPodSet = append(inPodSet, podSet...)

		case NotIn:
			labels := constructLabels(expression.Key, expression.Value)
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

		case Exists:
			podSet := pc.configuredPods.LookupPodsByNSKey(namespace + "/" + expression.Key)
			if podSet == nil {
				return false, nil
			}

			existsPodSet = append(existsPodSet, podSet...)

		case DoesNotExist:
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

// constructLabels returns a key-value pair as a label given an expression
func constructLabels(key string, values []string) []*policymodel.Policy_Label {
	policyLabel := []*policymodel.Policy_Label{}
	for _, label := range values {
		policyLabel = append(policyLabel,
			&policymodel.Policy_Label{
				Key:   key,
				Value: label,
			})
	}
	return policyLabel
}
