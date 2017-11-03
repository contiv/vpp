package cache

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

const (
	In           = policymodel.Policy_LabelSelector_LabelExpression_IN
	NotIn        = policymodel.Policy_LabelSelector_LabelExpression_NOT_IN
	Exists       = policymodel.Policy_LabelSelector_LabelExpression_EXISTS
	DoesNotExist = policymodel.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST
)

// getMatchExpressionPods returns all the pods that match a collection of expressions (expressions are ANDed)
func (pc *PolicyCache) getMatchExpressionPods(namespace string, expressions []*policymodel.Policy_LabelSelector_LabelExpression) (bool, []string) {
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
			pods := difference(podNamespaceAll, podSet)
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
			pods := difference(podNamespaceAll, podSet)
			notExistPodSet = append(notExistPodSet, pods...)
			if notExistPodSet == nil {
				return false, nil
			}

		}
	}
	// Remove duplicates from slices
	inPodSet = removeDuplicates(inPodSet)
	notInPodSet = removeDuplicates(inPodSet)
	existsPodSet = removeDuplicates(inPodSet)
	notExistPodSet = removeDuplicates(inPodSet)

	inMatcher := intersect(inPodSet, notInPodSet)
	if inMatcher == nil {
		return false, nil
	}
	existsMatcher := intersect(existsPodSet, notExistPodSet)
	if existsMatcher == nil {
		return false, nil
	}

	pods := intersect(inMatcher, existsMatcher)
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

// difference returns the difference of two slices
func difference(a []string, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]bool)
	// Populate the map
	for _, el := range a {
		hash[el] = true
	}
	//Append to slice for every element that exists on the hash
	for _, el := range b {
		if _, found := hash[el]; !found {
			set = append(set, el)
		}
	}
	return set
}

func removeDuplicates(el []string) []string {
	found := map[string]bool{}

	// Create a map of all unique elements.
	for v := range el {
		found[el[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key, _ := range found {
		result = append(result, key)
	}
	return result
}
