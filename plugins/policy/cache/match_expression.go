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

func (pc *PolicyCache) getMatchExpressionPods(namespace string, expressions []*policymodel.Policy_LabelSelector_LabelExpression) (bool, []string) {
	var inPodSet, notInPodSet []string
	for _, expression := range expressions {
		switch expression.Operator {
		case In:
			labels := constructLabels(expression.Key, expression.Value)
			isMatch, podSet := pc.getPodsByNSLabelSelector(namespace, labels)
			if !isMatch {
				return false, nil
			}
			inPodSet = append(inPodSet, podSet...)
		//case NotIn:
		//	labels := constructLabels(expression.Key, expression.Value)
		//	isMatch
		case Exists:
			labels := constructLabels(expression.Key, expression.Value)
			isMatch, podSet := pc.getPodsByNSKeyPods(namespace, labels)
			if !isMatch {
				return false, nil
			}
			notInPodSet = append(notInPodSet, podSet...)
			//case DoesNotExist:
		}
	}
	matcher := intersect(inPodSet, notInPodSet)
	if matcher == nil {
		return false, nil
	}
	return true, matcher
}

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

func difference(a []string, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]bool)

	for _, el := range a {
		hash[el] = true
	}

	for _, el := range b {
		if _, found := hash[el]; !found {
			set = append(set, el)
		}
	}
	return set
}
