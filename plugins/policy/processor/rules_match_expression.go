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
