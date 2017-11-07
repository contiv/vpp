package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

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
