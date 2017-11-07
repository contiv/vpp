package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

func (pp *PolicyProcessor) isMatchLabel(pod *podmodel.Pod, matchLabel []*policymodel.Policy_Label, policyNamespace string) bool {
	namespace := pod.Namespace
	podLabels := pod.Label
	labelExists := make(map[string]bool)

	for _, podLabel := range podLabels {
		label := namespace + podLabel.Key + "/" + podLabel.Value
		labelExists[label] = true
	}

	isMatch := true
	i := 0
	for isMatch {
		label := policyNamespace + "/" + matchLabel[i].Key + "/" + matchLabel[i].Value
		if labelExists[label] == true {
			i++
		} else {
			isMatch = false
		}
	}

	return isMatch

}
