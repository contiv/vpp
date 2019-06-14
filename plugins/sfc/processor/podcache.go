package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

type podInfo struct {
	id     podmodel.ID
	labels map[string]string
	local  bool
}

func (sp *SFCProcessor) podMatchesSelector(pod *podInfo, podSelector map[string]string) bool {
	if len(pod.labels) == 0 {
		return false
	}
	for selKey, selVal := range podSelector {
		match := false

		for podLabelKey, podLabelVal := range pod.labels {
			if podLabelKey == selKey && podLabelVal == selVal {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}
