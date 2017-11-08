package cache

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// GetPodsByNSLabelSelector returns the pods that match a collection of Label Selectors in the same namespace
func (pc *PolicyCache) getPodsByNSLabelSelector(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {

	prevNSLabelSelector := namespace + "/" + labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByNSLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}

	if len(labels) == 1 {
		return true, prevPodSet
	}

	for i := 1; i < len(labels); i++ {
		newNSLabelSelector := namespace + "/" + labels[i].Key + "/" + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByNSLabelSelector(newNSLabelSelector)

		tmp := utils.Intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}

	return true, newPodSet
}

// GetPodsByNSLabelSelector returns the pods that match a collection of Label Selectors in the same namespace
func (pc *PolicyCache) getPodsByLabelSelector(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {

	prevNSLabelSelector := labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}

	if len(labels) == 1 {
		return true, prevPodSet
	}

	for i := 1; i < len(labels); i++ {
		newLabelSelector := labels[i].Key + "/" + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newLabelSelector)

		tmp := utils.Intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}

	return true, newPodSet
}
