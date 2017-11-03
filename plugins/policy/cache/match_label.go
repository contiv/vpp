package cache

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
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

		tmp := intersect(prevPodSet, newPodSet)
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

	prevNSLabelSelector := namespace + "/" + labels[0].Key + "/" + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}

	if len(labels) == 1 {
		return true, prevPodSet
	}

	for i := 1; i < len(labels); i++ {
		newLabelSelector := labels[i].Key + "/" + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newLabelSelector)

		tmp := intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}

	return true, newPodSet
}

// Intersect returns the common elements of two slices
func intersect(a []string, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]bool)

	for _, el := range a {
		hash[el] = true
	}

	for _, el := range b {
		if _, found := hash[el]; found {
			set = append(set, el)
		}
	}
	return set
}
