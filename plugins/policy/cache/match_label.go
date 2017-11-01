package cache

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

func (pc *PolicyCache) getMatchLabelPods(labels []*policymodel.Policy_Label) (bool, []string) {
	prevLabelSelector := labels[0].Key + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByLabelSelector(prevLabelSelector)
	newPodSet := []string{}
	for i := 1; i < len(labels); i++ {

		newPodLabelSelector := labels[i].Key + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newPodLabelSelector)

		tmp := intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}
	return true, newPodSet
}

func (pc *PolicyCache) getMatchLabelByKeyPods(labels []*policymodel.Policy_Label) (bool, []string) {
	prevLabelSelector := labels[0].Key
	prevPodSet := pc.configuredPods.LookupPodsByLabelKey(prevLabelSelector)
	newPodSet := []string{}
	for i := 1; i < len(labels); i++ {

		newPodLabelSelector := labels[i].Key
		newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newPodLabelSelector)

		tmp := intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
	}
	return true, newPodSet
}

// todo - brecode: check if there is a more efficient way to do this
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

//case "difference":
//prevKeySelector := labels[0].Key
//prevPodSet := pc.configuredPods.LookupPodsByLabelKey(prevKeySelector)
//newPodSet := []string{}
//for i := 1; i < len(labels); i++ {
//
//newPodLabelSelector := labels[i].Key + labels[i].Value
//newPodSet = pc.configuredPods.LookupPodsByLabelSelector(newPodLabelSelector)
//
//tmp := difference(prevPodSet, newPodSet)
//if len(tmp) == 0 {
//return false, nil
//}
//
//prevPodSet = newPodSet
//newPodSet = tmp
//}
//return true, newPodSet
