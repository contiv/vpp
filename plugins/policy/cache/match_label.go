package cache

import (
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

func (pc *PolicyCache) getPodsByNSLabelSelector(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {
	testPod := pc.configuredPods.ListAll()
	pc.Log.Infof("Should have all the pods: %+v", testPod)
	prevNSLabelSelector := namespace + labels[0].Key + labels[0].Value
	prevPodSet := pc.configuredPods.LookupPodsByNSLabelSelector(prevNSLabelSelector)
	newPodSet := []string{}
	//todo remove debug logs
	pc.Log.Infof("This is pods by nsls: %s", prevPodSet)
	if len(labels) == 1 {
		return true, prevPodSet
	}
	for i := 1; i < len(labels); i++ {
		newNSLabelSelector := namespace + labels[i].Key + labels[i].Value
		newPodSet = pc.configuredPods.LookupPodsByNSLabelSelector(newNSLabelSelector)
		pc.Log.Infof("Podset1: %+v, Podset2: %+v", prevPodSet, newPodSet)

		tmp := intersect(prevPodSet, newPodSet)
		if len(tmp) == 0 {
			return false, nil
		}

		prevPodSet = newPodSet
		newPodSet = tmp
		pc.Log.Infof("Pods after intersect: %s, - %s", prevPodSet, newPodSet)
	}
	return true, newPodSet
}

func (pc *PolicyCache) getPodsByNSKeyPods(namespace string, labels []*policymodel.Policy_Label) (bool, []string) {
	prevLabelSelector := namespace + labels[0].Key
	prevPodSet := pc.configuredPods.LookupPodsByNSKey(prevLabelSelector)
	newPodSet := []string{}
	if len(labels) < 1 {
		return true, prevPodSet
	}
	for i := 1; i < len(labels); i++ {

		newPodLabelSelector := namespace + labels[i].Key
		newPodSet = pc.configuredPods.LookupPodsByNSKey(newPodLabelSelector)

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
