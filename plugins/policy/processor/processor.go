/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package processor

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"net"

	"github.com/contiv/vpp/plugins/policy/cache"
	config "github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// PolicyProcessor processes K8s State data and generates a set of Contiv
// policies for each pod with outdated configuration.
// PolicyProcessor implements the PolicyCacheWatcher interface to watch
// for changes and RESYNC events via the Policy Cache. For each change,
// it decides if the re-configuration is ready to go or if it needs to be postponed
// until more data are available. If the change carries enough information,
// the processor first determines the list of pods with outdated policy config
// and then for each of them re-calculates the set of Contiv policies
// that should be configured (the order of policies is irrelevant).
// Request for re-configuration is propagated into the layer below - the Policy
// Configurator.
type PolicyProcessor struct {
	Deps
	podIPAddressMap map[string]string
}

// Deps lists dependencies of Policy Processor.
type Deps struct {
	Log          logging.Logger
	Cache        cache.PolicyCacheAPI
	Contiv       contiv.API /* to get the Host IP */
	Configurator config.PolicyConfiguratorAPI
}

// Init initializes the Policy Processor.
func (pp *PolicyProcessor) Init() error {
	pp.Cache.Watch(pp)
	pp.podIPAddressMap = make(map[string]string)
	return nil
}

// Process re-calculates the set of Contiv policies for pods with outdated
// configuration. The order at which the pods are reconfigured or the order
// of policies listed for a given pod are all irrelevant.
func (pp *PolicyProcessor) Process(resync bool, pods []podmodel.ID) error {
	txn := pp.Configurator.NewTxn(false)
	for _, pod := range pods {
		policies := []*config.ContivPolicy{}

		// Find the policies pod in the slice is associated with
		policiesByPod := pp.Cache.LookupPoliciesByPod(pod)
		if len(policiesByPod) == 0 {
			txn.Configure(pod, policies)
			continue
		}

		for _, policyByPod := range policiesByPod {
			var policyType config.PolicyType
			found, policyData := pp.Cache.LookupPolicy(policyByPod)

			if !found {
				continue
			}

			switch policyData.PolicyType {
			case policymodel.Policy_INGRESS:
				policyType = 0
				break
			case policymodel.Policy_EGRESS:
				policyType = 1
				break
			case policymodel.Policy_INGRESS_AND_EGRESS:
				policyType = 2
				break
			default:
				policyType = 0
				break
			}

			matches := pp.calculateMatches(policyData)

			policy := &config.ContivPolicy{
				ID: policymodel.ID{
					Name:      policyData.Name,
					Namespace: policyData.Namespace,
				},
				Type:    policyType,
				Matches: matches,
			}

			policies = append(policies, policy)

		}
		pp.Log.WithField("process-resync", resync).
			Infof("Pod sent to Configurator: %+v, w/ Policies: %+v", pod, policies)
		txn.Configure(pod, policies)

	}
	return txn.Commit()
}

// Resync processes the RESYNC event by re-calculating the policies for all
// known pods.
func (pp *PolicyProcessor) Resync(data *cache.DataResyncEvent) error {
	return pp.Process(true, pp.Cache.ListAllPods())
}

// AddPod processes the event of newly added pod. The processor may postpone
// the reconfiguration until all needed data are available.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of
// them.
func (pp *PolicyProcessor) AddPod(pod *podmodel.Pod) error {
	if pod.IpAddress == "" {
		pp.Log.WithField("add-pod", pod).Warn("Pod does not have an IP Address assigned yet")
		return nil
	}

	if pod.Namespace == "kube-system" {
		pp.Log.WithField("add-pod", pod).Info("Pod belongs to kube-system namespace, ignoring")
		return nil
	}

	return nil
}

// DelPod processes the event of a removed pod.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPod(pod *podmodel.Pod) error {
	pods := []podmodel.ID{}
	policies := []*policymodel.Policy{}
	addedPolicies := make(map[string]bool)
	dataPolicies := []*policymodel.Policy{}

	// No action if Pod belongs to kube-system namespace
	if pod.Namespace == "kube-system" {
		pp.Log.WithField("del-pod", pod).Info("Pod belongs to kube-system namespace, ignoring")
		return nil
	}

	// List AllPolicies will fetch all the installed policies and append
	// Policy Data in the dataPolicies slice
	allPolicies := pp.Cache.ListAllPolicies()
	for _, stringPolicy := range allPolicies {
		found, policyData := pp.Cache.LookupPolicy(stringPolicy)
		if !found {
			continue
		}
		dataPolicies = append(dataPolicies, policyData)
	}

	// Check every policy for ingress and egress rules that match old Pod's labels
	// and append them in a slice.
	for _, dataPolicy := range dataPolicies {
		if len(dataPolicy.IngressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector
			policies = append(policies, dataPolicy)
		} else {
			for _, ingressRules := range dataPolicy.IngressRule {
				for _, ingressRule := range ingressRules.From {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if ingressRule.Pods != nil {
						matchLabels = ingressRule.Pods.MatchLabel
						matchExpressions = ingressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(pod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if ingressRule.Namespaces != nil {
						matchLabels = ingressRule.Namespaces.MatchLabel
						matchExpressions = ingressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(pod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			policies = append(policies, dataPolicy)
		} else {
			for _, egressRules := range dataPolicy.EgressRule {
				for _, egressRule := range egressRules.To {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if egressRule.Pods != nil {
						matchLabels = egressRule.Pods.MatchLabel
						matchExpressions = egressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(pod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if egressRule.Namespaces != nil {
						matchLabels = egressRule.Namespaces.MatchLabel
						matchExpressions = egressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(pod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}

				}
			}
		}
	}

	// For every matched policy find all the Pods that have the policy attached
	if len(policies) > 0 {
		for _, policy := range policies {
			namespace := policy.Namespace
			policyLabelSelectors := policy.Pods
			if len(policyLabelSelectors.MatchExpression) == 0 && len(policyLabelSelectors.MatchLabel) == 0 {
				policyPods := pp.Cache.LookupPodsByNamespace(namespace)
				pods = append(pods, policyPods...)
			} else {
				policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
				pods = append(pods, policyPods...)
			}
		}
	}
	strPods := utils.RemoveDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	// Find pods that belong to the current node.
	hostPods := []podmodel.ID{}
	for _, hostPod := range pods {
		found, hostPodData := pp.Cache.LookupPod(hostPod)

		if !found {
			continue
		}
		hostNetwork := pp.Contiv.GetPodNetwork()
		hostPodID := podmodel.GetID(hostPodData).String()
		removedPodIP := pp.podIPAddressMap[hostPodID]
		podIPAddress := net.ParseIP(removedPodIP)
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, hostPod)
	}

	pp.Log.WithField("del-pod", pod).
		Infof("Pods sent to Process: %+v", hostPods)
	if len(hostPods) > 0 {
		return pp.Process(false, hostPods)
	}

	return nil
}

// UpdatePod processes the event of changed pod data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePod(oldPod, newPod *podmodel.Pod) error {
	pods := []podmodel.ID{}
	policies := []*policymodel.Policy{}
	addedPolicies := make(map[string]bool)
	dataPolicies := []*policymodel.Policy{}

	// No action if Pod belongs to kube-system namespace
	if newPod.Namespace == "kube-system" {
		pp.Log.WithField("pod", newPod).Info("Pod belongs to kube-system namespace, ignoring")
		return nil
	}

	// No action if Pod has no IP Address
	if newPod.IpAddress == "" {
		pp.Log.WithField("pod", newPod).Warn("Pod does not have an IP Address assigned yet")
		return nil
	}

	// New and old Pod will be checked for attached policies
	newPodID := podmodel.GetID(newPod)
	pp.podIPAddressMap[newPodID.String()] = newPod.IpAddress

	// List AllPolicies will fetch all the installed policies and append
	// Policy Data in the dataPolicies slice
	allPolicies := pp.Cache.ListAllPolicies()
	for _, stringPolicy := range allPolicies {
		found, policyData := pp.Cache.LookupPolicy(stringPolicy)

		if !found {
			continue
		}

		dataPolicies = append(dataPolicies, policyData)
	}

	// Check every policy for ingress and egress rules that match old Pod's labels
	// and append them in a slice.
	for _, dataPolicy := range dataPolicies {
		if len(dataPolicy.IngressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector
			policies = append(policies, dataPolicy)
		} else {
			for _, ingressRules := range dataPolicy.IngressRule {
				for _, ingressRule := range ingressRules.From {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if ingressRule.Pods != nil {
						matchLabels = ingressRule.Pods.MatchLabel
						matchExpressions = ingressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(oldPod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if ingressRule.Namespaces != nil {
						matchLabels = ingressRule.Namespaces.MatchLabel
						matchExpressions = ingressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(oldPod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			policies = append(policies, dataPolicy)
		} else {
			for _, egressRules := range dataPolicy.EgressRule {
				for _, egressRule := range egressRules.To {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if egressRule.Pods != nil {
						matchLabels = egressRule.Pods.MatchLabel
						matchExpressions = egressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(oldPod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if egressRule.Namespaces != nil {
						matchLabels = egressRule.Namespaces.MatchLabel
						matchExpressions = egressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(oldPod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}

				}
			}
		}
	}

	// Check every policy for ingress and egress rules that match new Pod's labels
	// and append them in a slice.
	for _, dataPolicy := range dataPolicies {
		if len(dataPolicy.IngressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector
			policies = append(policies, dataPolicy)
		} else {
			for _, ingressRules := range dataPolicy.IngressRule {
				for _, ingressRule := range ingressRules.From {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if ingressRule.Pods != nil {
						matchLabels = ingressRule.Pods.MatchLabel
						matchExpressions = ingressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(newPod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if ingressRule.Namespaces != nil {
						matchLabels = ingressRule.Namespaces.MatchLabel
						matchExpressions = ingressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(newPod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			policies = append(policies, dataPolicy)
		} else {
			for _, egressRules := range dataPolicy.EgressRule {
				for _, egressRule := range egressRules.To {

					matchLabels := []*policymodel.Policy_Label{}
					matchExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					if egressRule.Pods != nil {
						matchLabels = egressRule.Pods.MatchLabel
						matchExpressions = egressRule.Pods.MatchExpression
					}
					isMatchPodSelector := pp.calculateLabelSelectorMatches(newPod, matchLabels, matchExpressions, dataPolicy.Namespace)

					if egressRule.Namespaces != nil {
						matchLabels = egressRule.Namespaces.MatchLabel
						matchExpressions = egressRule.Namespaces.MatchExpression
					}

					isMatchNamespaceSelector := pp.isNamespaceMatchLabel(newPod, matchLabels)
					if !isMatchPodSelector && isMatchNamespaceSelector {
						continue
					}

					if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
						addedPolicies[policymodel.GetID(dataPolicy).String()] = true
						policies = append(policies, dataPolicy)
					}

				}
			}
		}
	}

	// For every matched policy find all the Pods that have the policy attached.
	if len(policies) > 0 {
		for _, policy := range policies {
			namespace := policy.Namespace
			policyLabelSelectors := policy.Pods
			if len(policyLabelSelectors.MatchExpression) == 0 && len(policyLabelSelectors.MatchLabel) == 0 {
				policyPods := pp.Cache.LookupPodsByNamespace(namespace)
				pods = append(pods, policyPods...)
			} else {
				policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
				pods = append(pods, policyPods...)
			}
		}
	}

	strPods := utils.RemoveDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	pp.Log.WithField("debug-pod-processor", newPod).
		Infof("Pods sent to Process: %+v", pods)

	// Find pods that belong to the current node.
	hostPods := []podmodel.ID{}
	for _, hostPod := range pods {
		found, hostPodData := pp.Cache.LookupPod(hostPod)

		if !found {
			continue
		}
		hostNetwork := pp.Contiv.GetPodNetwork()
		podIPAddress := net.ParseIP(hostPodData.IpAddress)
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, hostPod)
	}

	pp.Log.WithField("update-pod", newPod).
		Infof("Pods sent to Process: %+v", hostPods)

	if len(hostPods) > 0 {
		return pp.Process(false, hostPods)
	}

	return nil
}

// AddPolicy processes the event of newly added policy. The processor may postpone
// the reconfiguration until all needed data are available.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// Check if policy was read correctly.
	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	namespace := policy.Namespace
	podLabelSelectors := policy.Pods

	// Find all the pods that match Policy's Pod Label Selectors
	if len(podLabelSelectors.MatchExpression) == 0 && len(podLabelSelectors.MatchLabel) == 0 {
		policyPods := pp.Cache.LookupPodsByNamespace(namespace)
		pods = append(pods, policyPods...)
	} else {
		policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, podLabelSelectors)
		pods = append(pods, policyPods...)
	}

	// Find pods that belong to the current node.
	hostPods := []podmodel.ID{}
	for _, hostPod := range pods {
		found, hostPodData := pp.Cache.LookupPod(hostPod)

		if !found {
			continue
		}
		hostNetwork := pp.Contiv.GetPodNetwork()
		podIPAddress := net.ParseIP(hostPodData.IpAddress)
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, hostPod)
	}

	if len(hostPods) > 0 {
		pp.Log.WithField("add-policy", policy).
			Infof("Pods sent to Process: %+v", hostPods)
		return pp.Process(false, hostPods)
	}
	return nil
}

// DelPolicy processes the event of a removed policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}

	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	namespace := policy.Namespace
	policyLabelSelectors := policy.Pods

	// Find all the pods that match Policy's Pod Label Selectors
	if len(policyLabelSelectors.MatchExpression) == 0 && len(policyLabelSelectors.MatchLabel) == 0 {
		policyPods := pp.Cache.LookupPodsByNamespace(namespace)
		pods = append(pods, policyPods...)
	} else {
		policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
		pods = append(pods, policyPods...)
	}

	// Find pods that belong to the current node.
	hostPods := []podmodel.ID{}
	for _, hostPod := range pods {
		found, hostPodData := pp.Cache.LookupPod(hostPod)

		if !found {
			continue
		}
		hostNetwork := pp.Contiv.GetPodNetwork()
		podIPAddress := net.ParseIP(hostPodData.IpAddress)
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, hostPod)
	}

	if len(pods) > 0 {
		pp.Log.WithField("del-policy", policy).
			Infof("Pods sent to Process: %+v", hostPods)
		return pp.Process(false, hostPods)
	}
	return nil
}

// UpdatePolicy processes the event of changed policy data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error {
	pods := []podmodel.ID{}

	if newPolicy == nil {
		pp.Log.WithField("policy", newPolicy).Error("Error reading New Policy")
		return nil
	}

	if oldPolicy == nil {
		pp.Log.WithField("policy", oldPolicy).Error("Error reading Old Policy")
		return nil
	}

	// Outdated pods using old Policy configuration
	oldNamespace := oldPolicy.Namespace
	oldPolicyLabelSelectors := oldPolicy.Pods
	if len(oldPolicyLabelSelectors.MatchExpression) == 0 && len(oldPolicyLabelSelectors.MatchLabel) == 0 {
		oldPolicyPods := pp.Cache.LookupPodsByNamespace(oldNamespace)
		pods = append(pods, oldPolicyPods...)
	} else {
		oldPolicyPods := pp.Cache.LookupPodsByNSLabelSelector(oldNamespace, oldPolicyLabelSelectors)
		pods = append(pods, oldPolicyPods...)
	}

	// Pods using new Policy configuration
	newNamespace := newPolicy.Namespace
	newPolicyLabelSelectors := newPolicy.Pods
	if len(newPolicyLabelSelectors.MatchExpression) == 0 && len(newPolicyLabelSelectors.MatchLabel) == 0 {
		newPolicyPods := pp.Cache.LookupPodsByNamespace(newNamespace)
		pods = append(pods, newPolicyPods...)
	} else {
		oldPolicyPods := pp.Cache.LookupPodsByNSLabelSelector(oldNamespace, oldPolicyLabelSelectors)
		pods = append(pods, oldPolicyPods...)
	}

	strPods := utils.RemoveDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	// Find pods that belong to the current node.
	hostPods := []podmodel.ID{}
	for _, hostPod := range pods {
		found, hostPodData := pp.Cache.LookupPod(hostPod)

		if !found {
			continue
		}
		hostNetwork := pp.Contiv.GetPodNetwork()
		podIPAddress := net.ParseIP(hostPodData.IpAddress)
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, hostPod)
	}

	if len(pods) > 0 {
		return pp.Process(false, hostPods)
	}
	return nil
}

// AddNamespace processes the event of newly added namespace. The processor may
// postpone the reconfiguration until all needed data are available.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	if ns == nil {
		pp.Log.WithField("namespace", ns).Error("Error reading Namespace")
		return nil
	}
	return pp.Process(false, pods)
}

// DelNamespace processes the event of a removed namespace.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	if ns == nil {
		pp.Log.WithField("namespace", ns).Error("Error reading Namespace")
		return nil
	}
	return pp.Process(false, pods)
}

// UpdateNamespace processes the event of changed namespace data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	if newNs == nil {
		pp.Log.WithField("namespace", newNs).Error("Error reading Namespace")
		return nil
	}
	return pp.Process(false, pods)
}

// Close deallocates all resources held by the processor.
func (pp *PolicyProcessor) Close() error {
	return nil
}
