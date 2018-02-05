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
	"fmt"
	"net"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
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
	podIPAddressMap map[podmodel.ID]net.IP
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
	pp.podIPAddressMap = make(map[podmodel.ID]net.IP)
	pp.Cache.Watch(pp)
	return nil
}

// Process re-calculates the set of Contiv policies for pods with outdated
// configuration. The order at which the pods are reconfigured or the order
// of policies listed for a given pod are all irrelevant.
func (pp *PolicyProcessor) Process(resync bool, pods []podmodel.ID) error {
	txn := pp.Configurator.NewTxn(false)
	processedPolicies := make(map[policymodel.ID]*config.ContivPolicy)
	var contivPolicy *config.ContivPolicy
	var alreadyProcessed bool

	for _, pod := range pods {
		policies := []*config.ContivPolicy{}

		// Find the policies the pod in the slice is associated with.
		policiesByPod := pp.Cache.LookupPoliciesByPod(pod)
		if len(policiesByPod) == 0 {
			txn.Configure(pod, policies)
			continue
		}

		// Convert each policy from the Kubernetes data model to an instance of ContivPolicy.
		for _, policy := range policiesByPod {
			if contivPolicy, alreadyProcessed = processedPolicies[policy]; !alreadyProcessed {

				var policyType config.PolicyType
				found, policyData := pp.Cache.LookupPolicy(policy)

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

				contivPolicy = &config.ContivPolicy{
					ID: policymodel.ID{
						Name:      policyData.Name,
						Namespace: policyData.Namespace,
					},
					Type:    policyType,
					Matches: matches,
				}
				processedPolicies[policy] = contivPolicy
			}

			policies = append(policies, contivPolicy)
		}

		// Re-configure policies for the pod.
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

// AddPod processes the event of newly added pod. The processor will postpone
// the reconfiguration until all needed data are available (IP address).
func (pp *PolicyProcessor) AddPod(podID podmodel.ID, pod *podmodel.Pod) error {
	pp.Log.WithField("pod", pod).Info("Pod was added")

	if pod.IpAddress == "" {
		pp.Log.WithField("add-pod", pod).Info("Pod does not have an IP Address assigned yet")
		return nil
	}

	if pod.Namespace == "kube-system" {
		pp.Log.WithField("add-pod", pod).Info("Pod belongs to kube-system namespace, ignoring")
		return nil
	}

	return nil
}

// DelPod processes the event of a removed pod (no action needed).
func (pp *PolicyProcessor) DelPod(podID podmodel.ID, pod *podmodel.Pod) error {
	pp.Log.WithField("podID", podID).Info("Pod was removed")
	/* Already un-configured when the pod has lost its IP address */
	return nil
}

// UpdatePod processes the event of changed pod data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePod(podID podmodel.ID, oldPod, newPod *podmodel.Pod) error {
	pp.Log.WithFields(logging.Fields{
		"podID":   podID,
		"new-pod": newPod,
		"old-pod": oldPod,
	}).Info("Pod was updated")

	fmt.Printf("Update Pod old: %+v %p\n", *oldPod, oldPod)
	fmt.Printf("Update Pod new: %+v %p\n", *newPod, newPod)

	// No action if Pod belongs to kube-system namespace
	if newPod.Namespace == "kube-system" {
		pp.Log.WithField("pod", newPod).Info("Pod belongs to kube-system namespace, ignoring")
		return nil
	}

	if newPod.IpAddress != "" {
		pp.podIPAddressMap[podID] = net.ParseIP(newPod.IpAddress)
	} else {
		if oldPod.IpAddress != "" {
			pp.Log.WithField("update-pod", newPod).Debug("Pod does not have an IP Address assigned anymore")
		} else {
			pp.Log.WithField("update-pod", newPod).Debug("Pod does not have an IP Address assigned yet")
			return nil
		}
	}

	// For every matched policy (before and now), find all the pods that have the policy attached.
	pods := []podmodel.ID{}
	if oldPod.IpAddress != "" {
		oldPolicies := pp.getPoliciesAssignedToPod(oldPod)
		for _, policy := range oldPolicies {
			pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
		}
	}
	if newPod.IpAddress != "" {
		newPolicies := pp.getPoliciesAssignedToPod(newPod)
		for _, policy := range newPolicies {
			pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
		}
	}
	strPods := utils.RemoveDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	// Re-configure only pods that belong to the current node.
	hostPods := pp.filterHostPods(pods)

	pp.Log.WithField("update-pod", newPod).
		Infof("Pods sent to Process: %+v", hostPods)

	if len(hostPods) > 0 {
		return pp.Process(false, hostPods)
	}

	return nil
}

// AddPolicy processes the event of newly added policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddPolicy(policy *policymodel.Policy) error {
	pp.Log.WithField("policy", policy).Info("Policy was added")

	// Check if policy was read correctly.
	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	// Find all the pods that match the newly added policy.
	pods := pp.getPodsAssignedToPolicy(policy)

	// Re-configure only pods that belong to the current node.
	hostPods := pp.filterHostPods(pods)

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
	pp.Log.WithField("policy", policy).Info("Policy was deleted")

	// Check if policy was read correctly.
	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	// Find all the pods that used to match the removed policy.
	pods := pp.getPodsAssignedToPolicy(policy)

	// Re-configure only pods that belong to the current node.
	hostPods := pp.filterHostPods(pods)

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
	pp.Log.WithFields(logging.Fields{
		"new-policy": newPolicy,
		"old-policy": oldPolicy,
	}).Info("Policy was updated")

	if newPolicy == nil {
		pp.Log.WithField("policy", newPolicy).Error("Error reading New Policy")
		return nil
	}

	if oldPolicy == nil {
		pp.Log.WithField("policy", oldPolicy).Error("Error reading Old Policy")
		return nil
	}

	// Get all matching pods before the change and now.
	pods := []podmodel.ID{}
	pods = append(pods, pp.getPodsAssignedToPolicy(oldPolicy)...)
	pods = append(pods, pp.getPodsAssignedToPolicy(newPolicy)...)
	strPods := utils.RemoveDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	// Re-configure only pods that belong to the current node.
	hostPods := pp.filterHostPods(pods)

	if len(pods) > 0 {
		return pp.Process(false, hostPods)
	}
	return nil
}

// AddNamespace processes the event of newly added namespace (no action needed).
func (pp *PolicyProcessor) AddNamespace(ns *nsmodel.Namespace) error {
	pp.Log.WithField("ns", ns).Info("Namespace was added")
	return nil
}

// DelNamespace processes the event of a removed namespace (no action needed).
func (pp *PolicyProcessor) DelNamespace(ns *nsmodel.Namespace) error {
	pp.Log.WithField("ns", ns).Info("Namespace was deleted")
	return nil
}

// UpdateNamespace processes the event of changed namespace data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error {
	pp.Log.WithFields(logging.Fields{
		"new-ns": newNs,
		"old-ns": oldNs,
	}).Info("Namespace was updated")

	pods := []podmodel.ID{}
	if newNs == nil {
		pp.Log.WithField("namespace", newNs).Error("Error reading Namespace")
		return nil
	}
	// TODO
	return pp.Process(false, pods)
}

// Close deallocates all resources held by the processor.
func (pp *PolicyProcessor) Close() error {
	return nil
}

// filterHostPods filters out pods from the passed list which are not deployed
// on the current node.
func (pp *PolicyProcessor) filterHostPods(pods []podmodel.ID) []podmodel.ID {
	var (
		podIPAddress net.IP
		hadIP        bool
		hostPods     []podmodel.ID
	)
	hostNetwork := pp.Contiv.GetPodNetwork()

	for _, podID := range pods {
		found, podData := pp.Cache.LookupPod(podID)

		if !found {
			continue
		}

		if podData.IpAddress == "" {
			if podIPAddress, hadIP = pp.podIPAddressMap[podmodel.GetID(podData)]; !hadIP {
				continue
			}
		} else {
			podIPAddress = net.ParseIP(podData.IpAddress)
		}
		if !hostNetwork.Contains(podIPAddress) {
			continue
		}
		hostPods = append(hostPods, podID)
	}
	return hostPods
}

// getPodsAssignedToPolicy returns all pods that have the given policy assigned.
func (pp *PolicyProcessor) getPodsAssignedToPolicy(policy *policymodel.Policy) (pods []podmodel.ID) {
	namespace := policy.Namespace
	policyLabelSelectors := policy.Pods
	if len(policyLabelSelectors.MatchExpression) == 0 && len(policyLabelSelectors.MatchLabel) == 0 {
		return pp.Cache.LookupPodsByNamespace(namespace)
	}

	return pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
}

// getPoliciesAssignedToPod returns all policies currently assigned to a given pod.
func (pp *PolicyProcessor) getPoliciesAssignedToPod(pod *podmodel.Pod) (policies map[policymodel.ID]*policymodel.Policy) {
	policies = make(map[policymodel.ID]*policymodel.Policy)

	// Fetch data of all policies from the cache.
	allPolicies := pp.Cache.ListAllPolicies()
	dataPolicies := []*policymodel.Policy{}
	for _, policy := range allPolicies {
		found, policyData := pp.Cache.LookupPolicy(policy)

		if !found {
			continue
		}

		dataPolicies = append(dataPolicies, policyData)
	}

	// Select policies that match pod's labels.
	for _, dataPolicy := range dataPolicies {
		dataPolicyID := policymodel.GetID(dataPolicy)
		if len(dataPolicy.IngressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector.
			policies[dataPolicyID] = dataPolicy
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
					if !isMatchPodSelector && !isMatchNamespaceSelector {
						continue
					}

					policies[dataPolicyID] = dataPolicy
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			// If Egress Rule is an empty array, policy matches the PodSelector.
			policies[dataPolicyID] = dataPolicy
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

					if !isMatchPodSelector && !isMatchNamespaceSelector {
						continue
					}

					policies[dataPolicyID] = dataPolicy
				}
			}
		}
	}
	return policies
}
