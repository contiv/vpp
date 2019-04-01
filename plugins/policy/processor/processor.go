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
	"net"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contivconf"
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
	IPAM         IPAM
	ContivConf   contivconf.API
	Configurator config.PolicyConfiguratorAPI
}

// IPAM interface lists IPAM methods needed by Policy Processor.
type IPAM interface {
	// PodSubnetThisNode returns POD network for the current node
	// (given by nodeID allocated for this node).
	PodSubnetThisNode() *net.IPNet
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
	var contivPolicy *config.ContivPolicy
	var alreadyProcessed bool

	// Remove duplicate pods first.
	pods = utils.RemoveDuplicatePodIDs(pods)

	// In case of ipv6 take into account all pods
	if !pp.ContivConf.GetIPAMConfig().UseIPv6 {
		// Re-configure only pods that belong to the current node.
		pods = pp.filterHostPods(pods)
	}
	if len(pods) == 0 {
		return nil
	}

	txn := pp.Configurator.NewTxn(resync)
	processedPolicies := make(map[policymodel.ID]*config.ContivPolicy)
	pp.Log.Debugf("Pods selected for policy pre-processing: %v", pods)

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

				matches := pp.calculateMatches(policyData, pod)

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
	// resync the map pod->IP first
	pp.podIPAddressMap = make(map[podmodel.ID]net.IP)
	for _, pod := range data.Pods {
		if pod.IpAddress == "" {
			continue
		}
		pp.podIPAddressMap[podmodel.GetID(pod)] = net.ParseIP(pod.IpAddress)
	}

	return pp.Process(true, pp.Cache.ListAllPods())
}

// AddPod processes the event of newly added pod. The processor will postpone
// the reconfiguration until all needed data are available (IP address).
func (pp *PolicyProcessor) AddPod(podID podmodel.ID, pod *podmodel.Pod) error {
	// Remember pod IP.
	if pod.IpAddress == "" {
		pp.Log.WithField("add-pod", pod).Info("Pod does not have an IP Address assigned yet")
		return nil
	}
	pp.podIPAddressMap[podID] = net.ParseIP(pod.IpAddress)

	// For every matched policy, find all the pods that have the policy attached.
	pods := []podmodel.ID{}
	podPolicies := pp.getPoliciesReferencingPod(pod)
	for _, policy := range podPolicies {
		pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
	}

	// Update newly added pod as well.
	pods = append(pods, podID)

	return pp.Process(false, pods)
}

// DelPod processes the event of a removed pod (no action needed).
func (pp *PolicyProcessor) DelPod(podID podmodel.ID, pod *podmodel.Pod) error {
	// For every matched policy (before removal), find all the pods that have the policy attached.
	pods := []podmodel.ID{}
	podPolicies := pp.getPoliciesReferencingPod(pod)
	for _, policy := range podPolicies {
		pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
	}

	// Update deleted pod as well.
	pods = append(pods, podID)

	err := pp.Process(false, pods)

	// Remove remembered pod IP address.
	delete(pp.podIPAddressMap, podID)

	return err
}

// UpdatePod processes the event of changed pod data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePod(podID podmodel.ID, oldPod, newPod *podmodel.Pod) error {
	// Remember pod IP if it was added / has changed.
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
		oldPolicies := pp.getPoliciesReferencingPod(oldPod)
		for _, policy := range oldPolicies {
			pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
		}
	}
	if newPod.IpAddress != "" {
		newPolicies := pp.getPoliciesReferencingPod(newPod)
		for _, policy := range newPolicies {
			pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
		}
	}

	// Process this pod also in case the IP address has changed.
	if newPod.IpAddress != oldPod.IpAddress {
		pods = append(pods, podID)
	}

	return pp.Process(false, pods)
}

// AddPolicy processes the event of newly added policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddPolicy(policy *policymodel.Policy) error {
	// Check if policy was read correctly.
	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	// Find all the pods that match the newly added policy.
	pods := pp.getPodsAssignedToPolicy(policy)
	return pp.Process(false, pods)
}

// DelPolicy processes the event of a removed policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPolicy(policy *policymodel.Policy) error {
	// Check if policy was read correctly.
	if policy == nil {
		pp.Log.WithField("policy", policy).Error("Error reading Policy")
		return nil
	}

	// Find all the pods that used to match the removed policy.
	pods := pp.getPodsAssignedToPolicy(policy)
	return pp.Process(false, pods)
}

// UpdatePolicy processes the event of changed policy data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error {
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

	return pp.Process(false, pods)
}

// AddNamespace processes the event of newly added namespace (no action needed).
func (pp *PolicyProcessor) AddNamespace(ns *nsmodel.Namespace) error {
	return nil
}

// DelNamespace processes the event of a removed namespace (no action needed).
func (pp *PolicyProcessor) DelNamespace(ns *nsmodel.Namespace) error {
	return nil
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
	if oldNs == nil {
		pp.Log.WithField("namespace", oldNs).Error("Error reading Old Namespace")
		return nil
	}
	// For every matched policy (before and now), find all the pods that have the policy attached.
	oldPolicies := pp.getPoliciesReferencingNamespace(oldNs)
	for _, policy := range oldPolicies {
		pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
	}
	newPolicies := pp.getPoliciesReferencingNamespace(newNs)
	for _, policy := range newPolicies {
		pods = append(pods, pp.getPodsAssignedToPolicy(policy)...)
	}

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
	hostNetwork := pp.IPAM.PodSubnetThisNode()

	for _, podID := range pods {
		found, podData := pp.Cache.LookupPod(podID)

		if !found || podData.IpAddress == "" {
			if podIPAddress, hadIP = pp.podIPAddressMap[podID]; !hadIP {
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
	pods = pp.Cache.LookupPodsByLabelSelectorInsideNs(namespace, policyLabelSelectors)
	return pods
}

// getPoliciesAssignedToPod returns all policies currently assigned to a given pod.
func (pp *PolicyProcessor) getPoliciesReferencingPod(pod *podmodel.Pod) (policies map[policymodel.ID]*policymodel.Policy) {
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
					matchPodSelectorLabels := []*policymodel.Policy_Label{}
					matchPodSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}
					matchNsSelectorLabels := []*policymodel.Policy_Label{}
					matchNsSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}

					// Only one resource of a Policy Peer can exist (pod or namespace label selectors)
					// If resource equals to nil then policy is not a match
					if ingressRule.Pods != nil {
						matchPodSelectorLabels = ingressRule.Pods.MatchLabel
						matchPodSelectorExpressions = ingressRule.Pods.MatchExpression
						if pp.isPodLabelSelectorMatch(pod, matchPodSelectorLabels, matchPodSelectorExpressions, dataPolicy.Namespace) {
							policies[dataPolicyID] = dataPolicy
						}
					} else if ingressRule.Namespaces != nil {
						matchNsSelectorLabels = ingressRule.Namespaces.MatchLabel
						matchNsSelectorExpressions = ingressRule.Namespaces.MatchExpression
						if pp.isNsLabelSelectorMatch(pod, matchNsSelectorLabels, matchNsSelectorExpressions) {
							policies[dataPolicyID] = dataPolicy
						}
					} else {
						continue
					}
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			// If Egress Rule is an empty array, policy matches the PodSelector.
			policies[dataPolicyID] = dataPolicy
		} else {
			for _, egressRules := range dataPolicy.EgressRule {
				for _, egressRule := range egressRules.To {
					matchPodSelectorLabels := []*policymodel.Policy_Label{}
					matchPodSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}
					matchNsSelectorLabels := []*policymodel.Policy_Label{}
					matchNsSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}
					// Only one resource of a Policy Peer can exist (Pod or Namespace)
					// If resource equals to nil then policy is not a match
					if egressRule.Pods != nil {
						matchPodSelectorLabels = egressRule.Pods.MatchLabel
						matchPodSelectorExpressions = egressRule.Pods.MatchExpression
						if pp.isPodLabelSelectorMatch(pod, matchPodSelectorLabels, matchPodSelectorExpressions, dataPolicy.Namespace) {
							policies[dataPolicyID] = dataPolicy
						}
					} else if egressRule.Namespaces != nil {
						matchNsSelectorLabels = egressRule.Namespaces.MatchLabel
						matchNsSelectorExpressions = egressRule.Namespaces.MatchExpression
						if pp.isNsLabelSelectorMatch(pod, matchNsSelectorLabels, matchNsSelectorExpressions) {
							policies[dataPolicyID] = dataPolicy
						}
					} else {
						continue
					}
				}
			}
		}
	}
	return policies
}

// getPoliciesAssignedToNamespace returns all policies currently assigned to a namespace.
func (pp *PolicyProcessor) getPoliciesReferencingNamespace(ns *nsmodel.Namespace) (policies map[policymodel.ID]*policymodel.Policy) {
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

	// Select policies that match namespace's labels.
	for _, dataPolicy := range dataPolicies {
		dataPolicyID := policymodel.GetID(dataPolicy)
		if len(dataPolicy.IngressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector.
			policies[dataPolicyID] = dataPolicy
		} else {
			for _, ingressRules := range dataPolicy.IngressRule {
				for _, ingressRule := range ingressRules.From {
					matchNsSelectorLabels := []*policymodel.Policy_Label{}
					matchNsSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}
					// If resource equals to nil then policy is not a match
					if ingressRule.Namespaces != nil {
						matchNsSelectorLabels = ingressRule.Namespaces.MatchLabel
						matchNsSelectorExpressions = ingressRule.Namespaces.MatchExpression
						if pp.isNsUpdateLabelSelectorMatch(ns, matchNsSelectorLabels, matchNsSelectorExpressions) {
							policies[dataPolicyID] = dataPolicy
						}
					} else {
						continue
					}
				}
			}
		}

		if len(dataPolicy.EgressRule) == 0 {
			// If Ingress Rule is an empty array, policy matches the PodSelector.
			policies[dataPolicyID] = dataPolicy
		} else {
			for _, egressRules := range dataPolicy.EgressRule {
				for _, egressRule := range egressRules.To {
					matchNsSelectorLabels := []*policymodel.Policy_Label{}
					matchNsSelectorExpressions := []*policymodel.Policy_LabelSelector_LabelExpression{}
					// If resource equals to nil then policy is not a match
					if egressRule.Namespaces != nil {
						matchNsSelectorLabels = egressRule.Namespaces.MatchLabel
						matchNsSelectorExpressions = egressRule.Namespaces.MatchExpression
						if pp.isNsUpdateLabelSelectorMatch(ns, matchNsSelectorLabels, matchNsSelectorExpressions) {
							policies[dataPolicyID] = dataPolicy
						}
					} else {
						continue
					}
				}
			}
		}
	}
	return policies
}
