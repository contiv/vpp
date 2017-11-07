package processor

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"fmt"

	"errors"

	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/cache/utils"
	config "github.com/contiv/vpp/plugins/policy/configurator"
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
}

// Deps lists dependencies of Policy Processor.
type Deps struct {
	Log          logging.Logger
	Cache        cache.PolicyCacheAPI
	Contiv       *contiv.Plugin /* to get the Host IP */
	Configurator config.PolicyConfiguratorAPI
}

// Init initializes the Policy Processor.
func (pp *PolicyProcessor) Init() error {
	pp.Cache.Watch(pp)
	return nil
}

// Process re-calculates the set of Contiv policies for pods with outdated
// configuration. The order at which the pods are reconfigured or the order
// of policies listed for a given pod are all irrelevant.
func (pp *PolicyProcessor) Process(resync bool, pods []podmodel.ID) error {
	txn := pp.Configurator.NewTxn(false)
	for _, pod := range pods {
		policies := []*config.ContivPolicy{}
		policiesByPod := pp.Cache.LookupPoliciesByPod(pod)

		if policiesByPod == nil {
			continue
		}

		for _, policyByPod := range policiesByPod {
			var policyType config.PolicyType
			found, policyData := pp.Cache.LookupPolicy(policyByPod)

			// todo - Check here if Policy has been found before.
			if !found {
				continue
			}

			pp.Log.Infof("Panic reason: ", policyData.PolicyType)

			switch policyData.PolicyType {
			case policymodel.Policy_INGRESS:
				policyType = 1
				break
			case policymodel.Policy_EGRESS:
				policyType = 2
				break
			case policymodel.Policy_INGRESS_AND_EGRESS:
				policyType = 3
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

			pp.Log.Infof("Pod: %+v and w/ Policies sent to configurator: %+v ", pods, policies)
			policies = append(policies, policy)

		}
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
	//pods := []podmodel.ID{}
	// TODO: consider postponing the re-configuration until more data are available (e.g. pod ip address)
	// TODO: determine the list of pods with outdated policy configuration

	if pod.IpAddress == "" {
		return errors.New("Waiting for Pod to get an IPAddress")
	}

	if pod.Namespace == "kube-system" {
		return errors.New("Pods Kube-system are being ignored in Policies")
	}

	return nil
}

// DelPod processes the event of a removed pod.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPod(pod *podmodel.Pod) error {
	//pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	//return pp.Process(false, pods)
	return nil
}

// UpdatePod processes the event of changed pod data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePod(oldPod, newPod *podmodel.Pod) error {
	// TODO: determine the list of pods with outdated policy configuration
	//       - also handle migration of pods across hosts
	pods := []podmodel.ID{}

	if newPod.IpAddress == "" {
		return errors.New("Waiting for Pod to get an IPAddress")
	}

	if newPod.Namespace == "kube-system" {
		return errors.New("Pods Kube-system are being ignored in Policies")
	}

	addedPolicies := make(map[string]bool)
	policies := []*policymodel.Policy{}

	// Check if new Pod has policy attached
	newPodID := podmodel.GetID(newPod)
	podPolicies := pp.Cache.LookupPoliciesByPod(newPodID)

	if len(podPolicies) > 0 {
		pods = append(pods, newPodID)
	}

	allPolicies := pp.Cache.ListAllPolicies()
	dataPolicies := []*policymodel.Policy{}
	for _, stringPolicy := range allPolicies {
		found, policyData := pp.Cache.LookupPolicy(stringPolicy)
		if !found {
			continue
		}
		dataPolicies = append(dataPolicies, policyData)
	}

	for _, dataPolicy := range dataPolicies {
		for _, ingressRules := range dataPolicy.IngressRule {
			for _, ingressRule := range ingressRules.From {

				matchLabels := ingressRule.Pods.MatchLabel
				matchExpressions := ingressRule.Pods.MatchExpression

				isMatch := pp.calculateLabelSelectorMatches(newPod, matchLabels, matchExpressions, dataPolicy.Namespace)
				if !isMatch {
					continue
				}

				if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
					addedPolicies[policymodel.GetID(dataPolicy).String()] = true
					policies = append(policies, dataPolicy)
				}
			}
		}
		for _, egressRules := range dataPolicy.EgressRule {
			for _, egressRule := range egressRules.To {

				matchLabels := egressRule.Pods.MatchLabel
				matchExpressions := egressRule.Pods.MatchExpression

				isMatch := pp.calculateLabelSelectorMatches(newPod, matchLabels, matchExpressions, dataPolicy.Namespace)
				if !isMatch {
					continue
				}

				if addedPolicies[policymodel.GetID(dataPolicy).String()] != true {
					addedPolicies[policymodel.GetID(dataPolicy).String()] = true
					policies = append(policies, dataPolicy)
				}
			}
		}
	}

	if len(policies) > 0 {
		for _, policy := range policies {
			namespace := policy.Namespace
			policyLabelSelectors := policy.Pods

			policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
			pods = append(pods, policyPods...)
		}
	}

	strPods := removeDuplicates(utils.StringPodID(pods))
	pods = utils.UnstringPodID(strPods)

	pp.Log.Infof("Pods affected by Pod Add: ", pods)
	if len(pods) > 0 {
		return pp.Process(false, pods)
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
		return fmt.Errorf("Policy was not read correctly, retrying")
	}

	namespace := policy.Namespace
	policyLabelSelectors := policy.Pods

	policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
	pods = append(pods, policyPods...)

	return pp.Process(false, pods)
}

// DelPolicy processes the event of a removed policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}

	if policy == nil {
		return fmt.Errorf("Policy was not read correctly, retrying")
	}

	namespace := policy.Namespace
	policyLabelSelectors := policy.Pods

	policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
	pods = append(pods, policyPods...)

	if len(pods) > 0 {
		return pp.Process(false, pods)
	}
	return nil
}

// UpdatePolicy processes the event of changed policy data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error {
	pods := []podmodel.ID{}

	if newPolicy == nil {
		return fmt.Errorf("Policy was not read correctly, retrying")
	}

	namespace := newPolicy.Namespace
	policyLabelSelectors := newPolicy.Pods

	policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)
	pods = append(pods, policyPods...)

	if len(pods) > 0 {
		return pp.Process(false, pods)
	}
	return nil
}

// AddNamespace processes the event of newly added namespace. The processor may
// postpone the reconfiguration until all needed data are available.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: consider postponing the re-configuration until more data are available
	//         - e.g. empty namespace has no effect
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

// DelNamespace processes the event of a removed namespace.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

// UpdateNamespace processes the event of changed namespace data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

// Close deallocates all resources held by the processor.
func (pp *PolicyProcessor) Close() error {
	return nil
}

func removeDuplicates(el []string) []string {
	found := map[string]bool{}

	// Create a map of all unique elements.
	for v := range el {
		found[el[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key := range found {
		result = append(result, key)
	}
	return result
}
