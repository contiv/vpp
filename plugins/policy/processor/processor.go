package processor

import (
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"fmt"

	"github.com/contiv/vpp/plugins/policy/cache"
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
		pp.Log.Infof("This are the policies: %+v for pod: %+v", policiesByPod, pod)
		if policiesByPod != nil {
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
			policies = append(policies, policy)
		}
		pp.Log.Infof("Configurator Pod: %+v, Policies: %+v", pod, policies)
		//TODO: get and pre-process policies currently assigned to the pod
		//optimization: remember already evaluated policies between iterations
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
	pods := []podmodel.ID{}
	// TODO: consider postponing the re-configuration until more data are available (e.g. pod ip address)
	// TODO: determine the list of pods with outdated policy configuration

	return pp.Process(false, pods)
}

// DelPod processes the event of a removed pod.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPod(pod *podmodel.Pod) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

// UpdatePod processes the event of changed pod data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePod(oldPod, newPod *podmodel.Pod) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	//       - also handle migration of pods across hosts
	return pp.Process(false, pods)
}

// AddPolicy processes the event of newly added policy. The processor may postpone
// the reconfiguration until all needed data are available.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) AddPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	//ingressPods := []podmodel.ID{}
	//egressPods := []podmodel.ID{}
	// TODO: consider postponing the re-configuration until more data are available
	// TODO: determine the list of pods with outdated policy configuration

	if policy == nil {
		return fmt.Errorf("Policy was not read correctly, retrying")
	}

	pp.Log.Infof("This is the policy to be added: %+v", policy)
	namespace := policy.Namespace
	policyLabelSelectors := policy.Pods
	policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, policyLabelSelectors)

	pods = append(pods, policyPods...)
	fmt.Println("Pods policy applies to: %+v", pods)

	return pp.Process(false, pods)
}

// DelPolicy processes the event of a removed policy.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) DelPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

// UpdatePolicy processes the event of changed policy data.
// The list of pods with outdated policy configuration is determined and the
// policy re-processing is triggered for each of them.
func (pp *PolicyProcessor) UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
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

func (pp *PolicyProcessor) calculateMatches(policyData *policymodel.Policy) []config.Match {
	matches := []config.Match{}

	ingressRules := policyData.IngressRule
	egressRules := policyData.EgressRule
	namespace := policyData.Namespace

	if len(ingressRules) != 0 {

		matchType := config.MatchIngress

		for _, ingressRule := range ingressRules {
			ingressPods := []podmodel.ID{}
			ingressPorts := []config.Port{}

			ingressRuleFrom := ingressRule.From
			for _, ingressLabelSelector := range ingressRuleFrom {
				ingressLabel := ingressLabelSelector.Pods
				ingressPod := pp.Cache.LookupPodsByNSLabelSelector(namespace, ingressLabel)
				ingressPods = append(ingressPods, ingressPod...)
			}

			// for namespaces, for ipblocks

			ingressRulePorts := ingressRule.Port
			for _, ingressRulePort := range ingressRulePorts {
				ingressPortProtocol := config.TCP
				if ingressRulePort.Protocol == policymodel.Policy_Port_UDP {
					ingressPortProtocol = config.UDP
				}
				ingressPortNumber := uint16(ingressRulePort.Port.Number)
				ingressPorts = append(ingressPorts, config.Port{
					Protocol: ingressPortProtocol,
					Number:   ingressPortNumber,
				})
			}

			matches = append(matches, config.Match{
				Type:  matchType,
				Pods:  ingressPods,
				Ports: ingressPorts,
			})
		}
	}

	if len(egressRules) != 0 {

		matchType := config.MatchIngress

		for _, egressRule := range egressRules {
			egressPods := []podmodel.ID{}
			egressPorts := []config.Port{}

			egressRuleTo := egressRule.To
			for _, egressLabelSelector := range egressRuleTo {
				egressLabel := egressLabelSelector.Pods
				egressPod := pp.Cache.LookupPodsByNSLabelSelector(namespace, egressLabel)
				egressPods = append(egressPods, egressPod...)
			}

			// for namespaces, for ipblocks

			egressRulePorts := egressRule.Port
			for _, egressRulePort := range egressRulePorts {
				egressPortProtocol := config.TCP
				if egressRulePort.Protocol == policymodel.Policy_Port_UDP {
					egressPortProtocol = config.UDP
				}
				egressPortNumber := uint16(egressRulePort.Port.Number)
				egressPorts = append(egressPorts, config.Port{
					Protocol: egressPortProtocol,
					Number:   egressPortNumber,
				})
			}

			matches = append(matches, config.Match{
				Type:  matchType,
				Pods:  egressPods,
				Ports: egressPorts,
			})
		}
	}
	return matches
}
