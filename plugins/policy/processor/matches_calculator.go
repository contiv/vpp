package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	config "github.com/contiv/vpp/plugins/policy/configurator"
)

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
				// todo: translate form name to port number
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

		matchType := config.MatchEgress

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
				// todo: translate form name to port number
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

func (pp *PolicyProcessor) calculateLabelSelectorMatches(
	newPod *podmodel.Pod,
	matchLabels []*policymodel.Policy_Label,
	matchExpressions []*policymodel.Policy_LabelSelector_LabelExpression,
	policyNamespace string) bool {

	if len(matchLabels) > 0 && len(matchExpressions) > 0 {
		evalMatchLabels := pp.isMatchLabel(newPod, matchLabels, policyNamespace)
		evalMatchExpressions := pp.isMatchExpression(newPod, matchExpressions, policyNamespace)

		isMatch := evalMatchLabels && evalMatchExpressions

		if !isMatch {
			return false
		}
		return true

	} else if len(matchLabels) == 0 && len(matchExpressions) > 0 {
		evalMatchExpressions := pp.isMatchExpression(newPod, matchExpressions, policyNamespace)

		if !evalMatchExpressions {
			return false
		}
		return true
	} else if len(matchLabels) > 0 && len(matchExpressions) == 0 {
		evalMatchLabels := pp.isMatchLabel(newPod, matchLabels, policyNamespace)

		if !evalMatchLabels {
			return false
		}
		return true
	}
	return true
}
