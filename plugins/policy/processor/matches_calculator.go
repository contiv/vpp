package processor

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	config "github.com/contiv/vpp/plugins/policy/configurator"
)

// calculateMatches finds the returns a predicate that selects a subset of the traffic by calculating
// pods that match namespace and pod label selectors for ingress and egress policy and translates IPBlocks
// in the right format for configurator.
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
			ingressIPBlocks := []config.IPBlock{}

			ingressRuleFroms := ingressRule.From

			if len(ingressRuleFroms) == 0 {
				ingressPods = nil
				ingressIPBlocks = nil
			}

			for _, ingressRuleFrom := range ingressRuleFroms {
				// Find all the pods that match ingress rules pod label selectors
				if ingressRuleFrom.Pods != nil {
					ingressLabel := ingressRuleFrom.Pods
					policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, ingressLabel)
					ingressPods = append(ingressPods, policyPods...)
				}
				// Find all the pods that match ingress rules namespace label selectors
				if ingressRuleFrom.Namespaces != nil {
					namespaceLabels := ingressRuleFrom.Namespaces
					policyPods := pp.Cache.LookupPodsByLabelSelector(namespaceLabels)
					ingressPods = append(ingressPods, policyPods...)
				}

				ingressIPBlock := ingressRuleFrom.IpBlock
				if ingressIPBlock == nil {
					continue
				}
				_, ingressCIDR, _ := net.ParseCIDR(ingressIPBlock.Cidr)

				ingressIPBlockEx := []net.IPNet{}
				ingressIPBlockExcepts := ingressIPBlock.Except
				for _, ingressIPBlockExcept := range ingressIPBlockExcepts {
					_, ingressExcept, _ := net.ParseCIDR(ingressIPBlockExcept)
					ingressIPBlockEx = append(ingressIPBlockEx, *ingressExcept)
				}
				ingressIPBlocks = append(ingressIPBlocks, config.IPBlock{
					Network: *ingressCIDR,
					Except:  ingressIPBlockEx,
				})
			}

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
				Type:     matchType,
				Pods:     ingressPods,
				Ports:    ingressPorts,
				IPBlocks: ingressIPBlocks,
			})
		}
	}

	if len(egressRules) != 0 {

		matchType := config.MatchEgress

		for _, egressRule := range egressRules {
			egressPods := []podmodel.ID{}
			egressPorts := []config.Port{}
			egressIPBlocks := []config.IPBlock{}

			egressRulesTo := egressRule.To

			if len(egressRulesTo) == 0 {
				egressPods = nil
				egressIPBlocks = nil
			}

			for _, egressRuleTo := range egressRulesTo {
				// Find all the pods that match egress rules pod label selectors
				if egressRuleTo.Pods != nil {
					egressLabel := egressRuleTo.Pods
					policyPods := pp.Cache.LookupPodsByNSLabelSelector(namespace, egressLabel)
					egressPods = append(egressPods, policyPods...)
				}
				// Find all the pods that match egress rules namespace label selectors
				if egressRuleTo.Namespaces != nil {
					namespaceLabels := egressRuleTo.Namespaces
					policyPods := pp.Cache.LookupPodsByLabelSelector(namespaceLabels)
					egressPods = append(egressPods, policyPods...)
				}
				egressIPBlock := egressRuleTo.IpBlock
				if egressIPBlock == nil {
					continue
				}

				_, egressCIDR, _ := net.ParseCIDR(egressIPBlock.Cidr)

				egressIPBlockEx := []net.IPNet{}
				egressIPBlockExcepts := egressIPBlock.Except
				for _, ingressIPBlockExcept := range egressIPBlockExcepts {
					_, ingressExcept, _ := net.ParseCIDR(ingressIPBlockExcept)
					egressIPBlockEx = append(egressIPBlockEx, *ingressExcept)
				}
				egressIPBlocks = append(egressIPBlocks, config.IPBlock{
					Network: *egressCIDR,
					Except:  egressIPBlockEx,
				})
			}

			egressRulePorts := egressRule.Port
			// Egress ports to appropriate type
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
				Type:     matchType,
				Pods:     egressPods,
				Ports:    egressPorts,
				IPBlocks: egressIPBlocks,
			})
		}
	}
	return matches
}

// calculateLabelSelectorMatches returns true if all
func (pp *PolicyProcessor) calculateLabelSelectorMatches(
	pod *podmodel.Pod,
	matchLabels []*policymodel.Policy_Label,
	matchExpressions []*policymodel.Policy_LabelSelector_LabelExpression,
	policyNamespace string) bool {

	if len(matchLabels) > 0 && len(matchExpressions) > 0 {
		evalMatchLabels := pp.isMatchLabel(pod, matchLabels, policyNamespace)
		evalMatchExpressions := pp.isMatchExpression(pod, matchExpressions, policyNamespace)

		isMatch := evalMatchLabels && evalMatchExpressions

		if !isMatch {
			return false
		}
		return true

	} else if len(matchLabels) == 0 && len(matchExpressions) > 0 {
		evalMatchExpressions := pp.isMatchExpression(pod, matchExpressions, policyNamespace)

		if !evalMatchExpressions {
			return false
		}
		return true
	} else if len(matchLabels) > 0 && len(matchExpressions) == 0 {
		evalMatchLabels := pp.isMatchLabel(pod, matchLabels, policyNamespace)

		if !evalMatchLabels {
			return false
		}
		return true
	}
	// empty labelselector selects all pods
	return true
}
