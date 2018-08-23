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
func (pp *PolicyProcessor) calculateMatches(policyData *policymodel.Policy, podID podmodel.ID) []config.Match {
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
					policyPods := pp.Cache.LookupPodsByLabelSelectorInsideNs(namespace, ingressLabel)
					ingressPods = append(ingressPods, policyPods...)
				}
				// Find all the pods that match ingress rules namespace label selectors
				if ingressRuleFrom.Namespaces != nil {
					namespaceLabels := ingressRuleFrom.Namespaces
					policyPods := pp.Cache.LookupPodsByNsLabelSelector(namespaceLabels)
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
				// A port in kubernetes network policy is either a name (1) or a port number (0)
				if ingressRulePort.Port.Type == 0 {
					ingressPortNumber := uint16(ingressRulePort.Port.Number)
					ingressPorts = append(ingressPorts, config.Port{
						Protocol: ingressPortProtocol,
						Number:   ingressPortNumber,
					})
				} else {
					// Obtain data for pod that matches are calculated
					_, podData := pp.Cache.LookupPod(podID)
					// If pod has name matching port policy name, find the port that the name is mapped to
					for _, podContainer := range podData.Container {
						for _, podPort := range podContainer.Port {
							if podPort.Name == ingressRulePort.Port.Name {
								ingressPortNumber := uint16(podPort.ContainerPort)
								ingressPorts = append(ingressPorts, config.Port{
									Protocol: ingressPortProtocol,
									Number:   ingressPortNumber,
								})
							}
						}
					}
				}
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
					policyPods := pp.Cache.LookupPodsByLabelSelectorInsideNs(namespace, egressLabel)
					egressPods = append(egressPods, policyPods...)
				}
				// Find all the pods that match egress rules namespace label selectors
				if egressRuleTo.Namespaces != nil {
					namespaceLabels := egressRuleTo.Namespaces
					policyPods := pp.Cache.LookupPodsByNsLabelSelector(namespaceLabels)
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

				if egressRulePort.Port.Type == 0 {
					egressPortNumber := uint16(egressRulePort.Port.Number)
					egressPorts = append(egressPorts, config.Port{
						Protocol: egressPortProtocol,
						Number:   egressPortNumber,
					})
				} else {
					// if there are egressPods then map the portName to portNumber for every each one of them
					// without adding IPBlocks, if not do the same for all running pods.
					if len(egressPods) > 0 {
						// For all egress pods, find the matching policy port name mapped to a port number
						portNameMatches := pp.portNameToNumber(egressPods, egressPortProtocol, egressRulePort)
						matches = append(matches, portNameMatches...)
					} else {
						newEgressPods := pp.Cache.ListAllPods()
						portNameMatches := pp.portNameToNumber(newEgressPods, egressPortProtocol, egressRulePort)
						matches = append(matches, portNameMatches...)
					}
				}
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

func (pp *PolicyProcessor) portNameToNumber(pods []podmodel.ID, portProtocol config.ProtocolType,
	rulePort *policymodel.Policy_Port) []config.Match {
	matches := []config.Match{}
	for _, pod := range pods {
		_, podData := pp.Cache.LookupPod(pod)
		for _, podContainer := range podData.Container {
			for _, podPort := range podContainer.Port {
				if podPort.Name == rulePort.Port.Name {
					portNumber := uint16(podPort.ContainerPort)
					port := config.Port{
						Protocol: portProtocol,
						Number:   portNumber,
					}
					matches = append(matches, config.Match{
						Type:     config.MatchEgress,
						Pods:     []podmodel.ID{pod},
						IPBlocks: []config.IPBlock{},
						Ports:    []config.Port{port},
					})
				}
			}
		}
	}
	return matches
}
