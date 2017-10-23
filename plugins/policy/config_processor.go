package policy

import (
	"strconv"
	"time"

	"github.com/contiv/vpp/plugins/policy/ruleidx"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/clientv1/defaultplugins/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/podidx"
	"github.com/contiv/vpp/plugins/policy/policyidx"
)

// ConfigProcessor processes K8s config changes into VPP ACL changes.
type ConfigProcessor struct {
	ProcessorDeps

	configuredPolicies *policyidx.ConfigIndex
	configuredPods     *podidx.ConfigIndex
	configuredRules    *ruleidx.ConfigIndex
	// - todo configuredNamespaces *namespaceidx.ConfigIndex
}

// ProcessorDeps defines dependencies of the K8s Config processor.
type ProcessorDeps struct {
	Log        logging.Logger
	PluginName core.PluginName
	Contiv     *contiv.Plugin /* for GetIfName() */

	// TODO: inject PolicyReflector(s)
}

// Init initializes Config Processor.
func (pp *ConfigProcessor) Init() error {
	pp.configuredPolicies = policyidx.NewConfigIndex(pp.Log, pp.PluginName, "policies")
	pp.configuredPods = podidx.NewConfigIndex(pp.Log, pp.PluginName, "pods")
	pp.configuredRules = ruleidx.NewConfigIndex(pp.Log, pp.PluginName, "rules")
	return nil
}

// Resync processes an initial state of K8s config.
func (pp *ConfigProcessor) Resync(event *DataResyncEvent) error {
	pp.Log.WithField("event", event).Info("RESYNC of K8s configuration BEGIN")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		pp.Log.WithField("durationInNs", duration.Nanoseconds()).Info("RESYNC of K8s configuration END")
	}()

	acl1 := &acl.AccessLists_Acl{}
	acl2 := &acl.AccessLists_Acl{}
	acl3 := &acl.AccessLists_Acl{}
	err := localclient.DataResyncRequest(pp.PluginName).
		ACL(acl1).
		ACL(acl2).
		ACL(acl3).
		Send().ReceiveReply()
	return err
}

// AddPolicy stores k8s policy locally, gets the PodSelector label and does a lookup for all
// pods with the same label. Then applies policy to the Pods.
func (pp *ConfigProcessor) AddPolicy(policy *policy.Policy) error {
	pp.Log.WithField("policy", policy).Info("Add Policy")
	var (
		policyPodIDs         []string
		ingressPodIDs        []string
		podIngressInterfaces []string
		aclConfig            *acl.AccessLists_Acl
		aclRules             []*acl.AccessLists_Acl_Rule
		//egressPodIDs  []string
		//podEgressInterfaces []string
	)

	// When 1.8 is in place
	// policyType := policy.PolicyType
	// switch policyType {
	// case "Ingress":
	// 	ruleName := "default-ingress-deny-all"
	// 	aclRules = append(aclRules, getIngressDefaultDenyAll(ruleName))
	// case "Egress":
	// 	ruleName := "default-egress-deny-all"
	// 	aclRules = append(aclRules, getEgressDefaultDenyAll(*ruleName))
	// case "Both":
	// 	ruleName := "default-deny-all"
	// 	aclRules = append(aclRules, getDefaultDenyAll(ruleName))
	// default:
	// 	ruleName := "default-ingress-deny-all"
	// 	aclRules = append(aclRules, getIngressDefaultDenyAll(ruleName))
	// }
	// ruleName := "default-deny-all"
	// aclRules = append(aclRules, getDefaultDenyAll(ruleName))

	// Find all podLabelSelectors that match IngressFrom and whitelist
	ingressRules := policy.IngressRule
	if len(ingressRules) > 0 {
		for _, ingressRule := range ingressRules {

			ingressPorts := ingressRule.Port
			ingressFroms := ingressRule.From

			// IngressRule has both From and Port rules
			if len(ingressFroms) > 0 && len(ingressPorts) > 0 {

				for _, ingressFrom := range ingressFroms {
					ingressLabelSelectors := ingressFrom.Pods.MatchLabel
					for _, ingressLabelSelector := range ingressLabelSelectors {
						ingressPodLabel := ingressLabelSelector.Key + ingressLabelSelector.Value
						ingressPodIDs = append(ingressPodIDs,
							pp.configuredPods.LookupPodLabelSelector(ingressPodLabel)...)
					}
				}

				for _, ingressPort := range ingressPorts {
					for _, ingressPodID := range ingressPodIDs {
						_, podData := pp.configuredPods.LookupPod(ingressPodID)
						podIPAddress := podData.PodIPAddress
						dstPort := ingressPort.Port.Number
						proto := ingressPort.Protocol
						ruleName := "allow-ingress-from-source-and-port-" + ingressPodID
						aclRules = append(aclRules, getIngressRule(proto, dstPort, podIPAddress, ruleName))
					}
				}

			}

			// IngressRule has only Port rules
			if len(ingressFroms) == 0 && len(ingressPorts) > 0 {

				for _, ingressPort := range ingressPorts {
					dstPort := ingressPort.Port.Number
					proto := ingressPort.Protocol
					ruleName := "allow-ingress-to-port-" + strconv.Itoa(int(dstPort))
					aclRules = append(aclRules, getIngressPortRule(proto, dstPort, ruleName))
				}

			}
			// IngressRule has only From rules
			if len(ingressFroms) > 0 && len(ingressPorts) == 0 {

				for _, ingressFrom := range ingressFroms {
					ingressPodSelectors := ingressFrom.Pods.MatchLabel
					for _, ingressPodSelector := range ingressPodSelectors {
						ingressPodLabel := ingressPodSelector.Key + ingressPodSelector.Value
						ingressPodIDs = append(ingressPodIDs,
							pp.configuredPods.LookupPodLabelSelector(ingressPodLabel)...)
					}
				}

				for _, ingressPodID := range ingressPodIDs {
					_, podData := pp.configuredPods.LookupPod(ingressPodID)
					podIPAddress := podData.PodIPAddress
					ruleName := "allow-ingress-from-source-" + ingressPodID
					aclRules = append(aclRules, getFromRule(podIPAddress, ruleName))
				}

			}
		}
	}

	pp.Log.WithField("aclRules", aclRules).Info("ACL Rules: ")
	// Find all Pods that match policyLabelSelector
	policyPodSelectors := policy.Pods.MatchLabel
	if len(policyPodSelectors) > 0 {

		for _, policyPodSelector := range policyPodSelectors {
			podLabelSelector := policyPodSelector.Key + policyPodSelector.Value
			policyPodIDs = append(policyPodIDs,
				pp.configuredPods.LookupPodLabelSelector(podLabelSelector)...)
		}

		for _, policyPodID := range policyPodIDs {
			_, podData := pp.configuredPods.LookupPod(policyPodID)
			ifName, _ := pp.Contiv.GetIfName(podData.PodNamespace, podData.PodName)
			pp.Log.WithField("ifName", ifName).Info("Interface Name: ")
			podIngressInterfaces = append(podIngressInterfaces, ifName)
		}
	} else {

		allPodIDs := pp.configuredPods.ListAll()
		for _, allPodID := range allPodIDs {
			_, podData := pp.configuredPods.LookupPod(allPodID)
			ifName, _ := pp.Contiv.GetIfName(podData.PodNamespace, podData.PodName)
			pp.Log.WithField("ifName", ifName).Info("Interface Name: ")
			podIngressInterfaces = append(podIngressInterfaces, ifName)
		}

	}

	aclConfig = &acl.AccessLists_Acl{
		AclName: "aclName-" + policy.Name + "-aclNamespace-" + policy.Namespace,
		Rules:   aclRules,
		Interfaces: &acl.AccessLists_Acl_Interfaces{
			Ingress: podIngressInterfaces,
		},
	}

	// Save the policy Cfg
	policyCfg := &policyidx.Config{
		PolicyName:        policy.Name,
		PolicyNamespace:   policy.Namespace,
		PolicyPodLabel:    policy.Pods.MatchLabel,
		PolicyIngressRule: policy.IngressRule,
	}

	ruleCfg := &ruleidx.Config{
		ACLRule: aclConfig,
	}

	policyID := policy.Name + policy.Namespace
	pp.configuredPolicies.RegisterPolicy(policyID, policyCfg)
	pp.configuredRules.RegisterRule(policyID, ruleCfg)

	// Apply ACLs to POD interfaces
	err := localclient.DataChangeRequest(pp.PluginName).
		Put().
		ACL(aclConfig).
		Send().ReceiveReply()
	if err != nil {
		return err
	}
	return nil
}

// DelPolicy deletes local data of a removed K8s policy and removes ACL configuration
// from Pod interfaces in VPP.
func (pp *ConfigProcessor) DelPolicy(policy *policy.Policy) error {
	pp.Log.WithField("policy", policy).Info("Delete Policy")
	// TODO
	return nil
}

// UpdatePolicy updates local data of the updated K8s policy and updates ACL configuration
// to Pod interfaces in VPP.
func (pp *ConfigProcessor) UpdatePolicy(oldPolicy, newPolicy *policy.Policy) error {
	pp.Log.WithFields(logging.Fields{"old": oldPolicy, "new": newPolicy}).Info("Update Policy")
	// TODO
	return nil
}

// AddPod registers the pod to the cache. Since on AddPod interface has not been configured
// no actions will be taken here, only when full done on the Update Pod.
func (pp *ConfigProcessor) AddPod(pod *pod.Pod) error {
	pp.Log.WithField("pod", pod).Info("Add Pod")
	// 1. Register added pod with podID
	podID := pod.Name + pod.Namespace

	podCfg := &podidx.Config{
		PodName:          pod.Name,
		PodNamespace:     pod.Namespace,
		PodLabelSelector: pod.Label,
		PodIPAddress:     pod.IpAddress,
	}
	pp.Log.Infof("Added pod conifg", pp.configuredPods)
	pp.configuredPods.RegisterPod(podID, podCfg)
	return nil
}

// DelPod ...
func (pp *ConfigProcessor) DelPod(pod *pod.Pod) error {
	pp.Log.WithField("pod", pod).Info("Delete Pod")
	// TODO
	return nil
}

// UpdatePod updates the configuration of a Pod. When ready Pod will register and reflect
// policy changes if matched to a policy label.
func (pp *ConfigProcessor) UpdatePod(oldPod, newPod *pod.Pod) error {
	pp.Log.WithFields(logging.Fields{"old": oldPod, "new": newPod}).Info("Update Pod")
	// 1. Unregister added pod with oldpodID
	oldPodID := oldPod.Name + oldPod.Namespace
	pp.configuredPods.UnregisterPod(oldPodID)

	newPodID := newPod.Name + newPod.Namespace
	newPodCfg := &podidx.Config{
		PodName:          newPod.Name,
		PodNamespace:     newPod.Namespace,
		PodLabelSelector: newPod.Label,
		PodIPAddress:     newPod.IpAddress,
	}
	pp.Log.Infof("Show me the configured pod please: %+v", pp.configuredPods)

	if newPod.IpAddress == "" {
		pp.Log.WithFields(logging.Fields{"new": newPod}).Debug("CNI has not assigned IPAddress to POD")
		pp.configuredPods.RegisterPod(newPodID, newPodCfg)
		return nil
	}

	// 1. Check if policy applies to pod.
	policyIDs := []string{}
	policyLabelSelectors := newPod.Label
	for _, policyLabelSelector := range policyLabelSelectors {
		labelSelector := policyLabelSelector.Key + policyLabelSelector.Value
		policyIDs = append(policyIDs,
			pp.configuredPolicies.LookupPolicyLabelSelector(labelSelector)...)
	}
	if len(policyIDs) == 0 {
		pp.Log.Debug("No policy assigned to POD")
		pp.configuredPods.RegisterPod(newPodID, newPodCfg)
		return nil
	}

	//2. Check if ingress label selectors match pod label selectors
	policyIngressIDs := []string{}
	ingressLabelSelectors := newPod.Label
	for _, ingressLabelSelector := range ingressLabelSelectors {
		labelSelector := ingressLabelSelector.Key + ingressLabelSelector.Value
		policyIngressIDs = append(policyIngressIDs,
			pp.configuredPolicies.LookupIngressLabelSelector(labelSelector)...)
	}
	if len(policyIngressIDs) == 0 {
		pp.Log.Debug("No ingress whitelist policy assigned to POD")
		pp.configuredPods.RegisterPod(newPodID, newPodCfg)
		return nil
	}

	// Append newRule and send configuration to VPP
	// for _, policyIngressID := range policyIngressIDs {
	// 	_, policyRule := pp.configuredRules.LookupRule(policyIngressID)
	// 	_, policyCfg := pp.configuredPolicies.LookupPolicy(policyIngressID)
	// }
	return nil
}

// AddNamespace ...
func (pp *ConfigProcessor) AddNamespace(ns *namespace.Namespace) error {
	pp.Log.WithField("namespace", ns).Info("Add Namespace")
	// TODO
	return nil
}

// DelNamespace ...
func (pp *ConfigProcessor) DelNamespace(ns *namespace.Namespace) error {
	pp.Log.WithField("namespace", ns).Info("Delete Namespace")
	// TODO
	return nil
}

// UpdateNamespace ...
func (pp *ConfigProcessor) UpdateNamespace(oldNs, newNs *namespace.Namespace) error {
	pp.Log.WithFields(logging.Fields{"old": oldNs, "new": newNs}).Info("Update Namespace")
	// TODO
	return nil
}

// Close frees resources allocated by Config Processor.
func (pp *ConfigProcessor) Close() error {
	return nil
}

func getHostIPNet(ip string) string {
	if ip == "" {
		return ip
	}
	return ip + "/32"
}

func getIngressRule(proto policy.Policy_Port_Protocol, dstPort int32, srcIPAddr string, ruleName string) *acl.AccessLists_Acl_Rule {

	lowerDstPort := uint32(dstPort)
	upperDstPort := uint32(dstPort)

	matches := &acl.AccessLists_Acl_Rule_Matches{}
	// Set Src/DstNetwork and Ports based on protocol
	if proto == 0 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					SourceNetwork: getHostIPNet(srcIPAddr),
				},
				Tcp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
				},
			},
		}
	} else if proto == 1 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					SourceNetwork: getHostIPNet(srcIPAddr),
				},
				Udp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
				},
			},
		}
	}
	return &acl.AccessLists_Acl_Rule{
		RuleName: ruleName,
		Actions: &acl.AccessLists_Acl_Rule_Actions{
			AclAction: acl.AclAction_PERMIT,
		},
		Matches: matches,
	}
}

func getIngressPortRule(proto policy.Policy_Port_Protocol, dstPort int32, ruleName string) *acl.AccessLists_Acl_Rule {

	lowerDstPort := uint32(dstPort)
	upperDstPort := uint32(dstPort)

	matches := &acl.AccessLists_Acl_Rule_Matches{}
	// Set Src/DstNetwork and Ports based on protocol
	if proto == 0 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Tcp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
				},
			},
		}
	} else if proto == 1 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Udp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
				},
			},
		}
	}

	return &acl.AccessLists_Acl_Rule{
		RuleName: ruleName,
		Actions: &acl.AccessLists_Acl_Rule_Actions{
			AclAction: acl.AclAction_PERMIT,
		},
		Matches: matches,
	}
}

func getFromRule(srcIPAddr string, ruleName string) *acl.AccessLists_Acl_Rule {

	matches := &acl.AccessLists_Acl_Rule_Matches{}
	// Set Src/DstNetwork and Ports based on protocol
	matches = &acl.AccessLists_Acl_Rule_Matches{
		IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
			Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
				SourceNetwork: getHostIPNet(srcIPAddr),
			},
		},
	}
	matches = &acl.AccessLists_Acl_Rule_Matches{
		IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
			Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
				SourceNetwork: getHostIPNet(srcIPAddr),
			},
		},
	}

	return &acl.AccessLists_Acl_Rule{
		RuleName: ruleName,
		Actions: &acl.AccessLists_Acl_Rule_Actions{
			AclAction: acl.AclAction_PERMIT,
		},
		Matches: matches,
	}
}

func getDefaultDenyAll(ruleName string) *acl.AccessLists_Acl_Rule {
	matches := &acl.AccessLists_Acl_Rule_Matches{}
	return &acl.AccessLists_Acl_Rule{
		RuleName: ruleName,
		Actions: &acl.AccessLists_Acl_Rule_Actions{
			AclAction: acl.AclAction_DENY,
		},
		Matches: matches,
	}
}
