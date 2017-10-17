package policy

import (
	"time"

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
	// - todo configuredNamespaces *namespaceidx.ConfigIndex
	//  - memory storage for policies, namespaces, pods (consider using cn-infra/idxmap)
}

// ProcessorDeps defines dependencies of the K8s Config processor.
type ProcessorDeps struct {
	Log        logging.Logger
	PluginName core.PluginName
	Contiv     *contiv.Plugin /* for GetIfName() */
	// This is how you get the name of the VPP interface attached into the pod:
	// ifName, meta, found := pp.Contiv.GetIfName(pod.Namespace, pod.Pod)

	// TODO: inject PolicyReflector(s)
}

// Init initializes Config Processor.
func (pp *ConfigProcessor) Init() error {
	pp.configuredPolicies = policyidx.NewConfigIndex(pp.Log, pp.PluginName, "policies")
	pp.configuredPods = podidx.NewConfigIndex(pp.Log, pp.PluginName, "pods")
	// todo plugin.configuredNamespaces = namespaceidx.NewConfigIndex(plugin.Log, plugin.PluginName, "namespace")
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
	policyCfg := &policyidx.Config{
		PolicyName:      policy.Name,
		PolicyLabel:     policy.Label,
		PolicyNamespace: policy.Namespace,
	}
	var podIDs []string
	var ingressPodIDs []string
	var ingressInterfaces []string
	var aclConfig *acl.AccessLists_Acl
	var aclRules []*acl.AccessLists_Acl_Rule

	ingressRules := policy.GetIngressRule()
	for _, ingressRule := range ingressRules {
		ingressPorts := ingressRule.GetPort()
		ingressFroms := ingressRule.GetFrom()
		for _, ingressFrom := range ingressFroms {
			ingressPodSelectors := ingressFrom.GetPods().GetMatchLabel()
			for _, ingressPodSelector := range ingressPodSelectors {
				ingressPodLabel := ingressPodSelector.Key + ingressPodSelector.Value
				ingressPodIDs := pp.configuredPods.LookupPodLabelSelector(ingressPodLabel)
			}
		}
		for _, ingressPort := range ingressPorts {
			for _, ingressPodID := range ingressPodIDs {
				_, podData := pp.configuredPods.LookupPod(ingressPodID)
				podIPAddress := podData.PodIPAddress
				dstPort := ingressPort.GetPort().Number
				proto := ingressPort.Protocol
				aclRules = append(aclRules, getaclRules(proto, dstPort, 0, podIPAddress))
			}
		}
	}

	podSelectors := policy.GetPods().GetMatchLabel()
	for _, podSelector := range podSelectors {
		podSelectorLabel := podSelector.Key + podSelector.Value
		podIDs := pp.configuredPods.LookupPodLabelSelector(podSelectorLabel)
		for _, podID := range podIDs {
			_, podData := pp.configuredPods.LookupPod(podID)
			podIPAddress := podData.PodIPAddress
			ifName, _, _ := pp.Contiv.GetIfName(podData.PodNamespace, podData.PodName)
			for _, rule := range aclRules {
				rule.Matches = &acl.AccessLists_Acl_Rule_Matches{
					IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
						Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
							DestinationNetwork: podIPAddress,
						},
					},
				}
			}

			aclConfig = &acl.AccessLists_Acl{
				AclName: "aclName-" + policy.Name + "-" + "aclNamespace-" + policy.Namespace,
				Rules:   aclRules,
				Interfaces: &acl.AccessLists_Acl_Interfaces{
					Ingress: []string{ifName},
				},
			}
		}
	}

	//5. Apply ACLs to POD interfaces
	err := localclient.DataChangeRequest(pp.PluginName).
		Put().
		ACL(aclConfig).
		Send().ReceiveReply()
	return err
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

// AddPod ...
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
	pp.configuredPods.RegisterPod(podID, podCfg)

	// 2. Check if there are policies for current Label
	var policyIDs []string
	for _, v := range pod.Label {
		label := v.Key + v.Value
		policyIDs := pp.configuredPolicies.LookupPolicyLabelSelector(label)
	}

	if policyIDs == nil {
		pp.Log.WithField("pod", pod).Info("No policies matching labels were found")
		return nil
	}

	// 3. Apply ingress policy on pod interface
	// acl := ...

	return nil
}

// DelPod ...
func (pp *ConfigProcessor) DelPod(pod *pod.Pod) error {
	pp.Log.WithField("pod", pod).Info("Delete Pod")
	// TODO
	return nil
}

// UpdatePod ...
func (pp *ConfigProcessor) UpdatePod(oldPod, newPod *pod.Pod) error {
	pp.Log.WithFields(logging.Fields{"old": oldPod, "new": newPod}).Info("Update Pod")
	// TODO
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

func getaclRules(proto policy.Policy_IngressRule_Port_Protocol, dstPort int32, srcPort int32, srcIPAddr string) *acl.AccessLists_Acl_Rule {
	var lowerDstPort, upperDstPort, lowerSrcPort, upperSrcPort uint32
	// Check if Port Range is zero
	if dstPort == 0 {
		lowerDstPort = uint32(0)
		upperDstPort = uint32(65535)
	} else {
		lowerDstPort = uint32(dstPort)
		upperDstPort = uint32(dstPort)
	}
	if srcPort == 0 {
		lowerSrcPort = uint32(0)
		upperSrcPort = uint32(65535)
	} else {
		lowerSrcPort = uint32(srcPort)
		upperSrcPort = uint32(srcPort)
	}
	matches := &acl.AccessLists_Acl_Rule_Matches{}
	// Set Src/DstNetwork and Ports based on protocol
	if proto == 0 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					SourceNetwork: srcIPAddr,
				},
				Tcp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
					SourcePortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_SourcePortRange{
						LowerPort: lowerSrcPort,
						UpperPort: upperSrcPort,
					},
				},
			},
		}
	} else if proto == 1 {
		matches = &acl.AccessLists_Acl_Rule_Matches{
			IpRule: &acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					SourceNetwork: srcIPAddr,
				},
				Udp: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{
					DestinationPortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
					SourcePortRange: &acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_SourcePortRange{
						LowerPort: lowerSrcPort,
						UpperPort: upperSrcPort,
					},
				},
			},
		}
	}
	return &acl.AccessLists_Acl_Rule{
		RuleName: "temp",
		Actions: &acl.AccessLists_Acl_Rule_Actions{
			AclAction: acl.AclAction_PERMIT,
		},
		Matches: matches,
	}
}
