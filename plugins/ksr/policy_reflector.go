// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ksr

import (
	"reflect"
	"sort"
	"sync"

	"github.com/golang/protobuf/proto"

	coreV1 "k8s.io/api/core/v1"
	coreV1Beta1 "k8s.io/api/extensions/v1beta1"
	clientApiMetaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

// PolicyReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s network policies.
// Protobuf-modelled changes are published into the selected key-value store.
type PolicyReflector struct {
	Reflector
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s network policies. The subscription does not become active until Start()
// is called.
func (pr *PolicyReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	policyReflectorFuncs := ReflectorFunctions{
		EventHdlrFunc: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pr.addPolicy(obj)
			},
			DeleteFunc: func(obj interface{}) {
				pr.deletePolicy(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				pr.updatePolicy(oldObj, newObj)
			},
		},
		ProtoAllocFunc: func() proto.Message {
			return &policy.Policy{}
		},
		K8s2ProtoFunc: func(k8sObj interface{}) (interface{}, string, bool) {
			k8sPolicy, ok := k8sObj.(*coreV1Beta1.NetworkPolicy)
			if !ok {
				pr.Log.Errorf("service syncDataStore: wrong object type %s, obj %+v",
					reflect.TypeOf(k8sObj), k8sObj)
				return nil, "", false
			}
			return pr.policyToProto(k8sPolicy), policy.Key(k8sPolicy.Name, k8sPolicy.Namespace), true
		},
		K8sClntGetFunc: func(cs *kubernetes.Clientset) rest.Interface {
			// Use ExtensionsV1beta1 API client for policies
			return cs.ExtensionsV1beta1().RESTClient()
		},
	}

	return pr.ksrInit(stopCh2, wg, policy.KeyPrefix(), "networkpolicies",
		&coreV1Beta1.NetworkPolicy{}, policyReflectorFuncs)
}

// addPolicy adds state data of a newly created K8s pod into the data
// store.
func (pr *PolicyReflector) addPolicy(obj interface{}) {
	pr.Log.WithField("policy", obj).Info("Policy added")

	k8sPolicy, ok := obj.(*coreV1Beta1.NetworkPolicy)
	if !ok {
		pr.Log.Warn("Failed to cast newly created policy object")
		pr.stats.ArgErrors++
		return
	}

	policyProto := pr.policyToProto(k8sPolicy)
	key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
	pr.ksrAdd(key, policyProto)
}

// deletePolicy deletes state data of a removed K8s network policy from the data
// store.
func (pr *PolicyReflector) deletePolicy(obj interface{}) {
	pr.Log.WithField("policy", obj).Info("Policy updated")

	k8sPolicy, ok := obj.(*coreV1Beta1.NetworkPolicy)
	if !ok {
		pr.Log.Warn("Failed to cast newly created service object")
		pr.stats.ArgErrors++
		return
	}

	key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
	pr.ksrDelete(key)
}

// updatePolicy updates state data of a changes K8s network policy in the data
// store.
func (pr *PolicyReflector) updatePolicy(oldObj, newObj interface{}) {
	oldK8sPolicy, ok1 := oldObj.(*coreV1Beta1.NetworkPolicy)
	newK8sPolicy, ok2 := newObj.(*coreV1Beta1.NetworkPolicy)
	if !ok1 || !ok2 {
		pr.Log.Warn("Failed to cast changed service object")
		pr.stats.ArgErrors++
		return
	}
	pr.Log.WithFields(map[string]interface{}{"policy-old": oldK8sPolicy, "policy-new": oldK8sPolicy}).
		Info("Policy updated")

	oldPolicyProto := pr.policyToProto(oldK8sPolicy)
	newPolicyProto := pr.policyToProto(newK8sPolicy)
	key := policy.Key(newK8sPolicy.GetName(), newK8sPolicy.GetNamespace())
	pr.ksrUpdate(key, oldPolicyProto, newPolicyProto)
}

// policyToProto converts pod state data from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) policyToProto(k8sPolicy *coreV1Beta1.NetworkPolicy) *policy.Policy {
	policyProto := &policy.Policy{}

	// Name
	policyProto.Name = k8sPolicy.GetName()
	policyProto.Namespace = k8sPolicy.GetNamespace()

	// Labels
	labels := k8sPolicy.GetLabels()
	if labels != nil {
		for key, val := range labels {
			policyProto.Label = append(policyProto.Label, &policy.Policy_Label{Key: key, Value: val})
		}
		// Make sure that labels are always stored in the same order to avoid
		// unnecessary updates during resync.
		sort.Slice(policyProto.Label, func(i, j int) bool {
			return policyProto.Label[i].Key < policyProto.Label[j].Key
		})
	}
	// Pods
	policyProto.Pods = pr.labelSelectorToProto(&k8sPolicy.Spec.PodSelector)

	// PolicyType
	ingress := 0
	egress := 0
	for _, policyType := range k8sPolicy.Spec.PolicyTypes {
		switch policyType {
		case coreV1Beta1.PolicyTypeIngress:
			ingress++
		case coreV1Beta1.PolicyTypeEgress:
			egress++
		}
	}
	if ingress > 0 && egress > 0 {
		policyProto.PolicyType = policy.Policy_INGRESS_AND_EGRESS
	} else if ingress > 0 {
		policyProto.PolicyType = policy.Policy_INGRESS
	} else if egress > 0 {
		policyProto.PolicyType = policy.Policy_EGRESS
	} else {
		policyProto.PolicyType = policy.Policy_DEFAULT
	}

	// Ingress rules
	if k8sPolicy.Spec.Ingress != nil {
		for _, ingress := range k8sPolicy.Spec.Ingress {
			ingressProto := &policy.Policy_IngressRule{}
			// Ports
			if ingress.Ports != nil {
				ingressProto.Port = pr.portsToProto(ingress.Ports)
			}
			// From
			if ingress.From != nil {
				ingressProto.From = pr.peersToProto(ingress.From)
			}
			// append rule
			policyProto.IngressRule = append(policyProto.IngressRule, ingressProto)
		}
	}

	// Egress rules
	if k8sPolicy.Spec.Egress != nil {
		for _, egress := range k8sPolicy.Spec.Egress {
			egressProto := &policy.Policy_EgressRule{}
			// Ports
			if egress.Ports != nil {
				egressProto.Port = pr.portsToProto(egress.Ports)
			}
			// From
			if egress.To != nil {
				egressProto.To = pr.peersToProto(egress.To)
			}
			// append rule
			policyProto.EgressRule = append(policyProto.EgressRule, egressProto)
		}
	}
	return policyProto
}

// labelSelectorToProto converts label selector from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) labelSelectorToProto(selector *clientApiMetaV1.LabelSelector) *policy.Policy_LabelSelector {
	selectorProto := &policy.Policy_LabelSelector{}
	// MatchLabels
	if selector.MatchLabels != nil {
		for key, val := range selector.MatchLabels {
			selectorProto.MatchLabel = append(selectorProto.MatchLabel, &policy.Policy_Label{Key: key, Value: val})
		}
	}
	// MatchExpressions
	if selector.MatchExpressions != nil {
		for _, expression := range selector.MatchExpressions {
			expressionProto := &policy.Policy_LabelSelector_LabelExpression{}
			// Key
			expressionProto.Key = expression.Key
			// Operator
			switch expression.Operator {
			case clientApiMetaV1.LabelSelectorOpIn:
				expressionProto.Operator = policy.Policy_LabelSelector_LabelExpression_IN
			case clientApiMetaV1.LabelSelectorOpNotIn:
				expressionProto.Operator = policy.Policy_LabelSelector_LabelExpression_NOT_IN
			case clientApiMetaV1.LabelSelectorOpExists:
				expressionProto.Operator = policy.Policy_LabelSelector_LabelExpression_EXISTS
			case clientApiMetaV1.LabelSelectorOpDoesNotExist:
				expressionProto.Operator = policy.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST

			}
			// Values
			if expression.Values != nil {
				for _, val := range expression.Values {
					expressionProto.Value = append(expressionProto.Value, val)
				}
			}

			selectorProto.MatchExpression = append(selectorProto.MatchExpression, expressionProto)
		}
	}

	// Make sure that match labels are always stored in the same order to avoid
	// unnecessary updates during resync.
	sort.Slice(selectorProto.MatchLabel, func(i, j int) bool {
		return selectorProto.MatchLabel[i].Key < selectorProto.MatchLabel[j].Key
	})

	return selectorProto
}

// portsToProto converts a list of ports from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) portsToProto(ports []coreV1Beta1.NetworkPolicyPort) (portsProto []*policy.Policy_Port) {
	for _, port := range ports {
		portProto := &policy.Policy_Port{}
		// Protocol
		if port.Protocol != nil {
			switch *port.Protocol {
			case coreV1.ProtocolTCP:
				portProto.Protocol = policy.Policy_Port_TCP
			case coreV1.ProtocolUDP:
				portProto.Protocol = policy.Policy_Port_UDP
			}
		}
		// Port number/name
		if port.Port != nil {
			portProto.Port = &policy.Policy_Port_PortNameOrNumber{}
			switch port.Port.Type {
			case intstr.Int:
				portProto.Port.Type = policy.Policy_Port_PortNameOrNumber_NUMBER
				portProto.Port.Number = port.Port.IntVal
			case intstr.String:
				portProto.Port.Type = policy.Policy_Port_PortNameOrNumber_NAME
				portProto.Port.Name = port.Port.StrVal
			}
		}
		// append port
		portsProto = append(portsProto, portProto)
	}
	return portsProto
}

// peersToProto converts a list of peers from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) peersToProto(peers []coreV1Beta1.NetworkPolicyPeer) (peersProto []*policy.Policy_Peer) {
	for _, peer := range peers {
		peerProto := &policy.Policy_Peer{}
		if peer.PodSelector != nil {
			// pod selector
			peerProto.Pods = pr.labelSelectorToProto(peer.PodSelector)
		} else if peer.NamespaceSelector != nil {
			// namespace selector
			peerProto.Namespaces = pr.labelSelectorToProto(peer.NamespaceSelector)
		} else if peer.IPBlock != nil {
			// IP block
			peerProto.IpBlock = &policy.Policy_Peer_IPBlock{}
			peerProto.IpBlock.Cidr = peer.IPBlock.CIDR
			for _, except := range peer.IPBlock.Except {
				peerProto.IpBlock.Except = append(peerProto.IpBlock.Except, except)
			}
		}
		// append peer
		peersProto = append(peersProto, peerProto)
	}
	return peersProto
}
