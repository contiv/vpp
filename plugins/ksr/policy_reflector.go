package ksr

import (
	"sync"

	core_v1 "k8s.io/api/core/v1"
	clientapi_metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/ksr/model/policy"
	core_v1beta1 "k8s.io/api/extensions/v1beta1"
)

// PolicyReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s network policies.
// Protobuf-modelled changes are published into the selected key-value store.
type PolicyReflector struct {
	ReflectorDeps

	stopCh <-chan struct{}
	wg     *sync.WaitGroup

	k8sPolicyStore      cache.Store
	k8sPolicyController cache.Controller
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s network policies. The subscription does not become active until Start()
// is called.
func (pr *PolicyReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	pr.stopCh = stopCh2
	pr.wg = wg

	restClient := pr.K8sClientset.ExtensionsV1beta1().RESTClient()
	listWatch := pr.K8sListWatch.NewListWatchFromClient(restClient, "networkpolicies", "", fields.Everything())
	pr.k8sPolicyStore, pr.k8sPolicyController = pr.K8sListWatch.NewInformer(
		listWatch,
		&core_v1beta1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				policy, ok := obj.(*core_v1beta1.NetworkPolicy)
				if !ok {
					pr.Log.Warn("Failed to cast newly created policy object")
				} else {
					pr.addPolicy(policy)
				}
			},
			DeleteFunc: func(obj interface{}) {
				policy, ok := obj.(*core_v1beta1.NetworkPolicy)
				if !ok {
					pr.Log.Warn("Failed to cast removed policy object")
				} else {
					pr.deletePolicy(policy)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				policyOld, ok1 := oldObj.(*core_v1beta1.NetworkPolicy)
				policyNew, ok2 := newObj.(*core_v1beta1.NetworkPolicy)
				if !ok1 || !ok2 {
					pr.Log.Warn("Failed to cast changed policy object")
				} else {
					pr.updatePolicy(policyNew, policyOld)
				}
			},
		},
	)
	return nil
}

// Start activates the K8s subscription.
func (pr *PolicyReflector) Start() {
	pr.wg.Add(1)
	go pr.run()
}

// addPolicy adds state data of a newly created K8s pod into the data
// store.
func (pr *PolicyReflector) addPolicy(policy *core_v1beta1.NetworkPolicy) {
	pr.Log.WithField("policy", policy).Info("Policy added")
	policyProto := pr.policyToProto(policy)
	key := proto.Key(policy.GetName(), policy.GetNamespace())
	err := pr.Publish.Put(key, policyProto)
	if err != nil {
		pr.Log.WithField("err", err).Warn("Failed to add policy state data into the data store")
	}
}

// deletePolicy deletes state data of a removed K8s network policy from the data
// store.
func (pr *PolicyReflector) deletePolicy(policy *core_v1beta1.NetworkPolicy) {
	pr.Log.WithField("policy", policy).Info("Policy removed")
	key := proto.Key(policy.GetName(), policy.GetNamespace())
	_, err := pr.Publish.Delete(key)
	if err != nil {
		pr.Log.WithField("err", err).Warn("Failed to remove policy state data from the data store")
	}
}

// updatePolicy updates state data of a changes K8s network policy in the data
// store.
func (pr *PolicyReflector) updatePolicy(policyNew, policyOld *core_v1beta1.NetworkPolicy) {
	pr.Log.WithFields(map[string]interface{}{"policy-old": policyOld, "policy-new": policyNew}).Info("Policy updated")
	policyProto := pr.policyToProto(policyNew)
	key := proto.Key(policyNew.GetName(), policyNew.GetNamespace())
	err := pr.Publish.Put(key, policyProto)
	if err != nil {
		pr.Log.WithField("err", err).Warn("Failed to update policy state data in the data store")
	}
}

// policyToProto converts pod state data from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) policyToProto(policy *core_v1beta1.NetworkPolicy) *proto.Policy {
	policyProto := &proto.Policy{}
	// Name
	policyProto.Name = policy.GetName()
	policyProto.Namespace = policy.GetNamespace()
	// Labels
	labels := policy.GetLabels()
	if labels != nil {
		for key, val := range labels {
			policyProto.Label = append(policyProto.Label, &proto.Policy_Label{Key: key, Value: val})
		}
	}
	// Pods
	policyProto.Pods = pr.labelSelectorToProto(&policy.Spec.PodSelector)
	// PolicyType
	ingress := 0
	egress := 0
	for _, policyType := range policy.Spec.PolicyTypes {
		switch policyType {
		case core_v1beta1.PolicyTypeIngress:
			ingress++
		case core_v1beta1.PolicyTypeEgress:
			egress++
		}
	}
	if ingress > 0 && egress > 0 {
		policyProto.PolicyType = proto.Policy_INGRESS_AND_EGRESS
	} else if ingress > 0 {
		policyProto.PolicyType = proto.Policy_INGRESS
	} else if egress > 0 {
		policyProto.PolicyType = proto.Policy_EGRESS
	} else {
		policyProto.PolicyType = proto.Policy_DEFAULT
	}
	// Ingress rules
	if policy.Spec.Ingress != nil {
		for _, ingress := range policy.Spec.Ingress {
			ingressProto := &proto.Policy_IngressRule{}
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
	if policy.Spec.Egress != nil {
		for _, egress := range policy.Spec.Egress {
			egressProto := &proto.Policy_EgressRule{}
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
func (pr *PolicyReflector) labelSelectorToProto(selector *clientapi_metav1.LabelSelector) *proto.Policy_LabelSelector {
	selectorProto := &proto.Policy_LabelSelector{}
	// MatchLabels
	if selector.MatchLabels != nil {
		for key, val := range selector.MatchLabels {
			selectorProto.MatchLabel = append(selectorProto.MatchLabel, &proto.Policy_Label{Key: key, Value: val})
		}
	}
	// MatchExpressions
	if selector.MatchExpressions != nil {
		for _, expression := range selector.MatchExpressions {
			expressionProto := &proto.Policy_LabelSelector_LabelExpression{}
			// Key
			expressionProto.Key = expression.Key
			// Operator
			switch expression.Operator {
			case clientapi_metav1.LabelSelectorOpIn:
				expressionProto.Operator = proto.Policy_LabelSelector_LabelExpression_IN
			case clientapi_metav1.LabelSelectorOpNotIn:
				expressionProto.Operator = proto.Policy_LabelSelector_LabelExpression_NOT_IN
			case clientapi_metav1.LabelSelectorOpExists:
				expressionProto.Operator = proto.Policy_LabelSelector_LabelExpression_EXISTS
			case clientapi_metav1.LabelSelectorOpDoesNotExist:
				expressionProto.Operator = proto.Policy_LabelSelector_LabelExpression_DOES_NOT_EXIST

			}
			// Values
			if expression.Values != nil {
				for _, val := range expression.Values {
					expressionProto.Value = append(expressionProto.Value, val)
				}
			}
			// append expression
			selectorProto.MatchExpression = append(selectorProto.MatchExpression, expressionProto)
		}
	}
	return selectorProto
}

// portsToProto converts a list of ports from the k8s representation into
// our protobuf-modelled data structure.
func (pr *PolicyReflector) portsToProto(ports []core_v1beta1.NetworkPolicyPort) (portsProto []*proto.Policy_Port) {
	for _, port := range ports {
		portProto := &proto.Policy_Port{}
		// Protocol
		if port.Protocol != nil {
			switch *port.Protocol {
			case core_v1.ProtocolTCP:
				portProto.Protocol = proto.Policy_Port_TCP
			case core_v1.ProtocolUDP:
				portProto.Protocol = proto.Policy_Port_UDP
			}
		}
		// Port number/name
		if port.Port != nil {
			portProto.Port = &proto.Policy_Port_PortNameOrNumber{}
			switch port.Port.Type {
			case intstr.Int:
				portProto.Port.Type = proto.Policy_Port_PortNameOrNumber_NUMBER
				portProto.Port.Number = port.Port.IntVal
			case intstr.String:
				portProto.Port.Type = proto.Policy_Port_PortNameOrNumber_NAME
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
func (pr *PolicyReflector) peersToProto(peers []core_v1beta1.NetworkPolicyPeer) (peersProto []*proto.Policy_Peer) {
	for _, peer := range peers {
		peerProto := &proto.Policy_Peer{}
		if peer.PodSelector != nil {
			// pod selector
			peerProto.Pods = pr.labelSelectorToProto(peer.PodSelector)
		} else if peer.NamespaceSelector != nil {
			// namespace selector
			peerProto.Namespaces = pr.labelSelectorToProto(peer.NamespaceSelector)
		} else if peer.IPBlock != nil {
			// IP block
			peerProto.IpBlock = &proto.Policy_Peer_IPBlock{}
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

// run runs k8s subscription in a separate go routine.
func (pr *PolicyReflector) run() {
	defer pr.wg.Done()

	pr.Log.Info("Policy reflector is now running")
	pr.k8sPolicyController.Run(pr.stopCh)
	pr.Log.Info("Stopping Policy reflector")
}

// Close does nothing for this particular reflector.
func (pr *PolicyReflector) Close() error {
	return nil
}
