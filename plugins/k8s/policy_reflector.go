package k8s

import (
	"sync"

	clientapi_metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientapi_v1 "k8s.io/client-go/pkg/api/v1"
	clientapi_v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/k8s/model/policy"
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
	listWatch := cache.NewListWatchFromClient(restClient, "networkpolicies", "", fields.Everything())
	pr.k8sPolicyStore, pr.k8sPolicyController = cache.NewInformer(
		listWatch,
		&clientapi_v1beta1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				policy, ok := obj.(*clientapi_v1beta1.NetworkPolicy)
				if !ok {
					pr.Log.Warn("Failed to cast newly created policy object")
				} else {
					pr.addPolicy(policy)
				}
			},
			DeleteFunc: func(obj interface{}) {
				policy, ok := obj.(*clientapi_v1beta1.NetworkPolicy)
				if !ok {
					pr.Log.Warn("Failed to cast removed policy object")
				} else {
					pr.deletePolicy(policy)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				policyOld, ok1 := oldObj.(*clientapi_v1beta1.NetworkPolicy)
				policyNew, ok2 := newObj.(*clientapi_v1beta1.NetworkPolicy)
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
func (pr *PolicyReflector) addPolicy(policy *clientapi_v1beta1.NetworkPolicy) {
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
func (pr *PolicyReflector) deletePolicy(policy *clientapi_v1beta1.NetworkPolicy) {
	pr.Log.WithField("policy", policy).Info("Policy removed")
	// TODO (Delete not yet supported by kvdbsync)
	//key := proto.Key(policy.GetName(), policy.GetNamespace())
	//err := pr.Publish.Delete(key)
	//if err != nil {
	//	pr.Log.WithField("err", err).Warn("Failed to remove policy state data from the data store")
	//}
}

// updatePolicy updates state data of a changes K8s network policy in the data
// store.
func (pr *PolicyReflector) updatePolicy(policyNew, policyOld *clientapi_v1beta1.NetworkPolicy) {
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
func (pr *PolicyReflector) policyToProto(policy *clientapi_v1beta1.NetworkPolicy) *proto.Policy {
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
	// Ingress rules
	if policy.Spec.Ingress != nil {
		for _, ingress := range policy.Spec.Ingress {
			ingressProto := &proto.Policy_IngressRule{}
			// Ports
			if ingress.Ports != nil {
				for _, port := range ingress.Ports {
					portProto := &proto.Policy_IngressRule_Port{}
					// Protocol
					if port.Protocol != nil {
						switch *port.Protocol {
						case clientapi_v1.ProtocolTCP:
							portProto.Protocol = proto.Policy_IngressRule_Port_TCP
						case clientapi_v1.ProtocolUDP:
							portProto.Protocol = proto.Policy_IngressRule_Port_UDP
						}
					}
					// Port number/name
					if port.Port != nil {
						portProto.Port = &proto.Policy_IngressRule_Port_PortNameOrNumber{}
						switch port.Port.Type {
						case intstr.Int:
							portProto.Port.Type = proto.Policy_IngressRule_Port_PortNameOrNumber_NUMBER
							portProto.Port.Number = port.Port.IntVal
						case intstr.String:
							portProto.Port.Type = proto.Policy_IngressRule_Port_PortNameOrNumber_NUMBER
							portProto.Port.Number = port.Port.IntVal
						}
					}
					// append port
					ingressProto.Port = append(ingressProto.Port, portProto)
				}
			}
			// From
			if ingress.From != nil {
				for _, from := range ingress.From {
					fromProto := &proto.Policy_IngressRule_Peer{}
					// pod selectors
					if from.PodSelector != nil {
						fromProto.Pods = pr.labelSelectorToProto(from.PodSelector)
					} else if from.NamespaceSelector != nil {
						// namespace selectors
						fromProto.Namespaces = pr.labelSelectorToProto(from.NamespaceSelector)
					}
					// append peer
					ingressProto.From = append(ingressProto.From, fromProto)
				}
			}
			// append rule
			policyProto.IngressRule = append(policyProto.IngressRule, ingressProto)
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
