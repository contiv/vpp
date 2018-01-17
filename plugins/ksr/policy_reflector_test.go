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
	// "encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	coreV1Beta1 "k8s.io/api/extensions/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/ligato/cn-infra/flavors/local"
)

type PolicyTestVars struct {
	k8sListWatch    *mockK8sListWatch
	mockKvWriter    *mockKeyProtoValWriter
	mockKvLister    *mockKeyProtoValLister
	policyReflector *PolicyReflector
	policyTestData  []coreV1Beta1.NetworkPolicy
}

var policyTestVars PolicyTestVars

func TestPolicyReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	policyTestVars.k8sListWatch = &mockK8sListWatch{}
	policyTestVars.mockKvWriter = newMockKeyProtoValWriter()
	policyTestVars.mockKvLister = newMockKeyProtoValLister(policyTestVars.mockKvWriter.ds)

	policyTestVars.policyReflector = &PolicyReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("policy-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: policyTestVars.k8sListWatch,
			Writer:       policyTestVars.mockKvWriter,
			Lister:       policyTestVars.mockKvLister,
			dsSynced:     false,
			objType:      "Policy",
		},
	}

	var pprotTcp coreV1.Protocol = "TCP"

	policyTestVars.policyTestData = []coreV1Beta1.NetworkPolicy{
		// Test data 0: mocks a new object to be added or a "pre-existing"
		// object that is updated during sync
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "test-network-policy",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/networkpolicies/test-network-policy",
				UID:             "44a9312f-f99f-11e7-b9b5-0800271d72be",
				ResourceVersion: "692693",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1Beta1.NetworkPolicySpec{
				PodSelector: metaV1.LabelSelector{
					MatchLabels:      map[string]string{"role": "db"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
				Ingress: []coreV1Beta1.NetworkPolicyIngressRule{
					{
						Ports: []coreV1Beta1.NetworkPolicyPort{
							{
								Protocol: &pprotTcp,
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 6372,
								},
							},
						},
						From: []coreV1Beta1.NetworkPolicyPeer{
							{
								IPBlock: &coreV1Beta1.IPBlock{
									CIDR: "172.17.0.0/16",
									Except: []string{
										"172.17.1.0/24",
										"172.17.3.0/24",
									},
								},
							},
							{
								NamespaceSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"project": "myproject"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"role": "frontend"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
						},
					},
				},
				Egress: []coreV1Beta1.NetworkPolicyEgressRule{
					{
						Ports: []coreV1Beta1.NetworkPolicyPort{
							{
								Protocol: &pprotTcp,
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 5978,
								},
							},
						},
						To: []coreV1Beta1.NetworkPolicyPeer{
							{
								IPBlock: &coreV1Beta1.IPBlock{
									CIDR: "10.0.0.0/24",
								},
							},
						},
					},
				},
				PolicyTypes: []coreV1Beta1.PolicyType{
					"Ingress",
					"Egress",
				},
			},
		},
		// Test data 1: mocks a pre-existing object in the data store that is
		// updated during the mark-and-sweep synchronization test because its
		// counterpart in the K8s cache has changed.
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "access-nginx",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/networkpolicies/access-nginx",
				UID:             "4c4a8d72-f9bc-11e7-b9b5-0800271d72be",
				ResourceVersion: "706490",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1Beta1.NetworkPolicySpec{
				PodSelector: metaV1.LabelSelector{
					MatchLabels:      map[string]string{"run": "nginx"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
				Ingress: []coreV1Beta1.NetworkPolicyIngressRule{
					{
						From: []coreV1Beta1.NetworkPolicyPeer{
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
						},
					},
				},
				Egress: []coreV1Beta1.NetworkPolicyEgressRule{
					{
						Ports: []coreV1Beta1.NetworkPolicyPort{
							{
								Protocol: &pprotTcp,
								Port: &intstr.IntOrString{
									Type:   intstr.Int,
									IntVal: 5978,
								},
							},
						},
						To: []coreV1Beta1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"name": "name"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"run": "nginx"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
						},
					},
				},
				PolicyTypes: []coreV1Beta1.PolicyType{
					"Ingress",
					"Egress",
				},
			},
		},
		// Test data 2: mocks a pre-existing "stale" object in the data store
		// that is deleted during the mark-and-sweep synchronization test
		// because its counterpart no longer exists in the K8s cache.
		{
			ObjectMeta: metaV1.ObjectMeta{
				Name:            "redis-allow-services",
				Namespace:       "default",
				SelfLink:        "/apis/extensions/v1beta1/namespaces/default/networkpolicies/redis-allow-services",
				UID:             "5a091b3c-f9c1-11e7-b9b5-0800271d72be",
				ResourceVersion: "708875",
				Generation:      1,
				CreationTimestamp: metaV1.Date(2018, 01, 14, 18, 53, 37, 0,
					time.FixedZone("PST", -800)),
			},
			Spec: coreV1Beta1.NetworkPolicySpec{
				PodSelector: metaV1.LabelSelector{
					MatchLabels:      map[string]string{"app": "bookstore", "role": "db"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
				Ingress: []coreV1Beta1.NetworkPolicyIngressRule{
					{
						From: []coreV1Beta1.NetworkPolicyPeer{
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"app": "bookstore", "role": "db"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"app": "bookstore", "role": "api"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
							{
								PodSelector: &metaV1.LabelSelector{
									MatchLabels:      map[string]string{"app": "inventory", "role": "web"},
									MatchExpressions: []metaV1.LabelSelectorRequirement{},
								},
							},
						},
					},
				},
				PolicyTypes: []coreV1Beta1.PolicyType{
					"Ingress",
				},
			},
		},
	}

	// The mock function returns two K8s mock endpoints instances:
	// - a new endpoints instance to be added to the data store
	// - a modified endpoints instance, where and existing instance in the
	//   data store is to be updated
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			// Updated value mock
			&policyTestVars.policyTestData[0],
			// New value mock
			&policyTestVars.policyTestData[1],
		}
	}

	// Pre-populate the mock data store with pre-existing data that is supposed
	// to be updated during the test.
	k8sPolicy1 := &policyTestVars.policyTestData[1]
	protoPolicy1 := policyTestVars.policyReflector.policyToProto(k8sPolicy1)
	checkPolicyToProtoTranslation(t, protoPolicy1, k8sPolicy1)

	protoPolicy1.Pods.MatchLabel = append(protoPolicy1.Pods.MatchLabel,
		&policy.Policy_Label{Key: "key", Value: "value"})
	policyTestVars.mockKvWriter.Put(policy.Key(k8sPolicy1.GetName(), k8sPolicy1.GetNamespace()), protoPolicy1)

	// Pre-populate the mock data store with "stale" data that is supposed to
	// be deleted during the test.
	k8sPolicy2 := &policyTestVars.policyTestData[2]
	protoPolicy2 := policyTestVars.policyReflector.policyToProto(k8sPolicy2)
	checkPolicyToProtoTranslation(t, protoPolicy2, k8sPolicy2)

	policyTestVars.mockKvWriter.Put(policy.Key(k8sPolicy2.GetName(), k8sPolicy2.GetNamespace()), protoPolicy2)

	statsBefore := *policyTestVars.policyReflector.GetStats()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := policyTestVars.policyReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	// Wait for the initial sync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *policyTestVars.policyReflector.GetStats()

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.NumAdds + 1).Should(gomega.BeNumerically("==", statsAfter.NumAdds))
	gomega.Expect(statsBefore.NumUpdates + 1).Should(gomega.BeNumerically("==", statsAfter.NumUpdates))
	gomega.Expect(statsBefore.NumDeletes + 1).Should(gomega.BeNumerically("==", statsAfter.NumDeletes))

	policyTestVars.mockKvWriter.ClearDs()

	t.Run("addDeletePolicy", testAddDeletePolicy)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("updatePolicy", testUpdatePolicy)
}

func testAddDeletePolicy(t *testing.T) {
	// Test policy add
	for _, k8sPolicy := range policyTestVars.policyTestData {
		// Take a snapshot of counters
		adds := policyTestVars.policyReflector.GetStats().NumAdds
		argErrs := policyTestVars.policyReflector.GetStats().NumArgErrors

		// Test add with wrong argument type
		policyTestVars.k8sListWatch.Add(k8sPolicy)

		gomega.Expect(argErrs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumArgErrors))
		gomega.Expect(adds).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumAdds))

		// Test add where everything should be good
		policyTestVars.k8sListWatch.Add(&k8sPolicy)

		key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
		protoPolicy := &policy.Policy{}
		err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)

		gomega.Expect(adds + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumAdds))
		gomega.Expect(err).To(gomega.BeNil())
		gomega.Expect(protoPolicy).NotTo(gomega.BeNil())
	}

	for _, k8sPolicy := range policyTestVars.policyTestData {
		// Take a snapshot of counters
		dels := policyTestVars.policyReflector.GetStats().NumDeletes
		argErrs := policyTestVars.policyReflector.GetStats().NumArgErrors

		// Test delete with wrong argument type
		policyTestVars.k8sListWatch.Delete(k8sPolicy)

		gomega.Expect(argErrs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumArgErrors))
		gomega.Expect(dels).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumDeletes))

		// Test delete where everything should be good
		policyTestVars.k8sListWatch.Delete(&k8sPolicy)
		gomega.Expect(dels + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().NumDeletes))

		key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
		protoPolicy := &policy.Policy{}
		err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
		gomega.Ω(err).ShouldNot(gomega.Succeed())
	}
}

func testUpdatePolicy(t *testing.T) {
}

// checkPolicyToProtoTranslation checks whether the translation of K8s policy
// into the Contiv-VPP protobuf format is correct.
func checkPolicyToProtoTranslation(t *testing.T, protoNp *policy.Policy, k8sNp *coreV1Beta1.NetworkPolicy) {

	gomega.Expect(protoNp.Name).To(gomega.Equal(k8sNp.GetName()))
	gomega.Expect(protoNp.Namespace).To(gomega.Equal(k8sNp.GetNamespace()))
	gomega.Expect(len(protoNp.Label)).To(gomega.Equal(len(k8sNp.Labels)))

	// Check labels
	for _, lbl := range protoNp.Label {
		gomega.Expect(lbl.Value).To(gomega.Equal(k8sNp.Labels[lbl.Key]))
	}

	// Check pod selectors
	checkLabelSelector(protoNp.Pods, &k8sNp.Spec.PodSelector)

	// Check ingress rules
	gomega.Expect(len(protoNp.IngressRule)).To(gomega.Equal(len(k8sNp.Spec.Ingress)))
	for i, rule := range protoNp.IngressRule {
		// Check port translations
		checkRulePorts(rule.Port, k8sNp.Spec.Ingress[i].Ports)
		// Check peer translations
		checkRulePeers(rule.From, k8sNp.Spec.Ingress[i].From)
	}

	// Check egress rules
	gomega.Expect(len(protoNp.EgressRule)).To(gomega.Equal(len(k8sNp.Spec.Egress)))
	for i, rule := range protoNp.EgressRule {
		// Check port translations
		checkRulePorts(rule.Port, k8sNp.Spec.Egress[i].Ports)
		// Check peer translations
		checkRulePeers(rule.To, k8sNp.Spec.Egress[i].To)
	}
}

// checkLabelSelector checks whether the translation of K8s label selector
// into the Contiv-VPP protobuf format is correct.
func checkLabelSelector(protoLbl *policy.Policy_LabelSelector, k8sLbl *metaV1.LabelSelector) {
	gomega.Expect(len(protoLbl.MatchLabel)).To(gomega.Equal(len(k8sLbl.MatchLabels)))
	for _, lbl := range protoLbl.MatchLabel {
		gomega.Expect(lbl.Value).To(gomega.Equal(k8sLbl.MatchLabels[lbl.Key]))
	}

	gomega.Expect(len(protoLbl.MatchExpression)).To(gomega.Equal(len(k8sLbl.MatchExpressions)))
	for i, expr := range protoLbl.MatchExpression {
		k8sExpr := k8sLbl.MatchExpressions[i]
		gomega.Expect(expr.Key).To(gomega.Equal(k8sExpr.Key))
		gomega.Expect(expr.Value).To(gomega.BeEquivalentTo(k8sExpr.Values))
		gomega.Expect(expr.Operator.String()).To(gomega.BeEquivalentTo(k8sExpr.Operator))
	}
}

// checkRulePorts checks whether the translation of K8s policy rules ports
// into the Contiv-VPP protobuf format is correct.
func checkRulePorts(protoPorts []*policy.Policy_Port, k8sPorts []coreV1Beta1.NetworkPolicyPort) {

	gomega.Expect(len(protoPorts)).To(gomega.Equal(len(k8sPorts)))

	for j, protoPort := range protoPorts {
		switch protoPort.Port.Type {
		case policy.Policy_Port_PortNameOrNumber_NUMBER:
			gomega.Expect(k8sPorts[j].Port.Type).To(gomega.Equal(intstr.Int))
			gomega.Expect(protoPort.Port.Number).To(gomega.Equal(k8sPorts[j].Port.IntVal))

		case policy.Policy_Port_PortNameOrNumber_NAME:
			gomega.Expect(k8sPorts[j].Port.Type).To(gomega.Equal(intstr.String))
			gomega.Expect(protoPort.Port.Name).To(gomega.Equal(k8sPorts[j].Port.StrVal))

		default:
			gomega.Panic()
		}
		gomega.Expect(protoPort.Protocol.String()).To(gomega.BeEquivalentTo(*k8sPorts[j].Protocol))
	}
}

// checkRulePeers checks whether the translation of K8s policy rules peers
// into the Contiv-VPP protobuf format is correct.
func checkRulePeers(protoPeers []*policy.Policy_Peer, k8sPeers []coreV1Beta1.NetworkPolicyPeer) {
	gomega.Expect(len(protoPeers)).To(gomega.Equal(len(k8sPeers)))
	for j, protoPeer := range protoPeers {
		k8sPeer := k8sPeers[j]

		// Check pod selector translation
		if protoPeer.Pods != nil {
			checkLabelSelector(protoPeer.Pods, k8sPeer.PodSelector)
		} else {
			gomega.Expect(k8sPeer.PodSelector).Should(gomega.BeNil())
		}

		// Check Namespace selector translation
		if protoPeer.Namespaces != nil {
			checkLabelSelector(protoPeer.Namespaces, k8sPeer.NamespaceSelector)
		} else {
			gomega.Expect(k8sPeer.NamespaceSelector).Should(gomega.BeNil())
		}

		// Check IP Block translation
		if protoPeer.IpBlock != nil {
			gomega.Expect(protoPeer.IpBlock.Cidr).To(gomega.Equal(k8sPeer.IPBlock.CIDR))
			gomega.Expect(protoPeer.IpBlock.Except).To(gomega.BeEquivalentTo(k8sPeer.IPBlock.Except))
		} else {
			gomega.Expect(k8sPeer.IPBlock).Should(gomega.BeNil())
		}
	}
}
