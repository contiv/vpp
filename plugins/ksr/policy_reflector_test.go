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
	"encoding/json"
	"fmt"
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
	mockKvWriter    *mockKeyProtoVaBroker
	policyReflector *PolicyReflector
	policyTestData  []coreV1Beta1.NetworkPolicy
}

var policyTestVars PolicyTestVars

func TestPolicyReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	policyTestVars.k8sListWatch = &mockK8sListWatch{}
	policyTestVars.mockKvWriter = newMockKeyProtoValBroker()

	policyTestVars.policyReflector = &PolicyReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("policy-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: policyTestVars.k8sListWatch,
			Broker:       policyTestVars.mockKvWriter,
			dsSynced:     false,
			objType:      policyObjType,
		},
	}

	var pprotTCP coreV1.Protocol = "TCP"

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
								Protocol: &pprotTCP,
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
								Protocol: &pprotTCP,
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
								Protocol: &pprotTCP,
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

	// Clear the reflector list (i.e. apply the policy resync tests only to
	// the policy reflector)
	reflectors = make(map[string]*Reflector)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := policyTestVars.policyReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	policyTestVars.policyReflector.startDataStoreResync()

	// Wait for the initial sync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	statsAfter := *policyTestVars.policyReflector.GetStats()

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))
	gomega.Expect(statsBefore.Adds + 1).Should(gomega.BeNumerically("==", statsAfter.Adds))
	gomega.Expect(statsBefore.Updates + 1).Should(gomega.BeNumerically("==", statsAfter.Updates))
	gomega.Expect(statsBefore.Deletes + 1).Should(gomega.BeNumerically("==", statsAfter.Deletes))

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("addDeletePolicy", testAddDeletePolicy)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("updatePolicy", testUpdatePolicy)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("testResyncPolicyAddFail", testResyncPolicyAddFail)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("testResyncPolicySingleDeleteFail", testResyncPolicyDeleteFail)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("testResyncPolicyUpdateFail", testResyncPolicyUpdateFail)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("testResyncPolicyAddFailAndDataStoreDown", testResyncPolicyAddFailAndDataStoreDown)

	policyTestVars.mockKvWriter.ClearDs()
	t.Run("testResyncPolicyDataStoreDownThenAdd", testResyncPolicyDataStoreDownThenAdd)
}

func testAddDeletePolicy(t *testing.T) {
	// Test the policy add operation
	for _, k8sPolicy := range policyTestVars.policyTestData {
		// Take a snapshot of counters
		adds := policyTestVars.policyReflector.GetStats().Adds
		argErrs := policyTestVars.policyReflector.GetStats().ArgErrors

		// Test add with wrong argument type
		policyTestVars.k8sListWatch.Add(k8sPolicy)

		gomega.Expect(argErrs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ArgErrors))
		gomega.Expect(adds).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))

		// Test add where everything should be good
		policyTestVars.k8sListWatch.Add(&k8sPolicy)

		key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
		protoPolicy := &policy.Policy{}
		_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)

		gomega.Expect(adds + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
		gomega.Expect(err).To(gomega.BeNil())
		gomega.Expect(protoPolicy).NotTo(gomega.BeNil())

		checkPolicyToProtoTranslation(t, protoPolicy, &k8sPolicy)
	}

	// Test the policy delete operation
	for _, k8sPolicy := range policyTestVars.policyTestData {
		// Take a snapshot of counters
		dels := policyTestVars.policyReflector.GetStats().Deletes
		argErrs := policyTestVars.policyReflector.GetStats().ArgErrors

		// Test delete with wrong argument type
		policyTestVars.k8sListWatch.Delete(k8sPolicy)

		gomega.Expect(argErrs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ArgErrors))
		gomega.Expect(dels).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))

		// Test delete where everything should be good
		policyTestVars.k8sListWatch.Delete(&k8sPolicy)
		gomega.Expect(dels + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))

		key := policy.Key(k8sPolicy.GetName(), k8sPolicy.GetNamespace())
		protoPolicy := &policy.Policy{}
		_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
		gomega.Ω(err).ShouldNot(gomega.Succeed())
	}

	policyTestVars.policyReflector.Log.Infof("%s: data sync done, stats: %+v",
		policyTestVars.policyReflector.objType, policyTestVars.policyReflector.stats)
}

func testUpdatePolicy(t *testing.T) {
	// Prepare test data
	k8sPolicyOld := &policyTestVars.policyTestData[0]
	tmpBuf, err := json.Marshal(k8sPolicyOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPolicyNew := &coreV1Beta1.NetworkPolicy{}
	err = json.Unmarshal(tmpBuf, k8sPolicyNew)
	gomega.Ω(err).Should(gomega.Succeed())

	// Take a snapshot of counters
	upds := policyTestVars.policyReflector.GetStats().Updates
	argErrs := policyTestVars.policyReflector.GetStats().ArgErrors

	// Test update with wrong argument type
	policyTestVars.k8sListWatch.Update(*k8sPolicyOld, *k8sPolicyNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ArgErrors))
	gomega.Expect(upds).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))

	// Ensure that there is no update if old and new values are the same
	policyTestVars.k8sListWatch.Update(k8sPolicyOld, k8sPolicyNew)
	gomega.Expect(upds).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))

	// Test update where everything should be good
	k8sPolicyNew.Spec.Egress = append(k8sPolicyNew.Spec.Egress, coreV1Beta1.NetworkPolicyEgressRule{
		Ports: []coreV1Beta1.NetworkPolicyPort{
			{
				Port: &intstr.IntOrString{
					Type:   intstr.String,
					StrVal: "my_name",
				},
			},
		},
		To: []coreV1Beta1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metaV1.LabelSelector{
					MatchLabels:      map[string]string{"key1": "name1"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
			},
			{
				PodSelector: &metaV1.LabelSelector{
					MatchLabels:      map[string]string{"key2": "name2"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
			},
		},
	})

	policyTestVars.k8sListWatch.Update(k8sPolicyOld, k8sPolicyNew)
	gomega.Expect(upds + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))

	key := policy.Key(k8sPolicyOld.GetName(), k8sPolicyOld.GetNamespace())
	protoPolicyNew := &policy.Policy{}
	_, _, err = policyTestVars.mockKvWriter.GetValue(key, protoPolicyNew)
	gomega.Ω(err).Should(gomega.Succeed())

	checkPolicyToProtoTranslation(t, protoPolicyNew, k8sPolicyNew)

	policyTestVars.policyReflector.Log.Infof("%s: data sync done, stats: %+v",
		policyTestVars.policyReflector.objType, policyTestVars.policyReflector.stats)
}

func testResyncPolicyAddFail(t *testing.T) {

	// Set the mock K8s cache to expect 3 values.
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			&policyTestVars.policyTestData[0],
			&policyTestVars.policyTestData[1],
			&policyTestVars.policyTestData[2],
		}
	}

	// Take a snapshot of reflector counters
	sSnap := *policyTestVars.policyReflector.GetStats()

	// Add two elements
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[0])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[1])
	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))

	gomega.Expect(sSnap.Adds + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))

	// Injecting two errors into the Broker and one error in the Lister will test
	// the data sync good path and all error paths
	policyTestVars.mockKvWriter.injectListError(fmt.Errorf("%s", "Lister test error"), 1)
	policyTestVars.mockKvWriter.injectReadWriteError(fmt.Errorf("%s", "Read/write test error"), 2)

	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[2])

	// Wait for the resync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	policyTestVars.policyReflector.Log.Infof("*** data sync done:\nsSnap: %+v\nstats: %+v",
		sSnap, policyTestVars.policyReflector.stats)

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.Updates).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))
	gomega.Expect(sSnap.Deletes).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))
	gomega.Expect(sSnap.Resyncs + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Resyncs))
	gomega.Expect(sSnap.AddErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))
	gomega.Expect(sSnap.UpdErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().UpdErrors))
	gomega.Expect(sSnap.DelErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().DelErrors))
	gomega.Expect(sSnap.ResErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ResErrors))

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(3))

	key := policy.Key(policyTestVars.policyTestData[2].GetName(), policyTestVars.policyTestData[2].GetNamespace())
	protoPolicy := &policy.Policy{}
	_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
	gomega.Ω(err).Should(gomega.Succeed())
	checkPolicyToProtoTranslation(t, protoPolicy, &policyTestVars.policyTestData[2])
}

func testResyncPolicyDeleteFail(t *testing.T) {
	// Set the mock K8s cache to expect 3 values.
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			&policyTestVars.policyTestData[0],
			&policyTestVars.policyTestData[2],
		}
	}

	// Take a snapshot of reflector counters
	sSnap := *policyTestVars.policyReflector.GetStats()

	// Add three elements
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[0])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[1])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[2])

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))

	// Injecting two errors into the Broker and one error in the Lister will test
	// the data sync good path and all error paths
	policyTestVars.mockKvWriter.injectListError(fmt.Errorf("%s", "Lister test error"), 1)
	policyTestVars.mockKvWriter.injectReadWriteError(fmt.Errorf("%s", "Read/write test error"), 2)

	// Delete an element, write error happens during delete
	policyTestVars.k8sListWatch.Delete(&policyTestVars.policyTestData[1])

	// Wait for the resync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	policyTestVars.policyReflector.Log.Infof("*** data sync done:\nsSnap: %+v\nstats: %+v",
		sSnap, policyTestVars.policyReflector.stats)

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.Updates).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))
	gomega.Expect(sSnap.Deletes + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))
	gomega.Expect(sSnap.Resyncs + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Resyncs))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))
	gomega.Expect(sSnap.UpdErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().UpdErrors))
	gomega.Expect(sSnap.DelErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().DelErrors))
	gomega.Expect(sSnap.ResErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ResErrors))

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))

	key := policy.Key(policyTestVars.policyTestData[1].GetName(), policyTestVars.policyTestData[2].GetNamespace())
	protoPolicy := &policy.Policy{}
	_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
	gomega.Ω(err).ShouldNot(gomega.Succeed())
}

func testResyncPolicyUpdateFail(t *testing.T) {
	// Deep copy an existing (old) policy into an updaged (new) policy
	k8sPolicyOld := &policyTestVars.policyTestData[0]
	tmpBuf, err := json.Marshal(k8sPolicyOld)
	gomega.Ω(err).Should(gomega.Succeed())
	k8sPolicyNew := &coreV1Beta1.NetworkPolicy{}
	err = json.Unmarshal(tmpBuf, k8sPolicyNew)
	gomega.Ω(err).Should(gomega.Succeed())

	// Take a snapshot of reflector counters
	sSnap := *policyTestVars.policyReflector.GetStats()

	// Add three elements
	policyTestVars.k8sListWatch.Add(k8sPolicyOld)
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[1])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[2])

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))

	// Test update where everything should be good
	k8sPolicyNew.Spec.Egress = append(k8sPolicyNew.Spec.Egress, coreV1Beta1.NetworkPolicyEgressRule{
		Ports: []coreV1Beta1.NetworkPolicyPort{
			{
				Port: &intstr.IntOrString{
					Type:   intstr.String,
					StrVal: "my_name",
				},
			},
		},
		To: []coreV1Beta1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metaV1.LabelSelector{
					MatchLabels:      map[string]string{"key1": "name1"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
			},
			{
				PodSelector: &metaV1.LabelSelector{
					MatchLabels:      map[string]string{"key2": "name2"},
					MatchExpressions: []metaV1.LabelSelectorRequirement{},
				},
			},
		},
	})

	// Set the mock K8s cache to expect 3 values.
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			k8sPolicyNew,
			&policyTestVars.policyTestData[2],
			&policyTestVars.policyTestData[1],
		}
	}

	// Injecting two errors into the Broker and one error in the Lister will test
	// the data sync good path and all error paths
	policyTestVars.mockKvWriter.injectListError(fmt.Errorf("%s", "Lister test error"), 1)
	policyTestVars.mockKvWriter.injectReadWriteError(fmt.Errorf("%s", "Read/write test error"), 2)

	// Delete an element, write error happens during delete
	policyTestVars.k8sListWatch.Update(k8sPolicyOld, k8sPolicyNew)

	// Wait for the resync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	policyTestVars.policyReflector.Log.Infof("*** data sync done:\nsSnap: %+v\nstats: %+v",
		sSnap, policyTestVars.policyReflector.stats)

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.Deletes).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))
	gomega.Expect(policyTestVars.policyReflector.GetStats().Updates).To(gomega.Equal(sSnap.Updates + 1))
	gomega.Expect(sSnap.Resyncs + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Resyncs))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))
	gomega.Expect(sSnap.DelErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().DelErrors))
	gomega.Expect(sSnap.UpdErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().UpdErrors))
	gomega.Expect(sSnap.ResErrors + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ResErrors))

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(3))

	key := policy.Key(k8sPolicyNew.GetName(), k8sPolicyNew.GetNamespace())
	protoPolicy := &policy.Policy{}
	_, _, err = policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
	gomega.Ω(err).Should(gomega.Succeed())
	checkPolicyToProtoTranslation(t, protoPolicy, k8sPolicyNew)
}

func testResyncPolicyDataStoreDownThenAdd(t *testing.T) {
	// Set the mock K8s cache to expect 3 values.
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			&policyTestVars.policyTestData[2],
			&policyTestVars.policyTestData[0],
			&policyTestVars.policyTestData[1],
		}
	}

	// Take a snapshot of reflector counters
	sSnap := *policyTestVars.policyReflector.GetStats()

	// Add two elements
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[0])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[1])
	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))

	gomega.Expect(sSnap.Adds + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))

	dataStoreDownEvent()

	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[2])

	dataStoreUpEvent()

	// Wait for the resync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	policyTestVars.policyReflector.Log.Infof("*** data sync done:\nsSnap: %+v\nstats: %+v",
		sSnap, policyTestVars.policyReflector.stats)

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.Updates).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))
	gomega.Expect(sSnap.Deletes).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Deletes))
	gomega.Expect(sSnap.Resyncs + 1).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Resyncs))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))
	gomega.Expect(sSnap.UpdErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().UpdErrors))
	gomega.Expect(sSnap.DelErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().DelErrors))
	gomega.Expect(sSnap.ResErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().ResErrors))

	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(3))

	key := policy.Key(policyTestVars.policyTestData[2].GetName(), policyTestVars.policyTestData[2].GetNamespace())
	protoPolicy := &policy.Policy{}
	_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
	gomega.Ω(err).Should(gomega.Succeed())
	checkPolicyToProtoTranslation(t, protoPolicy, &policyTestVars.policyTestData[2])
}

func testResyncPolicyAddFailAndDataStoreDown(t *testing.T) {

	// Set the mock K8s cache to expect 3 values.
	MockK8sCache.ListFunc = func() []interface{} {
		return []interface{}{
			&policyTestVars.policyTestData[0],
			&policyTestVars.policyTestData[1],
			&policyTestVars.policyTestData[2],
		}
	}

	// Take a snapshot of counters
	sSnap := *policyTestVars.policyReflector.GetStats()

	// Add two elements
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[0])
	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[1])
	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(2))

	gomega.Expect(sSnap.Adds + 2).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.AddErrors).To(gomega.Equal(policyTestVars.policyReflector.GetStats().AddErrors))

	// Injecting and "infinite number" of errors into the Broker will keep
	// data sync in the rmark-and-sweep etry loop so that we can inject the
	// 'data store down' signal and thus abort the loop.
	// Injecting two errors into the Broker and one error in the Lister will test
	// the data sync good path and all error paths
	policyTestVars.mockKvWriter.injectListError(fmt.Errorf("%s", "Lister test error"), 1)
	policyTestVars.mockKvWriter.injectReadWriteError(fmt.Errorf("%s", "Read/write test error"), 1000)

	policyTestVars.k8sListWatch.Add(&policyTestVars.policyTestData[2])

	// Emulate the data store down/up sequence
	go func() {
		time.Sleep(time.Second)
		dataStoreDownEvent()
		time.Sleep(time.Second)
		policyTestVars.mockKvWriter.clearReadWriteError()
		dataStoreUpEvent()
	}()

	// Wait for the resync to finish
	for {
		if policyTestVars.policyReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	policyTestVars.policyReflector.Log.Infof("*** data sync done:\nsSnap: %+v\nstats: %+v",
		sSnap, policyTestVars.policyReflector.stats)

	gomega.Expect(sSnap.Adds + 3).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Adds))
	gomega.Expect(sSnap.Updates).To(gomega.Equal(policyTestVars.policyReflector.GetStats().Updates))
	gomega.Expect(policyTestVars.policyReflector.GetStats().AddErrors - sSnap.AddErrors).
		To(gomega.Equal(policyTestVars.policyReflector.GetStats().ResErrors - sSnap.ResErrors))
	gomega.Expect(policyTestVars.mockKvWriter.ds).Should(gomega.HaveLen(3))

	key := policy.Key(policyTestVars.policyTestData[2].GetName(), policyTestVars.policyTestData[2].GetNamespace())
	protoPolicy := &policy.Policy{}
	_, _, err := policyTestVars.mockKvWriter.GetValue(key, protoPolicy)
	gomega.Ω(err).Should(gomega.Succeed())
	checkPolicyToProtoTranslation(t, protoPolicy, &policyTestVars.policyTestData[2])
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

	// Check policy type
	checkPolicyType(protoNp.PolicyType, k8sNp.Spec.PolicyTypes)

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

		if k8sPorts[j].Protocol == nil {
			gomega.Expect(protoPort.Protocol).To(gomega.BeNumerically("==", policy.Policy_Port_TCP))
		} else {
			gomega.Expect(protoPort.Protocol.String()).To(gomega.BeEquivalentTo(*k8sPorts[j].Protocol))
		}
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

// checkPolicyType checks whether the translation of K8s policy type into
// the Contiv-VPP protobuf format is correct.
func checkPolicyType(protoPtype policy.Policy_PolicyType, k8sPtypes []coreV1Beta1.PolicyType) {
	switch protoPtype {

	case policy.Policy_INGRESS:
		gomega.Expect(len(k8sPtypes)).To(gomega.Equal(1))
		gomega.Expect(k8sPtypes[0]).To(gomega.BeEquivalentTo(coreV1Beta1.PolicyTypeIngress))

	case policy.Policy_EGRESS:
		gomega.Expect(len(k8sPtypes)).To(gomega.Equal(1))
		gomega.Expect(k8sPtypes[0]).To(gomega.BeEquivalentTo(coreV1Beta1.PolicyTypeEgress))

	case policy.Policy_INGRESS_AND_EGRESS:
		gomega.Expect(len(k8sPtypes)).To(gomega.Equal(2))
		gomega.Expect(stringsInSlice([]coreV1Beta1.PolicyType{
			coreV1Beta1.PolicyTypeEgress,
			coreV1Beta1.PolicyTypeIngress,
		}, k8sPtypes)).To(gomega.BeTrue())

	case policy.Policy_DEFAULT:
		gomega.Expect(len(k8sPtypes)).To(gomega.Equal(0))
	}
}

// stringsInSlice ensures that K8sPolicyTypes contains all policy types
// listed in 'pd'.
func stringsInSlice(pd []coreV1Beta1.PolicyType, K8sPolicyTypes []coreV1Beta1.PolicyType) bool {
loop:
	for _, s := range pd {
		for _, v := range K8sPolicyTypes {
			if v == s {
				continue loop
			}
		}
		return false
	}
	return true
}
