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
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"

	coreV1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	proto "github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/ligato/cn-infra/flavors/local"
)

type NamespaceTestVars struct {
	k8sListWatch *mockK8sListWatch
	mockKvWriter *mockKeyProtoVaBroker
	nsReflector  *NamespaceReflector
	svc          *coreV1.Service
	svcTestData  []coreV1.Service
}

var nsTestVars NamespaceTestVars

func TestNamespaceReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	nsTestVars.k8sListWatch = &mockK8sListWatch{}
	nsTestVars.mockKvWriter = newMockKeyProtoValBroker()

	nsTestVars.nsReflector = &NamespaceReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("namespace-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: nsTestVars.k8sListWatch,
			Broker:       nsTestVars.mockKvWriter,
			dsSynced:     false,
			objType:      namespaceObjType,
		},
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := nsTestVars.nsReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	nsTestVars.nsReflector.startDataStoreResync()

	// Wait for the initial sync to finish
	for {
		if nsTestVars.nsReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	t.Run("addDeleteNamespace", testAddDeleteNamespace)
	nsTestVars.mockKvWriter.ClearDs()
	t.Run("updateNamespace", testUpdateeNamespace)
}

func testAddDeleteNamespace(t *testing.T) {

	ns := &coreV1.Namespace{}
	ns.Name = "namespace1"
	ns.Labels = make(map[string]string)
	ns.Labels["role"] = "mgmt"
	ns.Labels["privileged"] = "true"

	// Take a snapshot of counters
	adds := nsTestVars.nsReflector.GetStats().Adds
	argErrs := nsTestVars.nsReflector.GetStats().ArgErrors

	// Test add with wrong argument type
	nsTestVars.k8sListWatch.Add(&ns)

	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().ArgErrors))
	gomega.Expect(adds).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Adds))

	// Test add where everything should be good
	nsTestVars.k8sListWatch.Add(ns)

	nsProto := &proto.Namespace{}
	_, _, err := nsTestVars.mockKvWriter.GetValue(proto.Key(ns.GetName()), nsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProto).NotTo(gomega.BeNil())
	gomega.Expect(nsProto.Name).To(gomega.Equal(ns.GetName()))
	gomega.Expect(nsProto.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))

	gomega.Expect(adds + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Adds))

	// Take a snapshot of counters
	dels := nsTestVars.nsReflector.GetStats().Deletes
	argErrs = nsTestVars.nsReflector.GetStats().ArgErrors

	nsTestVars.k8sListWatch.Delete(&ns)

	// Test delete with wrong argument type
	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().ArgErrors))
	gomega.Expect(dels).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Deletes))
	gomega.Expect(len(nsTestVars.mockKvWriter.ds)).Should(gomega.BeNumerically("==", 1))

	// Test delete where everything should be good
	nsTestVars.k8sListWatch.Delete(ns)

	// ArgErrors stat should roll and the data store should be empty
	gomega.Expect(dels + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Deletes))
	gomega.Expect(len(nsTestVars.mockKvWriter.ds)).Should(gomega.BeNumerically("==", 0))
}

func testUpdateeNamespace(t *testing.T) {

	nsOld := &coreV1.Namespace{}
	nsOld.Name = "namespace1"
	nsOld.Labels = make(map[string]string)
	nsOld.Labels["role"] = "mgmt"
	nsOld.Labels["privileged"] = "true"

	nsNew := &coreV1.Namespace{}
	nsNew.Name = nsOld.Name
	nsNew.Labels = make(map[string]string)
	nsNew.Labels["role"] = nsOld.Labels["role"]
	nsNew.Labels["privileged"] = "false" // <-- Different value for flag "privileged"

	adds := nsTestVars.nsReflector.GetStats().Adds

	nsTestVars.k8sListWatch.Add(nsOld)

	nsProtoOld := &proto.Namespace{}
	_, _, err := nsTestVars.mockKvWriter.GetValue(proto.Key(nsOld.GetName()), nsProtoOld)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProtoOld).NotTo(gomega.BeNil())
	gomega.Expect(nsProtoOld.Name).To(gomega.Equal(nsOld.GetName()))
	gomega.Expect(nsProtoOld.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))

	gomega.Expect(adds + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Adds))

	// Take a snapshot of counters
	updates := nsTestVars.nsReflector.GetStats().Updates
	argErrs := nsTestVars.nsReflector.GetStats().ArgErrors

	// Test update with wrong argument type
	nsTestVars.k8sListWatch.Update(nsOld, &nsNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().ArgErrors))
	gomega.Expect(updates).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Updates))

	// Test update where everything should be good
	nsTestVars.k8sListWatch.Update(nsOld, nsNew)

	gomega.Expect(updates + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().Updates))

	nsProtoNew := &proto.Namespace{}
	_, _, err = nsTestVars.mockKvWriter.GetValue(proto.Key(nsOld.GetName()), nsProtoNew)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))
	gomega.Expect(nsProtoNew.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "false"}))

}
