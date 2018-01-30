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
	mockKvWriter *mockKeyProtoValWriter
	mockKvLister *mockKeyProtoValLister
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
	nsTestVars.mockKvWriter = newMockKeyProtoValWriter()
	nsTestVars.mockKvLister = newMockKeyProtoValLister(nsTestVars.mockKvWriter.ds)

	nsTestVars.nsReflector = &NamespaceReflector{
		Reflector: Reflector{
			Log:          flavorLocal.LoggerFor("namespace-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: nsTestVars.k8sListWatch,
			Writer:       nsTestVars.mockKvWriter,
			Lister:       nsTestVars.mockKvLister,
			dsSynced:     false,
			objType:      "Service",
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
	adds := nsTestVars.nsReflector.GetStats().NumAdds
	argErrs := nsTestVars.nsReflector.GetStats().NumArgErrors

	// Test add with wrong argument type
	nsTestVars.k8sListWatch.Add(&ns)

	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumArgErrors))
	gomega.Expect(adds).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumAdds))

	// Test add where everything should be good
	nsTestVars.k8sListWatch.Add(ns)

	nsProto := &proto.Namespace{}
	err := nsTestVars.mockKvWriter.GetValue(proto.Key(ns.GetName()), nsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProto).NotTo(gomega.BeNil())
	gomega.Expect(nsProto.Name).To(gomega.Equal(ns.GetName()))
	gomega.Expect(nsProto.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))

	gomega.Expect(adds + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumAdds))

	// Take a snapshot of counters
	dels := nsTestVars.nsReflector.GetStats().NumDeletes
	argErrs = nsTestVars.nsReflector.GetStats().NumArgErrors

	nsTestVars.k8sListWatch.Delete(&ns)

	// Test delete with wrong argument type
	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumArgErrors))
	gomega.Expect(dels).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumDeletes))
	gomega.Expect(len(nsTestVars.mockKvWriter.ds)).Should(gomega.BeNumerically("==", 1))

	// Test delete where everything should be good
	nsTestVars.k8sListWatch.Delete(ns)

	// NumArgErrors stat should roll and the data store should be empty
	gomega.Expect(dels + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumDeletes))
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

	adds := nsTestVars.nsReflector.GetStats().NumAdds

	nsTestVars.k8sListWatch.Add(nsOld)

	nsProtoOld := &proto.Namespace{}
	err := nsTestVars.mockKvWriter.GetValue(proto.Key(nsOld.GetName()), nsProtoOld)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProtoOld).NotTo(gomega.BeNil())
	gomega.Expect(nsProtoOld.Name).To(gomega.Equal(nsOld.GetName()))
	gomega.Expect(nsProtoOld.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))

	gomega.Expect(adds + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumAdds))

	// Take a snapshot of counters
	updates := nsTestVars.nsReflector.GetStats().NumUpdates
	argErrs := nsTestVars.nsReflector.GetStats().NumArgErrors

	// Test update with wrong argument type
	nsTestVars.k8sListWatch.Update(nsOld, &nsNew)

	gomega.Expect(argErrs + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumArgErrors))
	gomega.Expect(updates).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumUpdates))

	// Test update where everything should be good
	nsTestVars.k8sListWatch.Update(nsOld, nsNew)

	gomega.Expect(updates + 1).To(gomega.Equal(nsTestVars.nsReflector.GetStats().NumUpdates))

	nsProtoNew := &proto.Namespace{}
	err = nsTestVars.mockKvWriter.GetValue(proto.Key(nsOld.GetName()), nsProtoNew)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(nsProtoOld.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))
	gomega.Expect(nsProtoNew.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "false"}))

}
