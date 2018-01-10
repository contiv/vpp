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

	// Wait for the initial sync to finish
	for {
		if nsTestVars.nsReflector.HasSynced() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	t.Run("newNamespace", testNewNamespace)
	nsTestVars.mockKvWriter.ClearDs()
	// TODO: add more
}

func testNewNamespace(t *testing.T) {
	ns := &coreV1.Namespace{}
	ns.Name = "namespace1"
	ns.Labels = make(map[string]string)
	ns.Labels["role"] = "mgmt"
	ns.Labels["privileged"] = "true"
	nsTestVars.k8sListWatch.Add(ns)

	nsProto := &proto.Namespace{}
	err := nsTestVars.mockKvWriter.GetValue(proto.Key(ns.GetName()), nsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProto).NotTo(gomega.BeNil())
	gomega.Expect(nsProto.Name).To(gomega.Equal(ns.GetName()))
	gomega.Expect(nsProto.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))
}
