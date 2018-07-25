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
	"fmt"
	"github.com/ligato/cn-infra/logging"
	"github.com/onsi/gomega"
	"sync"
	"testing"
)

const (
	mockReflectorType = "mockReflector"
)

type ReflectorRegistryTestVars struct {
	reflectorRegistry *ReflectorRegistry
	mockReflector     *Reflector
}

var rrTestVars ReflectorRegistryTestVars

func TestReflectorRegistry(t *testing.T) {
	gomega.RegisterTestingT(t)

	rrTestVars.reflectorRegistry = &ReflectorRegistry{
		lock:       sync.RWMutex{},
		reflectors: make(map[string]*Reflector),
	}

	rrTestVars.mockReflector = &Reflector{
		Log:               logging.ForPlugin("mock-reflector"),
		K8sClientset:      nil,
		K8sListWatch:      &k8sCache{},
		Broker:            nil,
		dsSynced:          false,
		objType:           mockReflectorType,
		ReflectorRegistry: rrTestVars.reflectorRegistry,
	}

	err := rrTestVars.reflectorRegistry.addReflector(rrTestVars.mockReflector)
	gomega.Expect(err).To(gomega.BeNil())

	err = rrTestVars.reflectorRegistry.addReflector(rrTestVars.mockReflector)
	gomega.Expect(err).To(gomega.MatchError(fmt.Errorf("%s reflector type already exists", mockReflectorType)))

	t.Run("testKsrHasSynced", testKsrHasSynced)
	t.Run("testGetRegisteredReflectors", testGetRegisteredReflectors)
	t.Run("testGetKsrStats", testGetKsrStats)
	t.Run("testGetStats", testGetStats)

}

func testKsrHasSynced(t *testing.T) {
	hasSynced := rrTestVars.reflectorRegistry.ksrHasSynced()
	gomega.Expect(hasSynced).To(gomega.BeFalse())

	rrTestVars.reflectorRegistry.reflectors[mockReflectorType].dsSynced = true
	hasSynced = rrTestVars.reflectorRegistry.ksrHasSynced()
	gomega.Expect(hasSynced).To(gomega.BeTrue())
}

func testGetRegisteredReflectors(t *testing.T) {
	rrList := rrTestVars.reflectorRegistry.getRegisteredReflectors()
	gomega.Expect(len(rrList)).To(gomega.Equal(1))
	gomega.Expect(rrList[0]).To(gomega.BeEquivalentTo(mockReflectorType))
}

func testGetKsrStats(t *testing.T) {
	stats, found := rrTestVars.reflectorRegistry.getKsrStats(mockReflectorType)
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(stats).To(gomega.Not(gomega.BeNil()))

	stats, found = rrTestVars.reflectorRegistry.getKsrStats("bogusReflector")
	gomega.Expect(found).To(gomega.BeFalse())
	gomega.Expect(stats).To(gomega.BeNil())
}

func testGetStats(t *testing.T) {
	stats := rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.BeNil())
	gomega.Expect(stats.ServiceStats).To(gomega.BeNil())
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.BeNil())
	gomega.Expect(stats.NamespaceStats).To(gomega.BeNil())
	gomega.Expect(stats.EndpointsStats).To(gomega.BeNil())

	rrTestVars.mockReflector.objType = endpointsObjType
	stats = rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.BeNil())
	gomega.Expect(stats.ServiceStats).To(gomega.BeNil())
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.BeNil())
	gomega.Expect(stats.NamespaceStats).To(gomega.BeNil())
	gomega.Expect(stats.EndpointsStats).To(gomega.Not(gomega.BeNil()))

	rrTestVars.mockReflector.objType = namespaceObjType
	stats = rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.BeNil())
	gomega.Expect(stats.ServiceStats).To(gomega.BeNil())
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.BeNil())
	gomega.Expect(stats.NamespaceStats).To(gomega.Not(gomega.BeNil()))
	gomega.Expect(stats.EndpointsStats).To(gomega.BeNil())

	rrTestVars.mockReflector.objType = podObjType
	stats = rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.BeNil())
	gomega.Expect(stats.ServiceStats).To(gomega.BeNil())
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.Not(gomega.BeNil()))
	gomega.Expect(stats.NamespaceStats).To(gomega.BeNil())
	gomega.Expect(stats.EndpointsStats).To(gomega.BeNil())

	rrTestVars.mockReflector.objType = serviceObjType
	stats = rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.BeNil())
	gomega.Expect(stats.ServiceStats).To(gomega.Not(gomega.BeNil()))
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.BeNil())
	gomega.Expect(stats.NamespaceStats).To(gomega.BeNil())
	gomega.Expect(stats.EndpointsStats).To(gomega.BeNil())

	rrTestVars.mockReflector.objType = nodeObjType
	stats = rrTestVars.reflectorRegistry.getStats()
	gomega.Expect(stats.NodeStats).To(gomega.Not(gomega.BeNil()))
	gomega.Expect(stats.ServiceStats).To(gomega.BeNil())
	gomega.Expect(stats.PolicyStats).To(gomega.BeNil())
	gomega.Expect(stats.PodStats).To(gomega.BeNil())
	gomega.Expect(stats.NamespaceStats).To(gomega.BeNil())
	gomega.Expect(stats.EndpointsStats).To(gomega.BeNil())
}
