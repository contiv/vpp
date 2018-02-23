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
	"sync"
	"testing"

	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
)

type mockKsrReflector struct {
	Reflector
}

type mockK8sController struct {
	synced  bool
	version string
	stopCh  <-chan struct{}
}

func (mc *mockK8sController) Run(stopCh <-chan struct{}) {
	mc.synced = true
	mc.stopCh = stopCh
	mc.version = "v2"
}

func (mc *mockK8sController) HasSynced() bool {
	return mc.synced
}

func (mc *mockK8sController) LastSyncResourceVersion() string {
	return mc.version
}

// TestKsrReflector runs KSR Reflector tests coveing code that is not covered
// in the typed reflector tests (for endpoints, policy, etc.)
func TestKsrReflector(t *testing.T) {
	t.Run("testKsrStartReflectors", testKsrStartReflectors)
	t.Run("testKsrReflectorClose", testKsrReflectorClose)
	t.Run("testKsrReflectorK8sSyncInitError", testKsrReflectorK8sSyncInitError)
}

func testKsrStartReflectors(t *testing.T) {
	gomega.RegisterTestingT(t)

	mockReflector := mockKsrReflector{}

	mockReflector.Log = logrus.DefaultLogger()
	mockReflector.wg = &sync.WaitGroup{}
	mockReflector.ksrStopCh = make(chan struct{})
	mockReflector.objType = "Mock"
	mockReflector.k8sController = &mockK8sController{false, "v1", nil}

	reflectors = make(map[string]*Reflector)
	reflectors[mockReflector.objType] = &mockReflector.Reflector

	startReflectors()

	mockReflector.wg.Wait()
	gomega.Expect(mockReflector.k8sController.HasSynced()).To(gomega.BeTrue())
}

func testKsrReflectorClose(t *testing.T) {
	gomega.RegisterTestingT(t)

	const mockObjType = "Mock"
	mockReflector := mockKsrReflector{}
	mockReflector.objType = mockObjType

	reflectors = make(map[string]*Reflector)

	err := mockReflector.Close()
	gomega.Ω(err).Should(gomega.MatchError(fmt.Sprintf("%s reflector type does not exist", mockObjType)))

	reflectors[mockReflector.objType] = &mockReflector.Reflector

	err = mockReflector.Close()
	gomega.Expect(err).To(gomega.BeNil())
}

func testKsrReflectorK8sSyncInitError(t *testing.T) {
	gomega.RegisterTestingT(t)

	const mockObjType = "Mock"

	mockReflector := mockKsrReflector{}

	mockReflector.objType = mockObjType
	mockReflector.dsMutex = sync.Mutex{}
	mockReflector.k8sController = &mockK8sController{false, "v1", nil}

	err := mockReflector.syncDataStoreWithK8sCache(nil)
	gomega.Ω(err).Should(gomega.MatchError(fmt.Sprintf("%s data sync: k8sController not synced", mockObjType)))
}
