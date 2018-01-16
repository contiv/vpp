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
	"time"

	"k8s.io/client-go/tools/cache"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
)

// K8sListWatcher is used to watch for Kubernetes config changes.
type K8sListWatcher interface {
	// NewListWatchFromClient creates a new ListWatch from the specified client, resource, namespace and field selector.
	NewListWatchFromClient(c cache.Getter, resource string, namespace string,
		fieldSelector fields.Selector) *cache.ListWatch

	// NewInformer returns a Store and a Controller for populating the store
	// while also providing event notifications.
	NewInformer(lw cache.ListerWatcher, objType runtime.Object, resyncPeriod time.Duration,
		h cache.ResourceEventHandler) (cache.Store, cache.Controller)
}

// k8sCache implements K8sListWatcher using k8s client-go cache.
type k8sCache struct {
}

// MockK8sCache holds the k8s mock cache
var MockK8sCache = &cache.FakeCustomStore{}

// NewListWatchFromClient propagates the call to k8s client-go cache.
func (*k8sCache) NewListWatchFromClient(c cache.Getter, resource string, namespace string,
	fieldSelector fields.Selector) *cache.ListWatch {
	return cache.NewListWatchFromClient(c, resource, namespace, fieldSelector)
}

// NewInformer propagates the call to k8s client-go cache.
func (*k8sCache) NewInformer(lw cache.ListerWatcher, objType runtime.Object,
	resyncPeriod time.Duration, h cache.ResourceEventHandler) (cache.Store, cache.Controller) {
	return cache.NewInformer(lw, objType, resyncPeriod, h)
}

// mockK8sListWatch is a mock implementation of K8sListWatcher used in unit tests.
type mockK8sListWatch struct {
	resourceHandler cache.ResourceEventHandler
}

// mockK8sListWatchController is a mock implementation of the controller for K8sListWatcher.
type mockK8sListWatchController struct {
}

// NewListWatchFromClient does nothing for the mock.
func (mock *mockK8sListWatch) NewListWatchFromClient(c cache.Getter, resource string, namespace string,
	fieldSelector fields.Selector) *cache.ListWatch {
	return nil
}

// NewInformer keeps resource handler callbacks for a simulated config changes.
func (mock *mockK8sListWatch) NewInformer(lw cache.ListerWatcher, objType runtime.Object,
	resyncPeriod time.Duration, h cache.ResourceEventHandler) (cache.Store, cache.Controller) {
	mock.resourceHandler = h
	return MockK8sCache, &mockK8sListWatchController{}
}

// Add simulates added K8s resource.
func (mock *mockK8sListWatch) Add(obj interface{}) {
	mock.resourceHandler.OnAdd(obj)
}

// Add simulates updated K8s resource.
func (mock *mockK8sListWatch) Update(oldObj, newObj interface{}) {
	mock.resourceHandler.OnUpdate(oldObj, newObj)
}

// Delete simulates removed K8s resource.
func (mock *mockK8sListWatch) Delete(obj interface{}) {
	mock.resourceHandler.OnDelete(obj)
}

// Run does nothing for the mock controller.
func (mock *mockK8sListWatchController) Run(stopCh <-chan struct{}) {
	return
}

// HasSync always returns true.
func (mock *mockK8sListWatchController) HasSynced() bool {
	return true
}

// LastSyncResourceVersion only returns an empty string.
func (mock *mockK8sListWatchController) LastSyncResourceVersion() string {
	return ""
}
