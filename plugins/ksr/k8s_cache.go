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

// NewListWatchFromClient propagates the call to k8s client-go cache.
func (cache *k8sCache) NewListWatchFromClient(c cache.Getter, resource string, namespace string,
	fieldSelector fields.Selector) *cache.ListWatch {
	return cache.NewListWatchFromClient(c, resource, namespace, fieldSelector)
}

// NewInformer propagates the call to k8s client-go cache.
func (cache *k8sCache) NewInformer(lw cache.ListerWatcher, objType runtime.Object,
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
	return nil, &mockK8sListWatchController{}
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
