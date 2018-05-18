package policycache

import (
	"github.com/ligato/cn-infra/datasync"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache"
)

// MockPolicyCache is mock for PolicyCache that only provides fake implementation
// of LookupPod().
type MockPolicyCache struct {
	pods map[podmodel.ID]*podmodel.Pod
}

// NewMockPolicyCache is a constructor for MockPolicyCache.
func NewMockPolicyCache() *MockPolicyCache {
	return &MockPolicyCache{
		pods: make(map[podmodel.ID]*podmodel.Pod),
	}
}

// AddPodConfig allows to fill the cache with fake pod data.
func (mpc *MockPolicyCache) AddPodConfig(id podmodel.ID, ipAddr string, labels ...*podmodel.Pod_Label) {
	pod := &podmodel.Pod{
		Name:      id.Name,
		Namespace: id.Namespace,
		IpAddress: ipAddr,
	}
	for _, label := range labels {
		pod.Label = append(pod.Label, label)
	}
	mpc.pods[id] = pod
}

// Update is not implemented by the mock.
func (mpc *MockPolicyCache) Update(dataChngEv datasync.ChangeEvent) error {
	return nil
}

// Resync is not implemented by the mock.
func (mpc *MockPolicyCache) Resync(resyncEv datasync.ResyncEvent) error {
	return nil
}

// Watch is not implemented by the mock.
func (mpc *MockPolicyCache) Watch(watcher cache.PolicyCacheWatcher) error {
	return nil
}

// LookupPod return pod config previously added using AddPodConfig.
func (mpc *MockPolicyCache) LookupPod(pod podmodel.ID) (found bool, data *podmodel.Pod) {
	data, found = mpc.pods[pod]
	return found, data
}

// LookupPodsByNSLabelSelector is not implemented by the mock.
func (mpc *MockPolicyCache) LookupPodsByLabelSelectorInsideNs(namespace string, podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	return nil
}

// LookupPodsByNsLabelSelector is not implemented by the mock.
func (mpc *MockPolicyCache) LookupPodsByNsLabelSelector(podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	return nil
}

// LookupPodsByNamespace is not implemented by the mock.
func (mpc *MockPolicyCache) LookupPodsByNamespace(policyNamespace string) (pods []podmodel.ID) {
	return nil
}

// ListAllPods is not implemented by the mock.
func (mpc *MockPolicyCache) ListAllPods() (pods []podmodel.ID) {
	return nil
}

// LookupPolicy is not implemented by the mock.
func (mpc *MockPolicyCache) LookupPolicy(policy policymodel.ID) (found bool, data *policymodel.Policy) {
	return false, nil
}

// LookupPoliciesByPod is not implemented by the mock.
func (mpc *MockPolicyCache) LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID) {
	return nil
}

// ListAllPolicies is not implemented by the mock.
func (mpc *MockPolicyCache) ListAllPolicies() (policies []policymodel.ID) {
	return nil
}

// LookupNamespace is not implemented by the mock.
func (mpc *MockPolicyCache) LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace) {
	return false, data
}

// ListAllNamespaces is not implemented by the mock.
func (mpc *MockPolicyCache) ListAllNamespaces() (namespaces []nsmodel.ID) {
	return nil
}
