package cache

import (
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

type PolicyCache struct {
	PolicyCacheDeps
}

type PolicyCacheDeps struct {
	Log logging.Logger
}

func (pc *PolicyCache) Update(dataChngEv datasync.ChangeEvent) error {
	return nil
}

func (pc *PolicyCache) Resync(resyncEv datasync.ResyncEvent) error {
	return nil
}

func (pc *PolicyCache) Watch(watcher *PolicyCacheWatcher) {
}

func (pc *PolicyCache) LookupPod(pod podmodel.ID) (found bool, data *podmodel.Pod) {
	return false, nil
}

func (pc *PolicyCache) LookupPodsByLabelSelector(podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	return nil
}

func (pc *PolicyCache) LookupPodsByNamespace(namespace nsmodel.ID) (pods []podmodel.ID) {
	return nil
}

func (pc *PolicyCache) ListAllPods() (pods []podmodel.ID) {
	return nil
}

func (pc *PolicyCache) LookupPolicy(policy podmodel.ID) (found bool, data *policymodel.Policy) {
	return false, nil
}

func (pc *PolicyCache) LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID) {
	return nil
}

func (pc *PolicyCache) ListAllPolicies() (policies []policymodel.ID) {
	return nil
}

func (pc *PolicyCache) LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace) {
	return false, nil
}

func (pc *PolicyCache) LookupNamespacesByLabelSelector(nsLabelSelector *policymodel.Policy_LabelSelector) (namespaces []nsmodel.ID) {
	return nil
}

func (pc *PolicyCache) ListAllNamespaces() (namespaces []nsmodel.ID) {
	return nil
}
