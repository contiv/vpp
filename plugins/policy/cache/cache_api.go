package cache

import (
	"github.com/ligato/cn-infra/datasync"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

type PolicyCacheAPI interface {
	Update(dataChngEv datasync.ChangeEvent) error
	Resync(resyncEv datasync.ResyncEvent) error
	Watch(watcher *PolicyCacheWatcher)

	LookupPod(pod podmodel.ID) (found bool, data *podmodel.Pod)
	LookupPodsByLabelSelector(podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID)
	LookupPodsByNamespace(namespace nsmodel.ID) (pods []podmodel.ID)
	ListAllPods() (pods []podmodel.ID)

	LookupPolicy(policy podmodel.ID) (found bool, data *policymodel.Policy)
	LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID)
	ListAllPolicies() (policies []policymodel.ID)

	LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace)
	LookupNamespacesByLabelSelector(nsLabelSelector *policymodel.Policy_LabelSelector) (namespaces []nsmodel.ID)
	ListAllNamespaces() (namespaces []nsmodel.ID)
}

type PolicyCacheWatcher interface {
	Resync(data *K8sStateResyncData) error

	AddPod(pod *podmodel.Pod) error
	DelPod(pod *podmodel.Pod) error
	UpdatePod(oldPod, newPod *podmodel.Pod) error

	AddPolicy(policy *policymodel.Policy) error
	DelPolicy(policy *policymodel.Policy) error
	UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error

	AddNamespace(ns *nsmodel.Namespace) error
	DelNamespace(ns *nsmodel.Namespace) error
	UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error
}

type K8sStateResyncData struct {
	Namespaces []*nsmodel.Namespace
	Pods       []*podmodel.Pod
	Policies   []*policymodel.Policy
}
