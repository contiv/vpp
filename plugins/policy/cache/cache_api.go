package cache

import (
	"github.com/ligato/cn-infra/datasync"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// PolicyCacheAPI defines API of PolicyCache used for a non-persistent storage
// of K8s State data with fast lookups.
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
// A watcher needs to implement the interface PolicyCacheWatcher and subscribe
// for watching using Watch() API.
// The cache provides various fast lookup methods (e.g. by the label selector).
type PolicyCacheAPI interface {
	// Update processes a datasync change event associated with K8s State data.
	// The change is applied into the cache and all subscribed watchers are
	// notified.
	// The function will forward any error returned by a watcher.
	Update(dataChngEv datasync.ChangeEvent) error

	// Resync processes a datasync resync event associated with K8s State data.
	// The cache content is full replaced with the received data and all
	// subscribed watchers are notified.
	// The function will forward any error returned by a watcher.
	Resync(resyncEv datasync.ResyncEvent) error

	// Watch subscribes a new watcher.
	Watch(watcher PolicyCacheWatcher)

	// LookupPod returns data of a given Pod.
	LookupPod(pod podmodel.ID) (found bool, data *podmodel.Pod)

	// LookupPodsByLabelSelector evaluates label selector (expression and/or match
	// labels) and returns IDs of matching pods.
	LookupPodsByLabelSelector(podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID)

	// LookupPodsByNamespace returns IDs of all pods inside a given namespace.
	LookupPodsByNamespace(namespace nsmodel.ID) (pods []podmodel.ID)

	// ListAllPods returns IDs of all known pods.
	ListAllPods() (pods []podmodel.ID)

	// LookupPolicy returns data of a given Policy.
	LookupPolicy(policy podmodel.ID) (found bool, data *policymodel.Policy)

	// LookupPoliciesByPod returns IDs of all policies assigned to a given pod.
	LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID)

	// ListAllPolicies returns IDs of all policies.
	ListAllPolicies() (policies []policymodel.ID)

	// LookupNamespace returns data of a given namespace.
	LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace)

	// LookupNamespacesByLabelSelector evaluates label selector (expression
	// and/or match labels) and returns IDs of matching namespaces.
	LookupNamespacesByLabelSelector(nsLabelSelector *policymodel.Policy_LabelSelector) (namespaces []nsmodel.ID)

	// ListAllNamespaces returns IDs of all known namespaces.
	ListAllNamespaces() (namespaces []nsmodel.ID)
}

// PolicyCacheWatcher defines interface that a PolicyCache watcher must implement.
type PolicyCacheWatcher interface {
	// Resync is called by Policy Cache during a RESYNC event.
	Resync(data *K8sStateResyncData) error

	// AddPod is called by Policy Cache when a new pod is created.
	AddPod(pod *podmodel.Pod) error

	// DelPod is called by Policy Cache after a pod was removed.
	DelPod(pod *podmodel.Pod) error

	// UpdatePod is called by Policy Cache when data of a pod were modified.
	UpdatePod(oldPod, newPod *podmodel.Pod) error

	// AddPolicy is called by Policy Cache when a new policy is created.
	AddPolicy(policy *policymodel.Policy) error

	// DelPolicy is called by Policy Cache after a policy was removed.
	DelPolicy(policy *policymodel.Policy) error

	// UpdatePolicy is called by Policy Cache when date of a policy were
	// modified.
	UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error

	// AddNamespace is called by Policy Cache when a new namespace is created.
	AddNamespace(ns *nsmodel.Namespace) error

	// DelNamespace is called by Policy Cache after a namespace was removed.
	DelNamespace(ns *nsmodel.Namespace) error

	// UpdateNamespace is called by Policy Cache when data of a namespace were
	// modified.
	UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error
}

// K8sStateResyncData contains a complete snapshot of K8s State data which should
// completely replace the currently installed configuration.
type K8sStateResyncData struct {
	Namespaces []*nsmodel.Namespace
	Pods       []*podmodel.Pod
	Policies   []*policymodel.Policy
}
