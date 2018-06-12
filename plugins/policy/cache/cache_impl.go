package cache

import (
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache/namespaceidx"
	"github.com/contiv/vpp/plugins/policy/cache/podidx"
	"github.com/contiv/vpp/plugins/policy/cache/policyidx"
	"github.com/contiv/vpp/plugins/policy/utils"
)

// PolicyCache s used for a in-memory storage of K8s State data with fast
// lookups using idxmap-s.
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
// A watcher needs to implement the interface PolicyCacheWatcher and subscribe
// for watching using Watch() API.
// The cache provides various fast lookup methods (e.g. by the label selector).
type PolicyCache struct {
	Deps

	configuredPolicies   *policyidx.ConfigIndex
	configuredPods       *podidx.ConfigIndex
	configuredNamespaces *namespaceidx.ConfigIndex
	watchers             []PolicyCacheWatcher
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// Init initializes policy cache.
func (pc *PolicyCache) Init() error {
	pc.configuredPolicies = policyidx.NewConfigIndex(pc.Log, "policies")
	pc.configuredPods = podidx.NewConfigIndex(pc.Log, "pods")
	pc.configuredNamespaces = namespaceidx.NewConfigIndex(pc.Log, "namespaces")

	pc.watchers = []PolicyCacheWatcher{}
	return nil
}

// Update processes a datasync change event associated with K8s State data.
// The change is applied into the cache and all subscribed watchers are
// notified.
// The function will forward any error returned by a watcher.
func (pc *PolicyCache) Update(dataChngEv datasync.ChangeEvent) error {
	err := pc.changePropagateEvent(dataChngEv)
	if err != nil {
		return err
	}

	return nil
}

// Resync processes a datasync resync event associated with K8s State data.
// The cache content is full replaced with the received data and all
// subscribed watchers are notified.
// The function will forward any error returned by a watcher.
func (pc *PolicyCache) Resync(resyncEv datasync.ResyncEvent) error {
	dataResyncEvent := pc.resyncParseEvent(resyncEv)

	for _, watcher := range pc.watchers {
		watcher.Resync(dataResyncEvent)
	}

	return nil
}

// Watch subscribes a new watcher.
func (pc *PolicyCache) Watch(watcher PolicyCacheWatcher) error {
	pc.watchers = append(pc.watchers, watcher)
	return nil
}

// LookupPod returns data of a given Pod.
func (pc *PolicyCache) LookupPod(pod podmodel.ID) (found bool, data *podmodel.Pod) {
	return pc.configuredPods.LookupPod(pod.String())
}

// LookupPodsByLabelSelectorInsideNs evaluates pod label selectors in a namespace and returns IDs of matching pods.
func (pc *PolicyCache) LookupPodsByLabelSelectorInsideNs(policyNamespace string,
	podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {

	// An empty podSelector matches all pods in this namespace.
	if len(podLabelSelector.MatchExpression) == 0 && len(podLabelSelector.MatchLabel) == 0 {
		pods := pc.configuredPods.LookupPodsByNamespace(policyNamespace)
		pc.Log.WithField("LookupPodsByNSLabelSelector", policyNamespace).
			Infof("Empty PodSelector returning pods: %+v", pods)
		return utils.UnstringPodID(pods)
	}

	// List of match labels and match expressions.
	matchLabels := podLabelSelector.MatchLabel
	matchExpressions := podLabelSelector.MatchExpression

	// Get matching pods for policy's pod label selectors
	mlPods := pc.getMatchLabelPodsInsideNs(policyNamespace, matchLabels)
	mePods := pc.getMatchExpressionPodsInsideNs(policyNamespace, matchExpressions)

	// If both pod labels and expressions exist,
	// we need to find the intersection of the returning pods
	// Requirements are AND'ed
	if len(matchLabels) > 0 && len(matchExpressions) > 0 {
		return utils.UnstringPodID(utils.Intersect(mlPods, mePods))
	}
	if len(matchLabels) > 0 {
		return utils.UnstringPodID(mlPods)
	}
	return utils.UnstringPodID(mePods)
}

// LookupPodsByNsLabelSelector evaluates namespace label selector and returns IDs of pods in the matched namespaces.
func (pc *PolicyCache) LookupPodsByNsLabelSelector(
	namespaceLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	// An empty namespace selector matches all namespaces.
	if len(namespaceLabelSelector.MatchExpression) == 0 && len(namespaceLabelSelector.MatchLabel) == 0 {
		allPods := pc.configuredPods.ListAll()
		kubeSystemPods := pc.configuredPods.LookupPodsByNamespace("kube-system")
		// Excluding "kube-system" pods
		pods := utils.Difference(allPods, kubeSystemPods)

		pc.Log.WithField("LookupPodsByNSLabelSelector", namespaceLabelSelector).
			Infof("Empty namespace selector returning pods: %+v", pods)
		return utils.UnstringPodID(pods)
	}

	// List of match labels and match expressions.
	matchNsLabels := namespaceLabelSelector.MatchLabel
	matchNsExpressions := namespaceLabelSelector.MatchExpression

	// Get matching pods for policy's namespace label selectors
	mlPods := pc.getPodsByNsLabelSelector(matchNsLabels)
	mePods := pc.getPodsByNsMatchExpression(matchNsExpressions)

	// If both namespace labels and expressions exist,
	// we need to find the intersection of the returning pods
	// Requirements are AND'ed
	if len(matchNsLabels) > 0 && len(matchNsExpressions) > 0 {
		return utils.UnstringPodID(utils.Intersect(mlPods, mePods))
	}
	if len(matchNsLabels) > 0 {
		return utils.UnstringPodID(mlPods)
	}
	return utils.UnstringPodID(mePods)

}

// LookupPodsByNamespace returns IDs of all pods inside a given namespace.
func (pc *PolicyCache) LookupPodsByNamespace(namespace string) (pods []podmodel.ID) {
	podsByNamespace := pc.configuredPods.LookupPodsByNamespace(namespace)
	pods = utils.UnstringPodID(podsByNamespace)

	return pods
}

// ListAllPods returns the IDs of all known pods.
func (pc *PolicyCache) ListAllPods() (pods []podmodel.ID) {
	allPods := pc.configuredPods.ListAll()
	pods = utils.UnstringPodID(allPods)

	return pods
}

// LookupPolicy returns the data of a given Policy.
func (pc *PolicyCache) LookupPolicy(policy policymodel.ID) (found bool, data *policymodel.Policy) {
	found, data = pc.configuredPolicies.LookupPolicy(policy.String())
	if !found {
		return found, nil
	}
	return found, data
}

// LookupPoliciesByPod returns the IDs of all policies assigned to a given pod.
func (pc *PolicyCache) LookupPoliciesByPod(pod podmodel.ID) (policyIDs []policymodel.ID) {
	policyIDs = []policymodel.ID{}
	policyData := []*policymodel.Policy{}

	// Get and store the data from all the policies in cache.
	policies := pc.ListAllPolicies()
	for _, policy := range policies {
		found, data := pc.LookupPolicy(policy)
		if !found {
			continue
		}
		policyData = append(policyData, data)
	}

	// For every policy data if podID matches any of policy's attached pods
	// save and return the policyID
	for _, pData := range policyData {
		podIDs := pc.LookupPodsByLabelSelectorInsideNs(pData.Namespace, pData.Pods)
		for _, podID := range podIDs {
			if podID == pod {
				policyID := policymodel.GetID(pData)
				policyIDs = append(policyIDs, policyID)
			}
		}
	}

	return policyIDs
}

// ListAllPolicies returns IDs of all policies.
func (pc *PolicyCache) ListAllPolicies() (policyIDs []policymodel.ID) {
	allPolicies := pc.configuredPolicies.ListAll()
	policyIDs = utils.UnstringPolicyID(allPolicies)

	return policyIDs
}

// LookupNamespace returns data of a given namespace.
func (pc *PolicyCache) LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace) {
	found, data = pc.configuredNamespaces.LookupNamespace(namespace.String())

	if !found {
		return found, nil
	}

	return found, data
}

// ListAllNamespaces returns IDs of all known namespaces.
func (pc *PolicyCache) ListAllNamespaces() (namespaces []nsmodel.ID) {
	allNamespaces := pc.configuredNamespaces.ListAll()
	namespaces = utils.UnstringNamespaceID(allNamespaces)

	return namespaces
}
