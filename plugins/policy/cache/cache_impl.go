package cache

import (
	"strings"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	"github.com/contiv/vpp/plugins/policy/cache/namespaceidx"
	"github.com/contiv/vpp/plugins/policy/cache/podidx"
	"github.com/contiv/vpp/plugins/policy/cache/policyidx"
	"github.com/contiv/vpp/plugins/policy/cache/ruleidx"
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
	configuredRules      *ruleidx.ConfigIndex
	configuredNamespaces *namespaceidx.ConfigIndex
	watchers             []PolicyCacheWatcher
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log        logging.Logger
	PluginName core.PluginName
}

// Init initializes policy cache.
func (pc *PolicyCache) Init() error {
	pc.configuredPolicies = policyidx.NewConfigIndex(pc.Log, pc.PluginName, "policies")
	pc.configuredPods = podidx.NewConfigIndex(pc.Log, pc.PluginName, "pods")
	pc.configuredRules = ruleidx.NewConfigIndex(pc.Log, pc.PluginName, "rules")
	pc.configuredNamespaces = namespaceidx.NewConfigIndex(pc.Log, pc.PluginName, "namespaces")

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
	return false, nil
}

// LookupPodsByLabelSelector evaluates label selector (expression and/or match
// labels) and returns IDs of matching pods in a namespace.
func (pc *PolicyCache) LookupPodsByNSLabelSelector(policyNamespace string, podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	// todo - Always set a label for phase1, filter kube-system later
	// An empty podSelector matches all pods in this namespace.
	if podLabelSelector == nil {
		pods := pc.configuredPods.LookupPodsByNamespace(policyNamespace)
		return GetPodIDs(pods)
	}
	matchLabels := podLabelSelector.MatchLabel
	matchExpressions := podLabelSelector.MatchExpression
	//pc.Log.Infof("PolicyLabels: %+v, PolicyExpressions: %+v", matchLabels, matchExpressions)

	if len(matchLabels) > 0 && len(matchExpressions) == 0 {
		found, pods := pc.getPodsByNSLabelSelector(policyNamespace, matchLabels)
		if !found {
			return nil
		}
		return GetPodIDs(pods)
	} else if len(matchLabels) == 0 && len(matchExpressions) > 0 {
		found, pods := pc.getMatchExpressionPods(policyNamespace, matchExpressions)
		if !found {
			return nil
		}
		return GetPodIDs(pods)
	} else if len(matchLabels) > 0 && len(matchExpressions) > 0 {
		foundMlPods, mlPods := pc.getPodsByNSLabelSelector(policyNamespace, matchLabels)
		if !foundMlPods {
			return nil
		}
		foundMePods, mePods := pc.getMatchExpressionPods(policyNamespace, matchExpressions)
		if !foundMePods {
			return nil
		}
		pods := intersect(mlPods, mePods)
		if pods == nil {
			return nil
		}
		return GetPodIDs(pods)
	}

	return nil
}

// LookupPodsByLabelSelector evaluates label selector (expression and/or match
// labels) and returns IDs of matching pods.
func (pc *PolicyCache) LookupPodsByLabelSelector(podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	return nil
}

// LookupPodsByNamespace returns IDs of all pods inside a given namespace.
func (pc *PolicyCache) LookupPodsByNamespace(namespace nsmodel.ID) (pods []podmodel.ID) {
	return nil
}

// ListAllPods returns IDs of all known pods.
func (pc *PolicyCache) ListAllPods() (pods []podmodel.ID) {
	return nil
}

// LookupPolicy returns data of a given Policy.
func (pc *PolicyCache) LookupPolicy(policy podmodel.ID) (found bool, data *policymodel.Policy) {
	return false, nil
}

// LookupPoliciesByPod returns IDs of all policies assigned to a given pod.
func (pc *PolicyCache) LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID) {
	return nil
}

// ListAllPolicies returns IDs of all policies.
func (pc *PolicyCache) ListAllPolicies() (policies []policymodel.ID) {
	return nil
}

// LookupNamespace returns data of a given namespace.
func (pc *PolicyCache) LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace) {
	return false, nil
}

// LookupNamespacesByLabelSelector evaluates label selector (expression
// and/or match labels) and returns IDs of matching namespaces.
func (pc *PolicyCache) LookupNamespacesByLabelSelector(nsLabelSelector *policymodel.Policy_LabelSelector) (namespaces []nsmodel.ID) {
	return nil
}

// ListAllNamespaces returns IDs of all known namespaces.
func (pc *PolicyCache) ListAllNamespaces() (namespaces []nsmodel.ID) {
	return nil
}

func GetPodIDs(pods []string) []podmodel.ID {
	podIDs := []podmodel.ID{}
	for _, pod := range pods {
		parts := strings.Split(pod, "/")
		podID := podmodel.ID{
			Name:      parts[0],
			Namespace: parts[1],
		}
		podIDs = append(podIDs, podID)
	}
	return podIDs
}
