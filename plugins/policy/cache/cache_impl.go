/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

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
	Log        logging.Logger
	PluginName core.PluginName
}

// Init initializes policy cache.
func (pc *PolicyCache) Init() error {
	pc.configuredPolicies = policyidx.NewConfigIndex(pc.Log, pc.PluginName, "policies")
	pc.configuredPods = podidx.NewConfigIndex(pc.Log, pc.PluginName, "pods")
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
	found, data = pc.configuredPods.LookupPod(pod.String())

	if !found {
		return !found, nil
	}

	return found, data
}

// LookupPodsByNSLabelSelector evaluates label selector (expression and/or match
// labels) and returns IDs of matching pods in a namespace.
func (pc *PolicyCache) LookupPodsByNSLabelSelector(policyNamespace string,
	podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {

	// An empty podSelector matches all pods in this namespace.
	if podLabelSelector == nil {
		pods := pc.configuredPods.LookupPodsByNamespace(policyNamespace)
		return utils.UnstringPodID(pods)
	}

	// List of match labels and match expressions.
	matchLabels := podLabelSelector.MatchLabel
	matchExpressions := podLabelSelector.MatchExpression

	if len(matchLabels) > 0 && len(matchExpressions) == 0 {
		found, pods := pc.getPodsByNSLabelSelector(policyNamespace, matchLabels)
		if !found {
			return nil
		}
		return utils.UnstringPodID(pods)

	} else if len(matchLabels) == 0 && len(matchExpressions) > 0 {
		found, pods := pc.getMatchExpressionPods(policyNamespace, matchExpressions)
		if !found {
			return nil
		}
		return utils.UnstringPodID(pods)

	} else if len(matchLabels) > 0 && len(matchExpressions) > 0 {
		foundMlPods, mlPods := pc.getPodsByNSLabelSelector(policyNamespace, matchLabels)
		if !foundMlPods {
			return nil
		}

		foundMePods, mePods := pc.getMatchExpressionPods(policyNamespace, matchExpressions)
		if !foundMePods {
			return nil
		}

		pods := utils.Intersect(mlPods, mePods)
		if pods == nil {
			return nil
		}

		return utils.UnstringPodID(pods)
	}

	return nil
}

// LookupPodsByLabelSelector evaluates label selector (expression and/or match
// labels) and returns IDs of matching pods.
func (pc *PolicyCache) LookupPodsByLabelSelector(
	podLabelSelector *policymodel.Policy_LabelSelector) (pods []podmodel.ID) {
	return nil
}

// LookupPodsByNamespace returns IDs of all pods inside a given namespace.
func (pc *PolicyCache) LookupPodsByNamespace(namespace nsmodel.ID) (pods []podmodel.ID) {
	podsByNamespace := pc.configuredPods.LookupPodsByNamespace(namespace.String())
	pods = utils.UnstringPodID(podsByNamespace)

	return pods
}

// ListAllPods returns IDs of all known pods.
func (pc *PolicyCache) ListAllPods() (pods []podmodel.ID) {
	allPods := pc.configuredPods.ListAll()
	pods = utils.UnstringPodID(allPods)

	return pods
}

// LookupPolicy returns data of a given Policy.
func (pc *PolicyCache) LookupPolicy(policy policymodel.ID) (found bool, data *policymodel.Policy) {
	found, data = pc.configuredPolicies.LookupPolicy(policy.String())
	if !found {
		return !found, nil
	}
	return found, data
}

// LookupPoliciesByPod returns IDs of all policies assigned to a given pod.
func (pc *PolicyCache) LookupPoliciesByPod(pod podmodel.ID) (policies []policymodel.ID) {
	policies = []policymodel.ID{}
	policyMap := make(map[string]*policymodel.Policy)

	found, podData := pc.configuredPods.LookupPod(pod.String())
	if !found {
		return nil
	}

	podLabels := podData.Label

	for _, podLabel := range podLabels {
		nsLabel := podData.Namespace + "/" + podLabel.Key + "/" + podLabel.Value
		policyIDs := pc.configuredPolicies.LookupPolicyByNSLabelSelector(nsLabel)

		for _, policyID := range policyIDs {
			found, policyData := pc.configuredPolicies.LookupPolicy(policyID)
			if found {
				policyMap[policyID] = policyData
			}
		}
	}

	for k, v := range policyMap {
		podByNS := pc.LookupPodsByNSLabelSelector(v.Namespace, v.Pods)
		for _, podID := range podByNS {
			if podID == pod {
				parts := strings.Split(k, "/")
				policyID := policymodel.ID{
					Name:      parts[1],
					Namespace: parts[0],
				}
				policies = append(policies, policyID)
			}
		}
	}

	return policies
}

// ListAllPolicies returns IDs of all policies.
func (pc *PolicyCache) ListAllPolicies() (policies []policymodel.ID) {
	allPolicies := pc.configuredPolicies.ListAll()
	policies = utils.UnstringPolicyID(allPolicies)

	return policies
}

// LookupNamespace returns data of a given namespace.
func (pc *PolicyCache) LookupNamespace(namespace nsmodel.ID) (found bool, data *nsmodel.Namespace) {
	found, data = pc.configuredNamespaces.LookupNamespace(namespace.String())

	if !found {
		return !found, nil
	}

	return found, data
}

// LookupNamespacesByLabelSelector evaluates label selector (expression
// and/or match labels) and returns IDs of matching namespaces.
func (pc *PolicyCache) LookupNamespacesByLabelSelector(
	nsLabelSelector *policymodel.Policy_LabelSelector) (namespaces []nsmodel.ID) {
	return nil
}

// ListAllNamespaces returns IDs of all known namespaces.
func (pc *PolicyCache) ListAllNamespaces() (namespaces []nsmodel.ID) {
	allNamespaces := pc.configuredNamespaces.ListAll()
	namespaces = utils.UnstringNamespaceID(allNamespaces)

	return namespaces
}
