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
	controller "github.com/contiv/vpp/plugins/controller/api"
	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// changePropagateEvent propagates CHANGE in the K8s configuration into the Cache.
func (pc *PolicyCache) changePropagateEvent(kubeStateChange *controller.KubeStateChange) error {
	switch kubeStateChange.Resource {
	case namespacemodel.NamespaceKeyword:
		if kubeStateChange.PrevValue == nil {
			// add namespace
			namespace := kubeStateChange.NewValue.(*namespacemodel.Namespace)
			namespaceID := namespace.Name
			pc.configuredNamespaces.RegisterNamespace(namespaceID, namespace)

			for _, watcher := range pc.watchers {
				if err := watcher.AddNamespace(namespace); err != nil {
					return err
				}
			}
		} else if kubeStateChange.NewValue == nil {
			// delete namespace
			oldNamespace := kubeStateChange.PrevValue.(*namespacemodel.Namespace)
			oldNamespaceID := oldNamespace.Name
			pc.configuredNamespaces.UnRegisterNamespace(oldNamespaceID)

			for _, watcher := range pc.watchers {
				if err := watcher.DelNamespace(oldNamespace); err != nil {
					return err
				}
			}
		} else {
			// update namespace
			oldNamespace := kubeStateChange.PrevValue.(*namespacemodel.Namespace)
			newNamespace := kubeStateChange.NewValue.(*namespacemodel.Namespace)
			namespaceID := newNamespace.Name
			oldNamespaceID := oldNamespace.Name
			pc.configuredNamespaces.UnRegisterNamespace(oldNamespaceID)
			pc.configuredNamespaces.RegisterNamespace(namespaceID, newNamespace)

			for _, watcher := range pc.watchers {
				if err := watcher.UpdateNamespace(oldNamespace, newNamespace); err != nil {
					return err
				}
			}
		}

	case podmodel.PodKeyword:
		if kubeStateChange.PrevValue == nil {
			// add pod
			pod := kubeStateChange.NewValue.(*podmodel.Pod)
			podID := podmodel.GetID(pod)
			pc.configuredPods.RegisterPod(podID.String(), pod)

			for _, watcher := range pc.watchers {
				if err := watcher.AddPod(podID, pod); err != nil {
					return err
				}
			}
		} else if kubeStateChange.NewValue == nil {
			// delete pod
			oldPod := kubeStateChange.PrevValue.(*podmodel.Pod)
			oldPodID := podmodel.GetID(oldPod)
			pc.configuredPods.UnregisterPod(oldPodID.String())

			for _, watcher := range pc.watchers {
				if err := watcher.DelPod(oldPodID, oldPod); err != nil {
					return err
				}
			}
		} else {
			// update pod
			oldPod := kubeStateChange.PrevValue.(*podmodel.Pod)
			newPod := kubeStateChange.NewValue.(*podmodel.Pod)
			podID := podmodel.GetID(newPod)
			oldPodID := podmodel.GetID(oldPod)
			pc.configuredPods.UnregisterPod(oldPodID.String())
			pc.configuredPods.RegisterPod(podID.String(), newPod)

			for _, watcher := range pc.watchers {
				if err := watcher.UpdatePod(podID, oldPod, newPod); err != nil {
					return err
				}
			}
		}

	case policymodel.PolicyKeyword:
		if kubeStateChange.PrevValue == nil {
			// add policy
			policy := kubeStateChange.NewValue.(*policymodel.Policy)
			policyID := policymodel.GetID(policy)
			pc.configuredPolicies.RegisterPolicy(policyID.String(), policy)

			for _, watcher := range pc.watchers {
				if err := watcher.AddPolicy(policy); err != nil {
					return err
				}
			}
		} else if kubeStateChange.NewValue == nil {
			// delete policy
			oldPolicy := kubeStateChange.PrevValue.(*policymodel.Policy)
			oldPolicyID := policymodel.GetID(oldPolicy)
			pc.configuredPolicies.UnregisterPolicy(oldPolicyID.String())

			for _, watcher := range pc.watchers {
				if err := watcher.DelPolicy(oldPolicy); err != nil {
					return err
				}
			}
		} else {
			// update policy
			oldPolicy := kubeStateChange.PrevValue.(*policymodel.Policy)
			newPolicy := kubeStateChange.NewValue.(*policymodel.Policy)
			policyID := policymodel.GetID(newPolicy)
			oldPolicyID := policymodel.GetID(oldPolicy)
			pc.configuredPolicies.UnregisterPolicy(oldPolicyID.String())
			pc.configuredPolicies.RegisterPolicy(policyID.String(), newPolicy)

			for _, watcher := range pc.watchers {
				if err := watcher.UpdatePolicy(oldPolicy, newPolicy); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
