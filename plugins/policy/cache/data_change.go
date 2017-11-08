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

	"github.com/ligato/cn-infra/datasync"

	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// changePropagateEvent propagates CHANGE in the K8s configuration into the Cache.
func (pc *PolicyCache) changePropagateEvent(dataChngEv datasync.ChangeEvent) error {
	var err error
	var diff bool
	key := dataChngEv.GetKey()
	pc.Log.Debug("Received CHANGE key ", key)

	if strings.HasPrefix(key, namespacemodel.KeyPrefix()) {
		// Propagate Policy CHANGE event
		_, _, err = policymodel.ParsePolicyFromKey(key)
		if err == nil {
			var value, prevValue policymodel.Policy

			if err = dataChngEv.GetValue(&value); err != nil {
				return err
			}

			if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
				return err
			}

			if datasync.Delete == dataChngEv.GetChangeType() {
				oldPolicyID := policymodel.GetID(&prevValue).String()

				for _, watcher := range pc.watchers {
					if err := watcher.DelPolicy(&prevValue); err != nil {
						return err
					}
				}
				pc.configuredPolicies.UnregisterPolicy(oldPolicyID)

			} else if diff {
				policyID := policymodel.GetID(&value).String()
				oldPolicyID := policymodel.GetID(&prevValue).String()
				pc.configuredPolicies.RegisterPolicy(policyID, &value)

				for _, watcher := range pc.watchers {
					if err := watcher.UpdatePolicy(&prevValue, &value); err != nil {
						return err
					}
				}
				pc.configuredPolicies.UnregisterPolicy(oldPolicyID)

			}
			policyID := policymodel.GetID(&value).String()
			pc.configuredPolicies.RegisterPolicy(policyID, &value)

			for _, watcher := range pc.watchers {
				if err := watcher.AddPolicy(&value); err != nil {
					return err
				}
			}

			return nil
		}

		// Propagate Pod CHANGE event
		_, _, err = podmodel.ParsePodFromKey(key)
		if err == nil {
			var value, prevValue podmodel.Pod

			if err = dataChngEv.GetValue(&value); err != nil {
				return err
			}

			if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
				return err
			}

			if datasync.Delete == dataChngEv.GetChangeType() {
				oldPodID := podmodel.GetID(&prevValue).String()

				for _, watcher := range pc.watchers {
					if err := watcher.DelPod(&prevValue); err != nil {
						return err
					}
				}
				pc.configuredPods.UnregisterPod(oldPodID)

			} else if diff {
				podID := podmodel.GetID(&value).String()
				oldPodID := podmodel.GetID(&prevValue).String()
				pc.configuredPods.RegisterPod(podID, &value)

				for _, watcher := range pc.watchers {
					if err := watcher.UpdatePod(&prevValue, &value); err != nil {
						return err
					}
				}
				pc.configuredPods.UnregisterPod(oldPodID)

			}
			podID := podmodel.GetID(&value).String()
			pc.configuredPods.RegisterPod(podID, &value)

			for _, watcher := range pc.watchers {
				if err := watcher.AddPod(&value); err != nil {
					return err
				}
			}

			return nil

		}

		// Propagate Namespace CHANGE event
		var value, prevValue namespacemodel.Namespace

		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}

		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}

		if datasync.Delete == dataChngEv.GetChangeType() {
			oldNamespaceID := prevValue.Name

			for _, watcher := range pc.watchers {
				if err := watcher.DelNamespace(&prevValue); err != nil {
					return err
				}
			}
			pc.configuredNamespaces.UnRegisterNamespace(oldNamespaceID)

		} else if diff {
			namespaceID := value.Name
			oldNamespaceID := prevValue.Name
			pc.configuredNamespaces.RegisterNamespace(namespaceID, &value)

			for _, watcher := range pc.watchers {
				if err := watcher.UpdateNamespace(&prevValue, &value); err != nil {
					return err
				}
			}
			pc.configuredNamespaces.UnRegisterNamespace(oldNamespaceID)
		}

		namespaceID := value.Name
		pc.configuredNamespaces.RegisterNamespace(namespaceID, &value)

		for _, watcher := range pc.watchers {
			if err := watcher.AddNamespace(&value); err != nil {
				return err
			}

		}

		return nil

	}

	pc.Log.WithField("event", dataChngEv).Warn("Ignoring CHANGE event")
	return nil
}
