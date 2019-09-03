/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

package podmanager

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/podmanager"
)

// MockPodManager is a mock implementation of podmanager plugin.
type MockPodManager struct {
	localPods podmanager.LocalPods
	pods      podmanager.Pods
}

// NewMockPodManager is a constructor for MockPodManager.
func NewMockPodManager() *MockPodManager {
	return &MockPodManager{
		localPods: make(podmanager.LocalPods),
		pods:      make(podmanager.Pods),
	}
}

// GetPods returns mock data for all pods.
func (m *MockPodManager) GetPods() podmanager.Pods {
	return m.pods
}

// GetLocalPods returns mock data for all pods added via AddPod() method.
func (m *MockPodManager) GetLocalPods() podmanager.LocalPods {
	return m.localPods
}

// AddPod allows to simulate AddPod event.
func (m *MockPodManager) AddPod(pod *podmanager.LocalPod) *podmanager.AddPod {
	m.localPods[pod.ID] = pod
	return &podmanager.AddPod{
		Pod:              pod.ID,
		ContainerID:      pod.ContainerID,
		NetworkNamespace: pod.NetworkNamespace,
	}
}

// AddRemotePod adds remote pod in podmanager
func (m *MockPodManager) AddRemotePod(pod *podmanager.Pod) {
	m.pods[pod.ID] = pod
}

// DeletePod allows to simulate DeletePod event.
func (m *MockPodManager) DeletePod(podID podmodel.ID) *podmanager.DeletePod {
	delete(m.localPods, podID)
	return &podmanager.DeletePod{
		Pod: podID,
	}
}
