// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dockerclient

import (
	"github.com/fsouza/go-dockerclient"

	"errors"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	// labels attached to (not only sandbox) container to identify the pod it belongs to
	k8sLabelForPodName      = "io.kubernetes.pod.name"
	k8sLabelForPodNamespace = "io.kubernetes.pod.namespace"
)

// MockDockerClient is a mock for Docker client.
type MockDockerClient struct {
	connected      bool
	podByID        map[pod.ID]podContainer
	podByContainer map[string]podContainer
}

// podContainer groups all parameters of a single pod that the Docker client is used
// to retrieve.
type podContainer struct {
	podID       pod.ID
	containerID string
	pid         int
}

// NewMockDockerClient is a constructor for MockDockerClient.
func NewMockDockerClient() *MockDockerClient {
	return &MockDockerClient{
		podByID:        make(map[pod.ID]podContainer),
		podByContainer: make(map[string]podContainer),
	}
}

// Connect puts the mock Docker client into the connected state.
func (m *MockDockerClient) Connect() {
	m.connected = true
}

// Disconnect puts the mock Docker client into the disconnected state.
func (m *MockDockerClient) Disconnect() {
	m.connected = false
}

// AddPod simulates creation of a pod.
func (m *MockDockerClient) AddPod(podID pod.ID, container string, pid int) {
	podContainer := podContainer{
		podID:       podID,
		containerID: container,
		pid:         pid,
	}
	m.podByID[podID] = podContainer
	m.podByContainer[container] = podContainer
}

// DelPod simulates removal of a pod.
func (m *MockDockerClient) DelPod(podID pod.ID) {
	podContainer, exists := m.podByID[podID]
	if exists {
		delete(m.podByID, podID)
		delete(m.podByContainer, podContainer.containerID)
	}
}

// Ping pings the docker server.
func (m *MockDockerClient) Ping() error {
	if !m.connected {
		return errors.New("docker client is not connected")
	}
	return nil
}

// ListContainers returns a slice of containers matching the given criteria.
func (m *MockDockerClient) ListContainers(opts docker.ListContainersOptions) (containers []docker.APIContainers, err error) {
	err = m.Ping()
	if err != nil {
		return containers, err
	}

	for _, container := range m.podByID {
		containers = append(containers, docker.APIContainers{
			ID: container.containerID,
			Labels: map[string]string{
				k8sLabelForPodName:      container.podID.Name,
				k8sLabelForPodNamespace: container.podID.Namespace,
			},
		})
	}

	return containers, nil
}

// InspectContainer returns information about a container by its ID.
func (m *MockDockerClient) InspectContainer(id string) (*docker.Container, error) {
	container := &docker.Container{}

	err := m.Ping()
	if err != nil {
		return container, err
	}

	podContainer, exists := m.podByContainer[id]
	if !exists {
		return container, errors.New("no such container")
	}

	container.ID = id
	container.State = docker.State{Pid: podContainer.pid}
	return container, nil
}
