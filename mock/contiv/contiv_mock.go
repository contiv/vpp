package contiv

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	podIfs map[podmodel.ID]string
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	return &MockContiv{podIfs: make(map[podmodel.ID]string)}
}

// SetPodIfName allows to create a fake association beetween a pod and an interface.
func (mc *MockContiv) SetPodIfName(pod podmodel.ID, ifName string) {
	mc.podIfs[pod] = ifName
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mc *MockContiv) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mc.podIfs[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
}
