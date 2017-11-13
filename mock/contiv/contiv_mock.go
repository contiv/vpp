package contiv

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	podIf map[podmodel.ID]string
	podNs map[podmodel.ID]int
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	return &MockContiv{
		podIf: make(map[podmodel.ID]string),
		podNs: make(map[podmodel.ID]int),
	}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mc *MockContiv) SetPodIfName(pod podmodel.ID, ifName string) {
	mc.podIf[pod] = ifName
}

// SetPodNsIndex allows to create a fake association between a pod and a VPP
// session namespace.
func (mc *MockContiv) SetPodNsIndex(pod podmodel.ID, nsIndex int) {
	mc.podNs[pod] = nsIndex
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mc *MockContiv) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mc.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
}

// GetNsIndex returns pod's namespace index as set previously using SetPodNsIndex.
func (mc *MockContiv) GetNsIndex(podNamespace string, podName string) (nsIndex int, exists bool) {
	nsIndex, exists = mc.podNs[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return nsIndex, exists
}
