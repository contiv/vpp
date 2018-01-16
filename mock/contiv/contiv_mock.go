package contiv

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	podIf            map[podmodel.ID]string
	podNs            map[podmodel.ID]uint32
	podNetwork       *net.IPNet
	tcpStackDisabled bool
	hostIPNetwork    *net.IPNet
	physicalIfs      []string
	hostInterconnect string
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	return &MockContiv{
		podIf: make(map[podmodel.ID]string),
		podNs: make(map[podmodel.ID]uint32),
	}
}

// SetPodIfName allows to create a fake association between a pod and an interface.
func (mc *MockContiv) SetPodIfName(pod podmodel.ID, ifName string) {
	mc.podIf[pod] = ifName
}

// SetPodNsIndex allows to create a fake association between a pod and a VPP
// session namespace.
func (mc *MockContiv) SetPodNsIndex(pod podmodel.ID, nsIndex uint32) {
	mc.podNs[pod] = nsIndex
}

// SetPodNetwork allows to set what tests will assume as the pod subnet
// for the current host node.
func (mc *MockContiv) SetPodNetwork(podNetwork string) {
	_, mc.podNetwork, _ = net.ParseCIDR(podNetwork)
}

// SetTCPStackDisabled allows to set flag denoting if the tcpStack is disabled or not.
func (mc *MockContiv) SetTCPStackDisabled(tcpStackDisabled bool) {
	mc.tcpStackDisabled = tcpStackDisabled
}

// SetHostIPNetwork allows to set what tests will assume the host IP is.
func (mc *MockContiv) SetHostIPNetwork(hostIPNet *net.IPNet) {
	mc.hostIPNetwork = hostIPNet
}

// SetPhysicalIfNames allows to set what tests will assume the list of physical interface names is.
func (mc *MockContiv) SetPhysicalIfNames(ifs []string) {
	mc.physicalIfs = ifs
}

// SetHostInterconnectIfName allows to set what tests will assume the name of the host-interconnect
// interface is.
func (mc *MockContiv) SetHostInterconnectIfName(ifName string) {
	mc.hostInterconnect = ifName
}

// GetIfName returns pod's interface name as set previously using SetPodIfName.
func (mc *MockContiv) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	name, exists = mc.podIf[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return name, exists
}

// GetNsIndex returns pod's namespace index as set previously using SetPodNsIndex.
func (mc *MockContiv) GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool) {
	nsIndex, exists = mc.podNs[podmodel.ID{Name: podName, Namespace: podNamespace}]
	return nsIndex, exists
}

// GetPodNetwork returns static subnet constant that should represent pod subnet for current host node
func (mc *MockContiv) GetPodNetwork() (podNetwork *net.IPNet) {
	return mc.podNetwork
}

// IsTCPstackDisabled returns true if the tcp stack is disabled and only veths are configured
func (mc *MockContiv) IsTCPstackDisabled() bool {
	return mc.tcpStackDisabled
}

// GetHostIPNetwork returns single-host subnet with the IP address of this node.
func (mc *MockContiv) GetHostIPNetwork() *net.IPNet {
	return mc.hostIPNetwork
}

// GetPhysicalIfNames returns a slice of names of all configured physical interfaces.
func (mc *MockContiv) GetPhysicalIfNames() []string {
	return mc.physicalIfs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (mc *MockContiv) GetHostInterconnectIfName() string {
	return mc.hostInterconnect
}
