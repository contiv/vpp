package contiv

import (
	"net"

	"github.com/contiv/vpp/plugins/contiv/containeridx"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/logging/logrus"
)

// MockContiv is a mock for the Contiv Plugin.
type MockContiv struct {
	podIf            map[podmodel.ID]string
	podNs            map[podmodel.ID]uint32
	podNetwork       *net.IPNet
	tcpStackDisabled bool
	nodeIP           net.IP
	physicalIfs      []string
	hostInterconnect string
	vxlanBVIIfName   string
	gwIP             net.IP
	containerIndex   *containeridx.ConfigIndex
}

// NewMockContiv is a constructor for MockContiv.
func NewMockContiv() *MockContiv {
	ci := containeridx.NewConfigIndex(logrus.DefaultLogger(), "test", "title")
	return &MockContiv{
		podIf:          make(map[podmodel.ID]string),
		podNs:          make(map[podmodel.ID]uint32),
		containerIndex: ci,
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

// SetContainerIndex allows to set index that contains configured containers
func (mc *MockContiv) SetContainerIndex(ci *containeridx.ConfigIndex) {
	mc.containerIndex = ci
}

// SetTCPStackDisabled allows to set flag denoting if the tcpStack is disabled or not.
func (mc *MockContiv) SetTCPStackDisabled(tcpStackDisabled bool) {
	mc.tcpStackDisabled = tcpStackDisabled
}

// SetNodeIP allows to set what tests will assume the node IP is.
func (mc *MockContiv) SetNodeIP(nodeIP net.IP) {
	mc.nodeIP = nodeIP
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

// SetDefaultGatewayIP allows to set what tests will assume the default gateway IP is (can be nil).
func (mc *MockContiv) SetDefaultGatewayIP(gwIP net.IP) {
	mc.gwIP = gwIP
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

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (mc *MockContiv) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	return "", "", false
}

// GetContainerIndex returns the index of configured containers/pods
func (mc *MockContiv) GetContainerIndex() containeridx.Reader {
	return mc.containerIndex
}

// GetPodNetwork returns static subnet constant that should represent pod subnet for current host node
func (mc *MockContiv) GetPodNetwork() (podNetwork *net.IPNet) {
	return mc.podNetwork
}

// IsTCPstackDisabled returns true if the tcp stack is disabled and only veths are configured
func (mc *MockContiv) IsTCPstackDisabled() bool {
	return mc.tcpStackDisabled
}

// GetNodeIP returns the IP address of this node.
func (mc *MockContiv) GetNodeIP() net.IP {
	return mc.nodeIP
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

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (mc *MockContiv) GetVxlanBVIIfName() string {
	return mc.vxlanBVIIfName
}

// GetDefaultGatewayIP returns the IP address of the default gateway for external traffic.
// If the default GW is not configured, the function returns nil.
func (mc *MockContiv) GetDefaultGatewayIP() net.IP {
	return mc.gwIP
}