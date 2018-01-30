package contiv

import (
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"net"
)

// API for other plugins to query network-related information.
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetNsIndex returns the index of the VPP session namespace associated
	// with the given pod.
	GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool)

	// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
	GetPodByIf(ifname string) (podNamespace string, podName string, exists bool)

	// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
	GetPodNetwork() *net.IPNet

	// GetContainerIndex exposes index of configured containers
	GetContainerIndex() containeridx.Reader

	// IsTCPstackDisabled returns true if the TCP stack is disabled and only VETHSs/TAPs are configured
	IsTCPstackDisabled() bool

	// GetNodeIP returns the IP address of this node.
	GetNodeIP() net.IP

	// GetPhysicalIfNames returns a slice of names of all configured physical interfaces.
	GetPhysicalIfNames() []string

	// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
	// interconnecting VPP with the host stack.
	GetHostInterconnectIfName() string

	// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
	// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
	GetVxlanBVIIfName() string
}
