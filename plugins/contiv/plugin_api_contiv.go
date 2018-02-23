package contiv

import (
	"net"

	"github.com/contiv/vpp/plugins/contiv/containeridx"
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

	// GetPodByAppNsIndex looks up podName and podNamespace that is associated with the VPP application namespace.
	GetPodByAppNsIndex(nsIndex uint32) (podNamespace string, podName string, exists bool)

	// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
	GetPodNetwork() *net.IPNet

	// GetContainerIndex exposes index of configured containers
	GetContainerIndex() containeridx.Reader

	// IsTCPstackDisabled returns true if the TCP stack is disabled and only VETHSs/TAPs are configured
	IsTCPstackDisabled() bool

	// GetNodeIP returns the IP+network address of this node.
	// With DHCP the node IP may get assigned later or change in the runtime, therefore it is preferred
	// to watch for node IP via WatchNodeIP().
	GetNodeIP() (ip net.IP, network *net.IPNet)

	// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
	// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
	WatchNodeIP(subscriber chan string)

	// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
	// the node with the rest of the cluster.
	GetMainPhysicalIfName() string

	// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
	// to the main interface.
	GetOtherPhysicalIfNames() []string

	// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
	// interconnecting VPP with the host stack.
	GetHostInterconnectIfName() string

	// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
	// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
	GetVxlanBVIIfName() string

	// GetDefaultGatewayIP returns the IP address of the default gateway for external traffic.
	// If the default GW is not configured, the function returns nil.
	GetDefaultGatewayIP() net.IP
}
