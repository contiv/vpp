package contiv

import (
	"net"

	"github.com/contiv/vpp/plugins/contiv/containeridx"
)

// PodActionHook defines parameters and the return value of a callback triggered
// during an event associated with a pod.
type PodActionHook func(podNamespace string, podName string) error

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

	// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
	GetPodSubnet() *net.IPNet

	// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
	GetPodNetwork() *net.IPNet

	// GetContainerIndex exposes index of configured containers
	GetContainerIndex() containeridx.Reader

	// IsTCPstackDisabled returns true if the TCP stack is disabled and only VETHs/TAPs are configured
	IsTCPstackDisabled() bool

	// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
	InSTNMode() bool

	// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
	// with node IP before being sent out from the node.
	NatExternalTraffic() bool

	// CleanupIdleNATSessions returns true if cleanup of idle NAT sessions is enabled.
	CleanupIdleNATSessions() bool

	// GetTCPNATSessionTimeout returns NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on.
	GetTCPNATSessionTimeout() uint32

	// GetOtherNATSessionTimeout returns NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on.
	GetOtherNATSessionTimeout() uint32

	// GetServiceLocalEndpointWeight returns the load-balancing weight assigned to locally deployed service endpoints.
	GetServiceLocalEndpointWeight() uint8

	// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
	// between clients and services via VPP even if the source and destination are the same
	// IP addresses and would otherwise be routed locally.
	GetNatLoopbackIP() net.IP

	// GetNodeIP returns the IP+network address of this node.
	// With DHCP the node IP may get assigned later or change in the runtime, therefore it is preferred
	// to watch for node IP via WatchNodeIP().
	GetNodeIP() (ip net.IP, network *net.IPNet)

	// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
	GetHostIPs() []net.IP

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

	// GetDefaultInterface returns the name and the IP address of the interface
	// used by the default route to send packets out from VPP towards the default gateway.
	// If the default GW is not configured, the function returns zero values.
	GetDefaultInterface() (ifName string, ifAddress net.IP)

	// RegisterPodPreRemovalHook allows to register callback that will be run for each
	// pod immediately before its removal.
	RegisterPodPreRemovalHook(hook PodActionHook)
}
