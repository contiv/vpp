package contiv

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

// PodActionHook defines parameters and the return value of a callback triggered
// during an event associated with a pod.
type PodActionHook func(podNamespace string, podName string, txn controller.UpdateOperations) error

// API for other plugins to query network-related information.
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
	GetPodByIf(ifname string) (podNamespace string, podName string, exists bool)

	// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
	GetPodSubnet() *net.IPNet

	// GetPodSubnetThisNode provides subnet used for allocating pod IP addresses on this host node.
	GetPodSubnetThisNode() *net.IPNet

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

	// DisableNATVirtualReassembly returns true if fragmented packets should be dropped by NAT.
	DisableNATVirtualReassembly() bool

	// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
	// between clients and services via VPP even if the source and destination are the same
	// IP addresses and would otherwise be routed locally.
	GetNatLoopbackIP() net.IP

	// GetNodeIP returns the IP+network address of this node.
	GetNodeIP() (ip net.IP, network *net.IPNet)

	// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
	GetHostIPs() []net.IP

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

	// RegisterPodPostAddHook allows to register callback that will be run for each
	// pod once it is added and before the CNI reply is sent.
	RegisterPodPostAddHook(hook PodActionHook)

	// GetMainVrfID returns the ID of the main network connectivity VRF.
	GetMainVrfID() uint32

	// GetPodVrfID returns the ID of the POD VRF.
	GetPodVrfID() uint32
}

// NodeIPv4Change is triggered when DHCP-assigned IPv4 address of the node changes.
type NodeIPv4Change struct {
	NewNodeIP    net.IP
	NewNodeIPNet *net.IPNet
}

// GetName returns name of the NodeIPv4Change event.
func (ev *NodeIPv4Change) GetName() string {
	return "Node IP(v4) Change"
}

// String describes NodeIPv4Change event.
func (ev *NodeIPv4Change) String() string {
	return fmt.Sprintf("%s\n"+
		"* new-IP: %s\n"+
		"* new-IP-net: %s", ev.GetName(), ev.NewNodeIP.String(), ev.NewNodeIPNet.String())
}

// Method is Resync.
func (ev *NodeIPv4Change) Method() controller.EventMethodType {
	return controller.Resync
}

// IsBlocking returns false.
func (ev *NodeIPv4Change) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *NodeIPv4Change) Done(error) {
	return
}
