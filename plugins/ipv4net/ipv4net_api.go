package ipv4net

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

/********************************* Plugin API *********************************/

// API defines methods provided by IPv4Net plugin for use by other plugins to query
// IPv4 network-related information.
// Apart from GetPodByIf, these methods should not be accessed from outside of the
// main event loop!
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
	// The method can be called from outside of the main event loop.
	GetPodByIf(ifname string) (podNamespace string, podName string, exists bool)

	// GetNodeIP returns the IP+network address of this node.
	GetNodeIP() (ip net.IP, network *net.IPNet)

	// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
	GetHostIPs() []net.IP

	// GetPodSubnetThisNode returns POD network for the current node
	// (given by nodeID allocated for this node).
	GetPodSubnetThisNode() *net.IPNet

	// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
	// interconnecting VPP with the host stack.
	GetHostInterconnectIfName() string

	// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
	// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
	GetVxlanBVIIfName() string
}

/*************************** Node IPv4 Change Event ***************************/

// NodeIPv4Change is triggered when DHCP-assigned IPv4 address of the node changes.
type NodeIPv4Change struct {
	NodeIP    net.IP
	NodeIPNet *net.IPNet
	DefaultGw net.IP
}

// GetName returns name of the NodeIPv4Change event.
func (ev *NodeIPv4Change) GetName() string {
	return "Node IP(v4) Change"
}

// String describes NodeIPv4Change event.
func (ev *NodeIPv4Change) String() string {
	return fmt.Sprintf("%s\n"+
		"* IP: %s\n"+
		"* IP-net: %s\n"+
		"* GW: %s",
		ev.GetName(), ev.NodeIP.String(), ev.NodeIPNet.String(), ev.DefaultGw.String())
}

// Method is UpstreamResync.
func (ev *NodeIPv4Change) Method() controller.EventMethodType {
	return controller.UpstreamResync
}

// IsBlocking returns false.
func (ev *NodeIPv4Change) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *NodeIPv4Change) Done(error) {
	return
}
