package ipnet

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

/********************************* Plugin API *********************************/

// API defines methods provided by IPNet plugin for use by other plugins to query
// IPv4 network-related information.
// Apart from GetPodByIf, these methods should not be accessed from outside of the
// main event loop!
type API interface {
	// GetPodIfNames looks up logical interface names that correspond to the interfaces
	// associated with the given local pod name + namespace.
	GetPodIfNames(podNamespace string, podName string) (vppIfName, linuxIfName, loopIfName string, exists bool)

	// GetPodCustomIfNames looks up logical interface name that corresponds to the custom interface
	// with specified name and type associated with the given local pod name + namespace.
	GetPodCustomIfNames(podNamespace, podName, customIfName string) (ifName string, linuxIfName string, exists bool)

	// GetExternalIfName returns logical name that corresponds to the specified external interface name and VLAN ID.
	GetExternalIfName(extIfName string, vlan uint32) (ifName string)

	// GetPodByIf looks up name and namespace that is associated with logical interface name.
	// The method can be called from outside of the main event loop.
	GetPodByIf(ifname string) (podNamespace string, podName string, exists bool)

	// GetNodeIP returns the IP+network address of this node.
	GetNodeIP() (ip net.IP, network *net.IPNet)

	// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
	GetHostIPs() []net.IP

	// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
	// interconnecting VPP with the host stack.
	GetHostInterconnectIfName() string

	// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
	// Returns an empty string if VXLAN is not used (in no-overlay interconnect mode).
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

/*************************** Pod Custom Interface Update Event ***************************/

// PodCustomIfUpdate is triggered when pod custom interfaces configuration needs to be updated.
type PodCustomIfUpdate struct {
	PodID       podmodel.ID
	Labels      map[string]string
	Annotations map[string]string
}

// GetName returns name of the PodCustomIfUpdate event.
func (ev *PodCustomIfUpdate) GetName() string {
	return "Pod Custom Interfaces Update"
}

// String describes PodCustomIfUpdate event.
func (ev *PodCustomIfUpdate) String() string {
	return fmt.Sprintf("%s\n"+
		"* Pod ID: %s\n"+
		"* Pod Labels: %v\n"+
		"* pod Annotations: %v",
		ev.GetName(), ev.PodID.String(), ev.Labels, ev.Annotations)
}

// Method is Update.
func (ev *PodCustomIfUpdate) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is RevertOnFailure.
func (ev *PodCustomIfUpdate) TransactionType() controller.UpdateTransactionType {
	return controller.BestEffort
}

// Direction is forward.
func (ev *PodCustomIfUpdate) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns false.
func (ev *PodCustomIfUpdate) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *PodCustomIfUpdate) Done(error) {
	return
}
