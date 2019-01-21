package externalipam

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

// NodeIPv4Change is triggered when DHCP-assigned IPv4 address of the node changes.
type PodCIDRChange struct {
	PodNetworkCIDR *net.IPNet
	LocalPodCIDR   *net.IPNet
	Gateway        net.IP
}

// GetName returns name of the NodeIPv4Change event.
func (ev *PodCIDRChange) GetName() string {
	return "Pod CIDR Change"
}

// String describes NodeIPv4Change event.
func (ev *PodCIDRChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* PodNetworkCIDR: %v\n"+
		"* LocalPodCIDR: %v\n"+
		"* Gateway: %v",
		ev.GetName(), ev.PodNetworkCIDR, ev.LocalPodCIDR, ev.Gateway)
}

// Method is UpstreamResync.
func (ev *PodCIDRChange) Method() controller.EventMethodType {
	return controller.UpstreamResync
}

// IsBlocking returns false.
func (ev *PodCIDRChange) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *PodCIDRChange) Done(error) {
	return
}
