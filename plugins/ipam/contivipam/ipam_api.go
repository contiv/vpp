package contivipam

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

// PodCIDRChange is triggered when CIDR for PODs on the current node changes.
type PodCIDRChange struct {
	LocalPodCIDR *net.IPNet
}

// GetName returns name of the PodCIDRChange event.
func (ev *PodCIDRChange) GetName() string {
	return "Pod CIDR Change"
}

// String describes PodCIDRChange event.
func (ev *PodCIDRChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* LocalPodCIDR: %v\n"+
		ev.GetName(), ev.LocalPodCIDR)
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
