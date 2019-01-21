package bgpreflector

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
}

/*************************** Node IPv4 Change Event ***************************/

// BGPRouteChange is triggered when DHCP-assigned IPv4 address of the node changes.
type BGPRouteChange struct {
	NodeIP    net.IP
	NodeIPNet *net.IPNet
	DefaultGw net.IP
}

// GetName returns name of the BGPRouteChange event.
func (ev *BGPRouteChange) GetName() string {
	return "BGP route Change"
}

// String describes BGPRouteChange event.
func (ev *BGPRouteChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* IP: %s\n"+
		"* IP-net: %s\n"+
		"* GW: %s",
		ev.GetName(), ev.NodeIP.String(), ev.NodeIPNet.String(), ev.DefaultGw.String())
}

// Method is UpstreamResync.
func (ev *BGPRouteChange) Method() controller.EventMethodType {
	return controller.Update
}

// IsBlocking returns false.
func (ev *BGPRouteChange) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *BGPRouteChange) Done(error) {
	return
}
