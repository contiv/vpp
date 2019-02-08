package bgpreflector

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

/*************************** BGP Route Update Event ***************************/

// BGPRouteUpdateType represents type of the BGP update.
type BGPRouteUpdateType int

const (
	// RouteAdd represents addition of a new BGP route.
	RouteAdd BGPRouteUpdateType = iota
	// RouteDelete represents deletion of a BGP route.
	RouteDelete
)

func (t BGPRouteUpdateType) String() string {
	switch t {
	case RouteAdd:
		return "RouteAdd"
	case RouteDelete:
		return "RouteDelete"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}

// BGPRouteUpdate is triggered when a BGP route on the host changes.
type BGPRouteUpdate struct {
	Type       BGPRouteUpdateType
	DstNetwork *net.IPNet
	GwAddr     net.IP
}

// GetName returns name of the BGPRouteUpdate event.
func (ev *BGPRouteUpdate) GetName() string {
	return "BGP route Change"
}

// String describes BGPRouteUpdate event.
func (ev *BGPRouteUpdate) String() string {
	return fmt.Sprintf("%s\n"+
		"* Type: %s\n"+
		"* DstNetwork: %s\n"+
		"* GW: %s",
		ev.GetName(), ev.Type.String(), ev.DstNetwork.String(), ev.GwAddr.String())
}

// Method is Update.
func (ev *BGPRouteUpdate) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is BestEffort.
func (ev *BGPRouteUpdate) TransactionType() controller.UpdateTransactionType {
	return controller.BestEffort
}

// Direction is Forward.
func (ev *BGPRouteUpdate) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns false.
func (ev *BGPRouteUpdate) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *BGPRouteUpdate) Done(error) {
	return
}
