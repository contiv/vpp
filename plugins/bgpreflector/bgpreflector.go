// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bgpreflector

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/vishvananda/netlink"
)

const (
	// protocol number for routes installed by bird
	// from /etc/iproute2/rt_protos
	birdRouteProtoNumber = 12
)

// BGPReflector plugin implements BGP route reflection from Linux host to VPP.
type BGPReflector struct {
	Deps
}

// Deps lists dependencies of the BGPReflector plugin.
type Deps struct {
	infra.PluginDeps
	ContivConf contivconf.API
	EventLoop  controller.EventLoop
}

// Init is NOOP - the plugin is initialized during the first resync.
func (br *BGPReflector) Init() (err error) {
	return nil
}

// HandlesEvent selects:
//   - any Resync event
//   - BGPRouteUpdate
func (br *BGPReflector) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if _, isBGPRouteChange := event.(*BGPRouteUpdate); isBGPRouteChange {
		return true
	}

	// unhandled event
	return false
}

// Resync resynchronizes BGPReflector against the BGP routes in the Linux host.
// A set of already allocated pod IPs is updated.
func (br *BGPReflector) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	// return any error as fatal
	defer func() {
		if err != nil {
			err = controller.NewFatalError(err)
		}
	}()

	if resyncCount == 1 {
		// initialize route watcher
		err := br.watchRoutes()
		if err != nil {
			br.Log.Error(err)
			return err
		}
	}

	// dump routes
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		err := fmt.Errorf("error by listing BGP routes: %v", err)
		br.Log.Error(err)
		return err
	}

	// reflect bird routes
	for _, r := range routes {
		if r.Protocol == birdRouteProtoNumber && isValidRoute(r.Dst, r.Gw) {
			key, route := br.vppRoute(r.Dst, r.Gw)
			txn.Put(key, route)
		}
	}

	return
}

// Update handles BGPRouteUpdate events.
func (br *BGPReflector) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {

	if bgpRouteUpdate, isBGPRouteUpdate := event.(*BGPRouteUpdate); isBGPRouteUpdate {
		br.Log.Debugf("BGP route update: %v", bgpRouteUpdate)

		key, route := br.vppRoute(bgpRouteUpdate.DstNetwork, bgpRouteUpdate.GwAddr)
		if bgpRouteUpdate.Type == RouteAdd {
			txn.Put(key, route)
			changeDescription = "BGP route Add"
		} else {
			txn.Delete(key)
			changeDescription = "BGP route Delete"
		}
	}
	return
}

// Revert is NOOP - never called.
func (br *BGPReflector) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP.
func (br *BGPReflector) Close() error {
	return nil
}

// watchRoutes watches routing table for BGP routes and generates BGPRouteUpdate events upon each BGP route change.
func (br *BGPReflector) watchRoutes() error {
	ch := make(chan netlink.RouteUpdate)
	done := make(chan struct{})

	//defer close(done) // TODO handle nice close
	if err := netlink.RouteSubscribe(ch, done); err != nil {
		return fmt.Errorf("unable to subscribe the route watcher")
	}

	go func() {
		for {
			select {
			case r := <-ch:
				if r.Protocol == birdRouteProtoNumber && isValidRoute(r.Dst, r.Gw) {
					br.Log.Debugf("BGP route update: proto=%d %v", r.Protocol, r)
					ev := &BGPRouteUpdate{
						DstNetwork: r.Dst,
						GwAddr:     r.Gw,
					}
					if r.Type == unix.RTM_NEWROUTE {
						br.Log.Debugf("New BGP route: %v", r)
						ev.Type = RouteAdd

					}
					if r.Type == unix.RTM_DELROUTE {
						br.Log.Debugf("Deleted BGP route: %v", r)
						ev.Type = RouteDelete
					}
					br.EventLoop.PushEvent(ev)
				}
			}
		}
	}()

	return nil
}

// vppRoute returns VPP route from given destination network and gateway IP.
func (br *BGPReflector) vppRoute(dst *net.IPNet, gw net.IP) (key string, config *vpp_l3.Route) {
	route := &vpp_l3.Route{
		DstNetwork:        dst.String(),
		NextHopAddr:       gw.String(),
		OutgoingInterface: br.ContivConf.GetMainInterfaceName(),
		VrfId:             br.ContivConf.GetRoutingConfig().MainVRFID,
	}
	key = vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	return key, route
}

// isValidRoute returns true if the route is valid and should be reflected, false otherwise.
func isValidRoute(dst *net.IPNet, gw net.IP) bool {
	if dst == nil || gw == nil {
		return false
	}
	if gw.IsUnspecified() {
		return false
	}
	return true
}
