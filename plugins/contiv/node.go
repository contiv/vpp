// Copyright (c) 2017 Cisco and/or its affiliates.
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

package contiv

import (
	"context"
	"fmt"
	"strings"

	"github.com/contiv/vpp/plugins/contiv/bin_api/session"
	"github.com/contiv/vpp/plugins/contiv/model/uid"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	"net"
)

// handleNodeEvents adjust VPP route configuration according to the node changes.
func (s *remoteCNIserver) handleNodeEvents(ctx context.Context, resyncChan chan datasync.ResyncEvent, changeChan chan datasync.ChangeEvent) {
	for {
		select {
		case resyncEv := <-resyncChan:

			err := s.nodeResync(resyncEv)
			resyncEv.Done(err)
		case changeEv := <-changeChan:
			err := s.nodeChangePropageteEvent(changeEv)
			changeEv.Done(err)
		case <-ctx.Done():
			return
		}
	}
}

func (s *remoteCNIserver) nodeChangePropageteEvent(dataChngEv datasync.ChangeEvent) error {
	var err error
	key := dataChngEv.GetKey()

	if strings.HasPrefix(key, allocatedIDsKeyPrefix) {
		nodeID := &uid.Identifier{}
		err = dataChngEv.GetValue(nodeID)
		if err != nil {
			return err
		}
		hostID := uint8(nodeID.Id) //idAllocator.getID() trims it to uint8

		// route := s.getRouteToNode(conf, nodeID.Id)
		if dataChngEv.GetChangeType() == datasync.Put { // Addition of host routes
			podsRoute, hostRoute, err := s.computeRoutesForHost(hostID)
			if err != nil {
				return err
			}
			if err = s.vppTxnFactory().Put().StaticRoute(podsRoute).StaticRoute(hostRoute).Send().ReceiveReply(); err != nil {
				return fmt.Errorf("Can't configure vpp to add route to host %v (and its pods): %v ", hostID, err)
			}
		} else { //Delete of host routes
			podsRoute, hostRoute, err := s.computeRoutesForHost(hostID)
			if err != nil {
				return err
			}
			_, podDest, err := net.ParseCIDR(podsRoute.DstIpAddr)
			if err != nil {
				return err
			}
			_, hostDest, err := net.ParseCIDR(hostRoute.DstIpAddr)
			if err != nil {
				return err
			}

			err = s.vppTxnFactory().Delete().
				StaticRoute(podsRoute.VrfId, podDest, net.ParseIP(podsRoute.NextHopAddr)).
				StaticRoute(hostRoute.VrfId, hostDest, net.ParseIP(hostRoute.NextHopAddr)).
				Send().ReceiveReply()
			if err != nil {
				return fmt.Errorf("Can't configure vpp to remove route to host %v (and its pods): %v ", hostID, err)
			}
		}
	} else {
		return fmt.Errorf("Unknown key %v", key)
	}
	return err
}

func (s *remoteCNIserver) computeRoutesForHost(hostID uint8) (podsRoute *l3.StaticRoutes_Route, hostRoute *l3.StaticRoutes_Route, err error) {
	podsRoute, err = s.routeToOtherHostPods(hostID)
	if err != nil {
		err = fmt.Errorf("Can't construct route to pods of host %v: %v ", hostID, err)
		return
	}
	hostRoute, err = s.routeToOtherHostStack(hostID)
	if err != nil {
		err = fmt.Errorf("Can't construct route to host %v: %v ", hostID, err)
		return
	}
	return
}

func (s *remoteCNIserver) nodeResync(dataResyncEv datasync.ResyncEvent) error {
	// TODO: implement proper resync (handle deleted routes as well)
	var err error
	txn := s.vppTxnFactory().Put()
	data := dataResyncEv.GetValues()
	for prefix, it := range data {
		if prefix == allocatedIDsKeyPrefix {
			for {
				kv, stop := it.GetNext()
				if stop {
					break
				}
				nodeID := &uid.Identifier{}
				err = kv.GetValue(nodeID)
				if err != nil {
					return err
				}
				// route := s.getRouteToNode(conf, nodeID.Id)
				// txn.StaticRoute(route)
			}
		}
	}

	return txn.Send().ReceiveReply()
}

func (s *remoteCNIserver) enableTCPSession() error {
	req := &session.SessionEnableDisable{
		IsEnable: 1,
	}

	if s.govppChan == nil {
		s.Logger.Warn("GoVpp not available")
		return nil
	}

	reply := session.SessionEnableDisableReply{}

	err := s.govppChan.SendRequest(req).ReceiveReply(&reply)

	if reply.Retval != 0 {
		return fmt.Errorf("enabling session returned non-zero return code")
	}

	return err
}
