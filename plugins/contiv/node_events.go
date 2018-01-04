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

	"github.com/contiv/vpp/plugins/contiv/model/uid"
	"github.com/ligato/cn-infra/datasync"
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
		hostID := uint8(nodeID.Id)

		// route := s.getRouteToNode(conf, nodeID.Id)
		if dataChngEv.GetChangeType() == datasync.Put {
			// Addition of host routes
			s.Logger.Info("New node discovered: ", hostID)

			podsRoute, hostRoute, err := s.computeRoutesForHost(hostID)
			if err != nil {
				return err
			}
			s.Logger.Info("Adding PODs route: ", podsRoute)
			s.Logger.Info("Adding host route: ", hostRoute)
			if err = s.vppLinuxTxnFactory().Put().StaticRoute(podsRoute).StaticRoute(hostRoute).Send().ReceiveReply(); err != nil {
				return fmt.Errorf("Can't configure vpp to add route to host %v (and its pods): %v ", hostID, err)
			}
		} else {
			// Delete of host routes
			s.Logger.Info("Node removed: ", hostID)

			podsRoute, hostRoute, err := s.computeRoutesForHost(hostID)
			if err != nil {
				return err
			}

			err = s.vppLinuxTxnFactory().Delete().
				StaticRoute(podsRoute.VrfId, podsRoute.DstIpAddr, podsRoute.NextHopAddr).
				StaticRoute(hostRoute.VrfId, hostRoute.DstIpAddr, hostRoute.NextHopAddr).
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

func (s *remoteCNIserver) nodeResync(dataResyncEv datasync.ResyncEvent) error {
	// TODO: implement proper resync (handle deleted routes as well)
	var err error
	txn := s.vppLinuxTxnFactory().Put()
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

				// add rhe route for this host
				hostID := uint8(nodeID.Id)
				if hostID != s.ipam.NodeID() {
					s.Logger.Info("Adding routes to host ", hostID)
					podsRoute, hostRoute, err := s.computeRoutesForHost(hostID)
					if err != nil {
						return err
					}
					s.Logger.Info("Adding PODs route: ", podsRoute)
					s.Logger.Info("Adding host route: ", hostRoute)
					if err = s.vppLinuxTxnFactory().Put().StaticRoute(podsRoute).StaticRoute(hostRoute).Send().ReceiveReply(); err != nil {
						return fmt.Errorf("Can't configure vpp to add route to host %v (and its pods): %v ", hostID, err)
					}
				}
			}
		}
	}

	return txn.Send().ReceiveReply()
}
