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
	"github.com/contiv/vpp/plugins/contiv/model/uid"
	"github.com/ligato/cn-infra/datasync"
	"strings"
)

// handleNodeEvents adjust VPP route configuration according to the node changes.
func (s *remoteCNIserver) handleNodeEvents(resyncChan chan datasync.ResyncEvent, changeChan chan datasync.ChangeEvent, ctx context.Context) {
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

		// route := s.getRouteToNode(conf, nodeID.Id)
		if dataChngEv.GetChangeType() == datasync.Put {
			// TODO: add route for nodeID.Id
			//err = s.vppTxnFactory().Put().StaticRoute(route).Send().ReceiveReply()
		} else {
			// TODO: remove route for nodeID.Id
			//err = s.vppTxnFactory().Delete().StaticRoute(route).Send().ReceiveReply()
		}
	} else {
		return fmt.Errorf("Unknown key %v", key)
	}
	return err
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
