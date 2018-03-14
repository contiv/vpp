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

	"net"

	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
)

// handleNodeEvents handles changes in nodes within the k8s cluster (node add / delete) and
// adjusts the vswitch config (routes to the other nodes) accordingly.
func (s *remoteCNIserver) handleNodeEvents(ctx context.Context, resyncChan chan datasync.ResyncEvent, changeChan chan datasync.ChangeEvent) {
	select {
	case resyncEv := <-resyncChan:
		// resync needs to return done immediately, to not block resync of the remote cni server
		go s.nodeResync(resyncEv)
		resyncEv.Done(nil)

	case <-ctx.Done():
		return
	}

	for {
		select {

		case resyncEv := <-resyncChan:
			// resync needs to return done immediately, to not block resync of the remote cni server
			go s.nodeResync(resyncEv)
			resyncEv.Done(nil)

		case changeEv := <-changeChan:
			err := s.nodeChangePropageteEvent(changeEv)
			changeEv.Done(err)

		case <-ctx.Done():
			return
		}
	}
}

// nodeResync processes all nodes data and configures vswitch (routes to the other nodes) accordingly.
func (s *remoteCNIserver) nodeResync(dataResyncEv datasync.ResyncEvent) error {

	// do not handle other nodes until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	// TODO: implement proper resync (handle deleted routes as well)

	var err error
	data := dataResyncEv.GetValues()

	for prefix, it := range data {
		if prefix == AllocatedIDsKeyPrefix {
			for {
				kv, stop := it.GetNext()
				if stop {
					break
				}
				nodeInfo := &node.NodeInfo{}
				err = kv.GetValue(nodeInfo)
				if err != nil {
					return err
				}

				nodeID := uint8(nodeInfo.Id)

				if nodeID != s.ipam.NodeID() {
					s.Logger.Info("Other node discovered: ", nodeID)
					if nodeInfo.IpAddress != "" && nodeInfo.ManagementIpAddress != "" {
						// add routes to the node
						err = s.addRoutesToNode(nodeInfo)
					} else {
						s.Logger.Infof("Ip address or management IP of node %v is not known yet.")
					}
				}
			}
		}
	}

	return err
}

// nodeChangePropageteEvent handles change in nodes within the k8s cluster (node add / delete)
// and configures vswitch (routes to the other nodes) accordingly.
func (s *remoteCNIserver) nodeChangePropageteEvent(dataChngEv datasync.ChangeEvent) error {

	// do not handle other nodes until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	key := dataChngEv.GetKey()
	var err error

	if strings.HasPrefix(key, AllocatedIDsKeyPrefix) {
		nodeInfo := &node.NodeInfo{}
		err = dataChngEv.GetValue(nodeInfo)
		if err != nil {
			return err
		}

		// skip nodeInfo of this node
		if nodeInfo.Id == uint32(s.nodeID) {
			return nil
		}

		if dataChngEv.GetChangeType() == datasync.Put {

			// Note: the case where IP address is changed during runtime is not handled
			if nodeInfo.IpAddress != "" && nodeInfo.ManagementIpAddress != "" {
				s.Logger.Info("New node discovered: ", nodeInfo.Id)
				// add routes to the node
				err = s.addRoutesToNode(nodeInfo)
			} else {
				s.Logger.Infof("IP address or management IP of node %v is not known yet.", nodeInfo.Id)
			}
		} else {
			s.Logger.Info("Node removed: ", nodeInfo.Id)

			// delete routes to the node
			err = s.deleteRoutesToNode(nodeInfo)
		}
	} else {
		return fmt.Errorf("Unknown key %v", key)
	}

	return err
}

// addRoutesToNode add routes to the node specified by nodeID.
func (s *remoteCNIserver) addRoutesToNode(nodeInfo *node.NodeInfo) error {

	txn := s.vppTxnFactory().Put()
	hostIP := s.otherHostIP(uint8(nodeInfo.Id), nodeInfo.IpAddress)

	// VXLAN tunnel
	if !s.useL2Interconnect {
		vxlanIf, err := s.computeVxlanToHost(uint8(nodeInfo.Id), hostIP)
		if err != nil {
			return err
		}
		txn.VppInterface(vxlanIf)

		// add the VXLAN interface into the VXLAN bridge domain
		s.addInterfaceToVxlanBD(s.vxlanBD, vxlanIf.Name)

		// pass deep copy to local client since we are overwriting previously applied config
		bd := proto.Clone(s.vxlanBD)
		txn.BD(bd.(*vpp_l2.BridgeDomains_BridgeDomain))
	}

	// static routes
	var (
		podsRoute    *vpp_l3.StaticRoutes_Route
		hostRoute    *vpp_l3.StaticRoutes_Route
		vxlanNextHop net.IP
		err          error
		nextHop      string
	)
	if s.useL2Interconnect {
		// static route directly to other node IP
		podsRoute, hostRoute, err = s.computeRoutesToHost(uint8(nodeInfo.Id), hostIP)
		nextHop = hostIP
	} else {
		// static route to other node VXLAN BVI
		vxlanNextHop, err = s.ipam.VxlanIPAddress(uint8(nodeInfo.Id))
		if err != nil {
			return err
		}
		nextHop = vxlanNextHop.String()
		podsRoute, hostRoute, err = s.computeRoutesToHost(uint8(nodeInfo.Id), nextHop)
	}
	if err != nil {
		return err
	}
	txn.StaticRoute(podsRoute)
	txn.StaticRoute(hostRoute)
	s.Logger.Info("Adding PODs route: ", podsRoute)
	s.Logger.Info("Adding host route: ", hostRoute)

	if s.stnIP == "" {
		managementRoute := s.routeToOtherManagementIP(nodeInfo.ManagementIpAddress, nextHop)
		txn.StaticRoute(managementRoute)
		s.Logger.Info("Adding managementIP route: ", managementRoute)
	}

	// send the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		return fmt.Errorf("Can't configure VPP to add routes to node %v: %v ", nodeInfo.Id, err)
	}
	return nil
}

// deleteRoutesToNode delete routes to the node specified by nodeID.
func (s *remoteCNIserver) deleteRoutesToNode(nodeInfo *node.NodeInfo) error {
	podsRoute, hostRoute, err := s.computeRoutesToHost(uint8(nodeInfo.Id), nodeInfo.IpAddress)
	if err != nil {
		return err
	}
	s.Logger.Info("Deleting PODs route: ", podsRoute)
	s.Logger.Info("Deleting host route: ", hostRoute)

	err = s.vppTxnFactory().Delete().
		StaticRoute(podsRoute.VrfId, podsRoute.DstIpAddr, podsRoute.NextHopAddr).
		StaticRoute(hostRoute.VrfId, hostRoute.DstIpAddr, hostRoute.NextHopAddr).
		Send().ReceiveReply()

	if err != nil {
		return fmt.Errorf("Can't configure vpp to remove route to host %v (and its pods): %v ", nodeInfo.Id, err)
	}
	return nil
}
