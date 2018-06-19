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
	"github.com/ligato/cn-infra/logging"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/l3"
)

// handleNodeEvents handles changes in nodes within the k8s cluster (node add / delete) and
// adjusts the vswitch config (routes to the other nodes) accordingly.
func (s *remoteCNIserver) handleNodeEvents(ctx context.Context, resyncChan chan datasync.ResyncEvent, changeChan chan datasync.ChangeEvent) {
	for {
		select {

		case resyncEv := <-resyncChan:
			// resync needs to return done immediately, to not block resync of the remote cni server
			go s.nodeResync(resyncEv)
			resyncEv.Done(nil)

		case changeEv := <-changeChan:
			err := s.nodeChangePropagateEvent(changeEv)
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
		if prefix == node.AllocatedIDsKeyPrefix {
			for {
				kv, stop := it.GetNext()
				if stop {
					break
				}
				rev := kv.GetRevision()
				if rev > s.nodeIDResyncRev {
					s.nodeIDResyncRev = rev
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
						s.Logger.Infof("Ip address or management IP of node %v is not known yet.", nodeID)
					}
				}
			}
		}
	}

	s.Logger.WithField("nodeResyncRev", s.nodeIDResyncRev).
		Infof("%v buffered nodeID change event found", len(s.nodeIDChangeEvs))
	for _, ev := range s.nodeIDChangeEvs {
		err = s.processChangeEvent(ev)
		if err != nil {
			s.Logger.Error(err)
		}
	}
	err = nil
	s.nodeIDChangeEvs = nil

	return err
}

// nodeChangePropagateEvent handles change in nodes within the k8s cluster (node add / delete)
// and configures vswitch (routes to the other nodes) accordingly.
func (s *remoteCNIserver) nodeChangePropagateEvent(dataChngEv datasync.ChangeEvent) error {

	// do not handle other nodes until the base vswitch config is successfully applied
	s.Lock()
	defer s.Unlock()

	if !s.vswitchConnectivityConfigured {
		// resync event must be processed first, cache the event
		s.nodeIDChangeEvs = append(s.nodeIDChangeEvs, dataChngEv)
		s.Logger.WithFields(logging.Fields{
			"key": dataChngEv.GetKey(),
			"rev": dataChngEv.GetRevision()}).Info("NodeId change event buffered")
		return nil
	}

	return s.processChangeEvent(dataChngEv)
}

func (s *remoteCNIserver) processChangeEvent(dataChngEv datasync.ChangeEvent) error {
	s.Logger.WithFields(logging.Fields{
		"key": dataChngEv.GetKey(),
		"rev": dataChngEv.GetRevision()}).Info("Processing change event")
	key := dataChngEv.GetKey()
	var err error

	if strings.HasPrefix(key, node.AllocatedIDsKeyPrefix) {
		rev := dataChngEv.GetRevision()
		if rev <= s.nodeIDResyncRev {
			s.Logger.Info("Node id change event was generated before resync, skipping")
			return nil
		}

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
			prevNodeInfo := &node.NodeInfo{}
			_, err := dataChngEv.GetPrevValue(prevNodeInfo)
			if err != nil {
				return err
			}

			s.Logger.Info("Node removed: ", prevNodeInfo.Id)

			// delete routes to the node
			err = s.deleteRoutesToNode(prevNodeInfo)
		}
	} else {
		return fmt.Errorf("Unknown key %v", key)
	}

	return err
}

// addRoutesToNode add routes to the node specified by nodeID.
func (s *remoteCNIserver) addRoutesToNode(nodeInfo *node.NodeInfo) error {

	txn := s.vppTxnFactory().Put()
	txn2 := s.vppTxnFactory().Put() // TODO: merge into 1 transaction after vpp-agent supports it
	hostIP := s.otherHostIP(uint8(nodeInfo.Id), nodeInfo.IpAddress)

	// VXLAN tunnel
	if !s.useL2Interconnect {
		vxlanIf, err := s.computeVxlanToHost(uint8(nodeInfo.Id), hostIP)
		if err != nil {
			return err
		}
		txn.VppInterface(vxlanIf)
		s.Logger.WithFields(logging.Fields{
			"srcIP":  vxlanIf.Vxlan.SrcAddress,
			"destIP": vxlanIf.Vxlan.DstAddress}).Info("Configuring vxlan")

		// add the VXLAN interface into the VXLAN bridge domain
		s.addInterfaceToVxlanBD(s.vxlanBD, vxlanIf.Name)

		// pass deep copy to local client since we are overwriting previously applied config
		bd := proto.Clone(s.vxlanBD)
		txn.BD(bd.(*vpp_l2.BridgeDomains_BridgeDomain))

		// static ARP entry
		vxlanIP, err := s.ipam.VxlanIPAddress(uint8(nodeInfo.Id))
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		vxlanArp := s.vxlanArpEntry(uint8(nodeInfo.Id), vxlanIP.String())
		txn.Arp(vxlanArp)

		// static FIB
		vxlanFib := s.vxlanFibEntry(vxlanArp.PhysAddress, vxlanIf.Name)
		txn2.BDFIB(vxlanFib)
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
	if !s.useL2Interconnect {
		err = txn2.Send().ReceiveReply()
		if err != nil {
			return fmt.Errorf("Can't configure VPP to add FIB to node %v: %v ", nodeInfo.Id, err)
		}
	}
	return nil
}

// deleteRoutesToNode delete routes to the node specified by nodeID.
func (s *remoteCNIserver) deleteRoutesToNode(nodeInfo *node.NodeInfo) error {
	txn := s.vppTxnFactory().Delete()
	txn2 := s.vppTxnFactory().Delete() // TODO: merge into 1 transaction after vpp-agent supports it
	hostIP := s.otherHostIP(uint8(nodeInfo.Id), nodeInfo.IpAddress)

	// VXLAN tunnel
	if !s.useL2Interconnect {
		vxlanIf, err := s.computeVxlanToHost(uint8(nodeInfo.Id), hostIP)
		if err != nil {
			return err
		}
		txn.VppInterface(vxlanIf.Name)
		s.Logger.WithFields(logging.Fields{
			"srcIP":  vxlanIf.Vxlan.SrcAddress,
			"destIP": vxlanIf.Vxlan.DstAddress}).Info("Removing vxlan")

		// remove the VXLAN interface from the VXLAN bridge domain
		s.removeInterfaceFromVxlanBD(s.vxlanBD, vxlanIf.Name)

		// pass deep copy to local client since we are overwriting previously applied config
		bd := proto.Clone(s.vxlanBD)
		err = s.vppTxnFactory().Put().BD(bd.(*vpp_l2.BridgeDomains_BridgeDomain)).Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return err
		}

		// static ARP entry
		vxlanIP, err := s.ipam.VxlanIPAddress(uint8(nodeInfo.Id))
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		vxlanArp := s.vxlanArpEntry(uint8(nodeInfo.Id), vxlanIP.String())
		txn.Arp(vxlanArp.Interface, vxlanArp.IpAddress)

		// static FIB
		vxlanFib := s.vxlanFibEntry(vxlanArp.PhysAddress, vxlanIf.Name)
		txn2.BDFIB(vxlanFib.BridgeDomain, vxlanFib.PhysAddress)
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
	txn.StaticRoute(podsRoute.VrfId, podsRoute.DstIpAddr, podsRoute.NextHopAddr)
	txn.StaticRoute(hostRoute.VrfId, hostRoute.DstIpAddr, hostRoute.NextHopAddr)
	s.Logger.Info("Deleting PODs route: ", podsRoute)
	s.Logger.Info("Deleting host route: ", hostRoute)

	if s.stnIP == "" {
		managementRoute := s.routeToOtherManagementIP(nodeInfo.ManagementIpAddress, nextHop)
		txn.StaticRoute(managementRoute.VrfId, managementRoute.DstIpAddr, managementRoute.NextHopAddr)
		s.Logger.Info("Deleting managementIP route: ", managementRoute)
	}

	// send the config transaction
	if !s.useL2Interconnect {
		// FIBs need to be removed before the VXLAN interface
		err = txn2.Send().ReceiveReply()
		if err != nil {
			return fmt.Errorf("Can't configure VPP to remove FIB to node %v: %v ", nodeInfo.Id, err)
		}
	}
	err = txn.Send().ReceiveReply()
	if err != nil {
		return fmt.Errorf("Can't configure VPP to remove routes to node %v: %v ", nodeInfo.Id, err)
	}
	return nil
}
