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
	"fmt"
	"strings"

	"net"

	k8sNode "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	"github.com/ligato/vpp-agent/clientv2/linux"
)

/* Contiv Plugin */

// processThisNodeChangeEvent publishes update of this node IPs for other nodes to know.
func (plugin *Plugin) processThisNodeChangeEvent(dataChng datasync.ProtoWatchResp) error {
	if dataChng.GetKey() == k8sNode.Key(plugin.ServiceLabel.GetAgentLabel()) {
		return plugin.updateThisNodeMgmtIPs(dataChng)
	}
	return nil
}

// thisNodeResync publishes update of this node IPs for other nodes based on resync data.
func (plugin *Plugin) thisNodeResync(resyncEv datasync.ResyncEvent) error {
	data := resyncEv.GetValues()

	for prefix, it := range data {
		if prefix == k8sNode.KeyPrefix() {
			for {
				kv, stop := it.GetNext()
				if stop {
					break
				}
				if kv.GetKey() == k8sNode.Key(plugin.ServiceLabel.GetAgentLabel()) {
					return plugin.updateThisNodeMgmtIPs(kv)
				}
			}
		}
	}
	return nil
}

// updateThisNodeMgmtIPs publishes update of this node IPs for other nodes to know.
func (plugin *Plugin) updateThisNodeMgmtIPs(nodeChange datasync.KeyVal) error {
	value := &k8sNode.Node{}
	err := nodeChange.GetValue(value)
	if err != nil {
		return err
	}

	var k8sIPs []string
	for i := range value.Addresses {
		if value.Addresses[i].Type == k8sNode.NodeAddress_NodeInternalIP ||
			value.Addresses[i].Type == k8sNode.NodeAddress_NodeExternalIP {
			k8sIPs = appendIfMissing(k8sIPs, value.Addresses[i].Address)
		}
	}
	if len(k8sIPs) > 0 {
		ips := strings.Join(k8sIPs, MgmtIPSeparator)
		plugin.Log.Info("Management IPs of the node are ", ips)
		return plugin.nodeIDAllocator.updateManagementIP(ips)
	}

	plugin.Log.Debug("Management IPs of the node are not in ETCD yet.")
	return nil
}

/* Remote CNI Server */

// otherNodesResync re-synchronizes connectivity to other nodes.
func (s *remoteCNIserver) otherNodesResync(dataResyncEv datasync.ResyncEvent, txn linuxclient.DataResyncDSL) error {

	// VXLAN BVI loopback
	vxlanBVI, err := s.vxlanBVILoopback()
	if err != nil {
		s.Logger.Error(err)
		return err
	}
	txn.VppInterface(vxlanBVI)

	data := dataResyncEv.GetValues()
	for prefix, it := range data {
		if prefix == node.AllocatedIDsKeyPrefix {
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

				nodeID := nodeInfo.Id

				if nodeID != s.ipam.NodeID() {
					s.Logger.Info("Other node discovered: ", nodeID)
					s.otherNodeIDs[nodeID] = struct{}{}
					if nodeInfo.IpAddress != "" && nodeInfo.ManagementIpAddress != "" {
						// add routes to the node
						err = s.addRoutesToNode(nodeInfo, txn)
					} else {
						s.Logger.Infof("Ip address or management IP of node %v is not known yet.", nodeID)
					}
				}
			}
		}
	}

	// bridge domain with vxlan interfaces
	if !s.config.UseL2Interconnect {
		// configure VXLAN tunnel bridge domain
		txn.BD(s.vxlanBridgeDomain())
	}
	return err
}

// processOtherNodeChangeEvent reacts to a changed node.
func (s *remoteCNIserver) processOtherNodeChangeEvent(dataChngEv datasync.ProtoWatchResp) error {
	s.Logger.WithFields(logging.Fields{
		"key": dataChngEv.GetKey(),
		"rev": dataChngEv.GetRevision()}).Info("Processing change event")
	key := dataChngEv.GetKey()
	var err error

	if strings.HasPrefix(key, node.AllocatedIDsKeyPrefix) {
		var (
			nodeInfo, prevNodeInfo node.NodeInfo
			modified, deleted, noAddresses bool
		)

		if err = dataChngEv.GetValue(&nodeInfo); err != nil {
			return err
		}

		if modified, err = dataChngEv.GetPrevValue(&prevNodeInfo); err != nil {
			return err
		}

		// skip nodeInfo of this node
		if nodeInfo.Id == uint32(s.nodeID) {
			return nil
		}

		// skip if nothing has really changed
		if modified && proto.Equal(&nodeInfo, &prevNodeInfo) {
			return nil
		}

		deleted = dataChngEv.GetChangeType() == datasync.Delete
		noAddresses = !deleted && nodeInfo.IpAddress == "" && nodeInfo.ManagementIpAddress == ""

		if deleted || modified /* re-create connectivity to the node if IP addresses have changed */ {
			err = s.deleteRoutesToNode(&prevNodeInfo)
		}
		if !deleted && !noAddresses {
			txn := s.vppTxnFactory().Put()
			err = s.addRoutesToNode(&nodeInfo, txn)
			// send the config transaction
			err = txn.Send().ReceiveReply()
			if err != nil {
				return fmt.Errorf("Failed to configure connectivity to the node %v: %v ", nodeInfo.Id, err)
			}
		}
		// TODO update otherNodeIDs and bridge domain
	}

	return err
}

// addRoutesToNode add routes to the node specified by nodeID.
func (s *remoteCNIserver) addRoutesToNode(nodeInfo *node.NodeInfo, txn NodeConfigPutTxn) error {
	hostIP := s.otherHostIP(nodeInfo.Id, nodeInfo.IpAddress)

	// VXLAN tunnel
	if !s.config.UseL2Interconnect {
		vxlanIf, err := s.computeVxlanToHost(nodeInfo.Id, hostIP)
		if err != nil {
			return err
		}
		txn.VppInterface(vxlanIf)
		s.Logger.WithFields(logging.Fields{
			"srcIP":  vxlanIf.GetVxlan().SrcAddress,
			"destIP": vxlanIf.GetVxlan().DstAddress}).Info("Configuring vxlan")

		// static ARP entry
		vxlanIP, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		vxlanArp := s.vxlanArpEntry(nodeInfo.Id, vxlanIP.String())
		txn.Arp(vxlanArp)

		// static FIB
		vxlanFib := s.vxlanFibEntry(vxlanArp.PhysAddress, vxlanIf.Name)
		txn.BDFIB(vxlanFib)
	}

	// static routes
	var (
		podsRoute    *vpp_l3.StaticRoute
		hostRoute    *vpp_l3.StaticRoute
		vxlanNextHop net.IP
		err          error
		nextHop      string
	)
	if s.config.UseL2Interconnect {
		// static route directly to other node IP
		podsRoute, hostRoute, err = s.computeRoutesToHost(nodeInfo.Id, hostIP)
		nextHop = hostIP
	} else {
		// static route to other node VXLAN BVI
		vxlanNextHop, err = s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			return err
		}
		nextHop = vxlanNextHop.String()
		podsRoute, hostRoute, err = s.computeRoutesToHost(nodeInfo.Id, nextHop)
	}
	if err != nil {
		return err
	}
	txn.StaticRoute(podsRoute)
	txn.StaticRoute(hostRoute)
	s.Logger.Info("Adding PODs route: ", podsRoute)
	s.Logger.Info("Adding host route: ", hostRoute)

	mgmtIPs := strings.Split(nodeInfo.ManagementIpAddress, MgmtIPSeparator)

	for _, mIP := range mgmtIPs {
		mgmtRoute1 := s.routeToOtherManagementIP(mIP, nextHop)
		txn.StaticRoute(mgmtRoute1)
		s.Logger.Info("Adding managementIP route: ", mgmtRoute1)

		if s.stnIP == "" {
			mgmtRoute2 := s.routeToOtherManagementIPViaPodVRF(mIP)
			txn.StaticRoute(mgmtRoute2)
			s.Logger.Info("Adding managementIP route via POD VRF: ", mgmtRoute2)
		}
	}
	return nil
}

// deleteRoutesToNode delete routes to the node specified by nodeID.
func (s *remoteCNIserver) deleteRoutesToNode(nodeInfo *node.NodeInfo) error {
	txn := s.vppTxnFactory()
	hostIP := s.otherHostIP(nodeInfo.Id, nodeInfo.IpAddress)

	// VXLAN tunnel
	if !s.config.UseL2Interconnect {
		vxlanIf, err := s.computeVxlanToHost(nodeInfo.Id, hostIP)
		if err != nil {
			return err
		}
		txn.Delete().VppInterface(vxlanIf.Name)
		s.Logger.WithFields(logging.Fields{
			"srcIP":  vxlanIf.GetVxlan().SrcAddress,
			"destIP": vxlanIf.GetVxlan().DstAddress}).Info("Removing vxlan")

		// static ARP entry
		vxlanIP, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		vxlanArp := s.vxlanArpEntry(nodeInfo.Id, vxlanIP.String())
		txn.Delete().Arp(vxlanArp.Interface, vxlanArp.IpAddress)

		// static FIB
		vxlanFib := s.vxlanFibEntry(vxlanArp.PhysAddress, vxlanIf.Name)
		txn.Delete().BDFIB(vxlanFib.BridgeDomain, vxlanFib.PhysAddress)
	}

	// static routes
	var (
		podsRoute    *vpp_l3.StaticRoute
		hostRoute    *vpp_l3.StaticRoute
		vxlanNextHop net.IP
		err          error
		nextHop      string
	)
	if s.config.UseL2Interconnect {
		// static route directly to other node IP
		podsRoute, hostRoute, err = s.computeRoutesToHost(nodeInfo.Id, hostIP)
		nextHop = hostIP
	} else {
		// static route to other node VXLAN BVI
		vxlanNextHop, err = s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			return err
		}
		nextHop = vxlanNextHop.String()
		podsRoute, hostRoute, err = s.computeRoutesToHost(nodeInfo.Id, nextHop)
	}
	if err != nil {
		return err
	}
	txn.Delete().StaticRoute(podsRoute.VrfId, podsRoute.DstNetwork, podsRoute.NextHopAddr)
	txn.Delete().StaticRoute(hostRoute.VrfId, hostRoute.DstNetwork, hostRoute.NextHopAddr)
	s.Logger.Info("Deleting PODs route: ", podsRoute)
	s.Logger.Info("Deleting host route: ", hostRoute)

	mgmtIPs := strings.Split(nodeInfo.ManagementIpAddress, MgmtIPSeparator)

	for _, mIP := range mgmtIPs {
		mgmtRoute1 := s.routeToOtherManagementIP(mIP, nextHop)
		txn.Delete().StaticRoute(mgmtRoute1.VrfId, mgmtRoute1.DstNetwork, mgmtRoute1.NextHopAddr)
		s.Logger.Info("Deleting managementIP route: ", mgmtRoute1)

		if s.stnIP == "" {
			mgmtRoute2 := s.routeToOtherManagementIPViaPodVRF(mIP)
			txn.Delete().StaticRoute(mgmtRoute2.VrfId, mgmtRoute2.DstNetwork, "")
			s.Logger.Info("Deleting managementIP route via POD VRF: ", mgmtRoute2)
		}
	}
	// send the config transaction
	err = txn.Send().ReceiveReply()
	if err != nil {
		return fmt.Errorf("Can't configure VPP to remove routes to node %v: %v ", nodeInfo.Id, err)
	}
	return nil
}
