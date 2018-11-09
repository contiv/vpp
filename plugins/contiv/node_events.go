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
	"net"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	scheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	"github.com/contiv/vpp/plugins/contiv/model/node"
	txn_api "github.com/contiv/vpp/plugins/controller/txn"
	k8sNode "github.com/contiv/vpp/plugins/ksr/model/node"
)

/* Contiv Plugin */

// thisNodeResync publishes update of this node IPs for other nodes based on resync data.
func (p *Plugin) thisNodeResync(resyncEv datasync.ResyncEvent) error {
	data := resyncEv.GetValues()

	for _, it := range data {
		for {
			kv, stop := it.GetNext()
			if stop {
				break
			}
			p.k8sStateData[kv.GetKey()] = kv

			if kv.GetKey() == k8sNode.Key(p.ServiceLabel.GetAgentLabel()) {
				return p.updateThisNodeMgmtIPs(kv)
			}
		}
	}
	return nil
}

// processThisNodeChangeEvent publishes update of this node IPs for other nodes to know.
func (p *Plugin) processThisNodeChangeEvent(dataChng datasync.ProtoWatchResp) error {
	if dataChng.GetKey() == k8sNode.Key(p.ServiceLabel.GetAgentLabel()) {
		return p.updateThisNodeMgmtIPs(dataChng)
	}
	return nil
}

// updateThisNodeMgmtIPs publishes update of this node IPs for other nodes to know.
func (p *Plugin) updateThisNodeMgmtIPs(nodeChange datasync.KeyVal) error {
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
		p.Log.Info("Management IPs of the node are ", ips)
		return p.nodeIDAllocator.updateManagementIP(ips)
	}

	p.Log.Debug("Management IPs of the node are not in ETCD yet.")
	return nil
}

/* Remote CNI Server */

// otherNodesResync re-synchronizes connectivity to other nodes.
func (s *remoteCNIserver) otherNodesResync(dataResyncEv datasync.ResyncEvent, txn txn_api.ResyncOperations) error {

	// collect other node IDs and configuration for connectivity with each of them
	data := dataResyncEv.GetValues()
	for prefix, it := range data {
		if prefix == node.AllocatedIDsKeyPrefix {
			for {
				kv, stop := it.GetNext()
				if stop {
					break
				}

				nodeInfo := &node.NodeInfo{}
				err := kv.GetValue(nodeInfo)
				if err != nil {
					// treat as warning
					s.Logger.Warnf("Failed to parse node information: %v", err)
					continue
				}

				nodeID := nodeInfo.Id

				// ignore for this node
				if nodeID == s.ipam.NodeID() {
					continue
				}

				// collect configuration for node connectivity
				s.Logger.Info("Other node discovered: ", nodeID)
				if nodeHasIPAddress(nodeInfo) {
					// add node info into the internal map
					s.otherNodes[nodeID] = nodeInfo
					// generate configuration
					nodeConnectConfig, err := s.nodeConnectivityConfig(nodeInfo)
					if err != nil {
						// treat as warning
						s.Logger.Warnf("Failed to configure connectivity to node ID=%d: %v",
							nodeInfo.Id, err)
						continue
					}
					for key, value := range nodeConnectConfig {
						txn.Put(key, value)
					}
				} else {
					s.Logger.Infof("Ip address or management IP of node %v is not known yet.", nodeID)
				}
			}
		}
	}

	// bridge domain with VXLAN interfaces
	if !s.config.UseL2Interconnect {
		// bridge domain
		key, bd := s.vxlanBridgeDomain()
		txn.Put(key, bd)

		// BVI interface
		key, vxlanBVI, err := s.vxlanBVILoopback()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		txn.Put(key, vxlanBVI)
	}
	return nil
}

// processOtherNodeChangeEvent reacts to a changed node.
func (s *remoteCNIserver) processOtherNodeChangeEvent(dataChngEv datasync.ProtoWatchResp) error {
	// process only NodeInfo key-values
	key := dataChngEv.GetKey()
	if !strings.HasPrefix(key, node.AllocatedIDsKeyPrefix) {
		return nil
	}
	s.Logger.WithFields(logging.Fields{
		"key": dataChngEv.GetKey(),
		"rev": dataChngEv.GetRevision()}).Info("Processing change event")

	var (
		nodeInfo, prevNodeInfo node.NodeInfo
		modified               bool
		err                    error
	)

	// parse node info
	if err = dataChngEv.GetValue(&nodeInfo); err != nil {
		return err
	}

	// get previous value
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

	// update internal map with node info
	if nodeHasIPAddress(&nodeInfo) {
		s.otherNodes[nodeInfo.Id] = &nodeInfo
	} else {
		delete(s.otherNodes, nodeInfo.Id)
	}

	// re-configure based on node IP changes
	txn := s.txnFactory()
	var operationName string

	// remove obsolete configuration
	if nodeHasIPAddress(&prevNodeInfo) {
		if !nodeHasIPAddress(&nodeInfo) {
			// un-configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(&prevNodeInfo)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					nodeInfo.Id, err)
				s.Logger.Error(err)
				return err
			}
			txn_api.DeleteAll(txn, connectivity)
			operationName = "Disconnect"
		} else {
			// remove obsolete routes
			routes, err := s.routesToNode(&prevNodeInfo)
			if err != nil {
				// treat as warning
				s.Logger.Warnf("Failed to generate config for obsolete routes for node ID=%d: %v",
					nodeInfo.Id, err)
			} else {
				txn_api.DeleteAll(txn, routes)
			}
			// operation is "Update"
		}
	}

	// add new configuration
	if nodeHasIPAddress(&nodeInfo) {
		if !nodeHasIPAddress(&prevNodeInfo) {
			// configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(&nodeInfo)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					nodeInfo.Id, err)
				s.Logger.Error(err)
				return err
			}
			txn_api.PutAll(txn, connectivity)
			operationName = "Connect"
		} else {
			// just add updated routes
			routes, err := s.routesToNode(&nodeInfo)
			if err != nil {
				err := fmt.Errorf("failed to generate config for obsolete routes for node ID=%d: %v",
					nodeInfo.Id, err)
				s.Logger.Error(err)
				return err
			}
			txn_api.PutAll(txn, routes)
			operationName = "Update"
		}
	}

	// update BD if node was newly connected or disconnected
	if nodeHasIPAddress(&prevNodeInfo) != nodeHasIPAddress(&nodeInfo) {
		key, bd := s.vxlanBridgeDomain()
		txn.Put(key, bd)
	}

	// commit transaction
	ctx := context.Background()
	ctx = scheduler_api.WithRetry(ctx, time.Second, true)
	ctx = scheduler_api.WithDescription(ctx, fmt.Sprintf("%s Node ID=%d", operationName, nodeInfo.Id))
	err = txn.Commit(ctx)
	if err != nil {
		err := fmt.Errorf("Failed to configure connectivity to the node %v: %v ", nodeInfo.Id, err)
		s.Logger.Error(err)
		return err
	}
	return nil
}

// nodeConnectivityConfig return configuration used to connect this node with the given other node.
func (s *remoteCNIserver) nodeConnectivityConfig(nodeInfo *node.NodeInfo) (config txn_api.KeyValuePairs, err error) {
	config = make(txn_api.KeyValuePairs)

	// configuration for VXLAN tunnel
	if !s.config.UseL2Interconnect {
		// VXLAN interface
		nodeIP, err := s.otherNodeIP(nodeInfo.Id, nodeInfo.IpAddress)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		key, vxlanIf := s.vxlanIfToOtherNode(nodeInfo.Id, nodeIP)
		config[key] = vxlanIf

		// ARP entry for the IP address on the opposite side
		vxlanIP, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		key, vxlanArp := s.vxlanArpEntry(nodeInfo.Id, vxlanIP)
		config[key] = vxlanArp

		// L2 FIB for the hardware address on the opposite side
		key, vxlanFib := s.vxlanFibEntry(nodeInfo.Id)
		config[key] = vxlanFib
	}

	// collect configuration for L3 routes
	routes, err := s.routesToNode(nodeInfo)
	if err != nil {
		return config, err
	}
	for key, route := range routes {
		config[key] = route
	}

	return config, nil
}

// routesToNode returns configuration of routes used for routing traffic destined to the given other node.
func (s *remoteCNIserver) routesToNode(nodeInfo *node.NodeInfo) (config txn_api.KeyValuePairs, err error) {
	config = make(txn_api.KeyValuePairs)

	var nextHop net.IP
	if s.config.UseL2Interconnect {
		// route traffic destined to the other node directly
		nodeIP, err := s.otherNodeIP(nodeInfo.Id, nodeInfo.IpAddress)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		nextHop = nodeIP
	} else {
		// route traffic destined to the other node via VXLANs
		vxlanNextHop, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		nextHop = vxlanNextHop
	}

	// route to pods of the other node
	key, routeToPods, err := s.routeToOtherNodePods(nodeInfo.Id, nextHop)
	if err != nil {
		s.Logger.Error(err)
		return config, err
	}
	config[key] = routeToPods

	// route to the host stack of the other node
	key, routeToHostStack, err := s.routeToOtherNodeHostStack(nodeInfo.Id, nextHop)
	if err != nil {
		s.Logger.Error(err)
		return config, err
	}
	config[key] = routeToHostStack

	// route to management IPs of the other node
	mgmtIPs := strings.Split(nodeInfo.ManagementIpAddress, MgmtIPSeparator)
	for _, address := range mgmtIPs {
		mgmtIP := net.ParseIP(address)
		if mgmtIP == nil {
			s.Logger.Warnf("Failed to parse management route '%s', skipping route configuration...",
				address)
		}

		// route management IP address towards the destination node
		key, mgmtRoute1 := s.routeToOtherNodeManagementIP(mgmtIP, nextHop)
		config[key] = mgmtRoute1

		// inter-VRF route for the management IP address
		if !s.UseSTN() {
			key, mgmtRoute2 := s.routeToOtherNodeManagementIPViaPodVRF(mgmtIP)
			config[key] = mgmtRoute2
		}
	}
	return config, nil
}

// nodeHasIPAddress returns true if the given node has at least one IP address assigned.
func nodeHasIPAddress(node *node.NodeInfo) bool {
	return node.IpAddress != "" || node.ManagementIpAddress != ""
}
