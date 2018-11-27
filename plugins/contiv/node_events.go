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
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/nodesync"
)

// otherNodesResync re-synchronizes connectivity to other nodes.
func (s *remoteCNIserver) otherNodesResync(txn controller.ResyncOperations) error {
	// collect other node IDs and configuration for connectivity with each of them
	for _, node := range s.nodeSync.GetAllNodes() {
		// ignore for this node
		if node.Name == s.agentLabel {
			continue
		}

		// collect configuration for node connectivity
		if nodeHasIPAddress(node) {
			// generate configuration
			nodeConnectConfig, err := s.nodeConnectivityConfig(node)
			if err != nil {
				// treat as warning
				s.Logger.Warnf("Failed to configure connectivity to node ID=%d: %v",
					node.ID, err)
				continue
			}
			for key, value := range nodeConnectConfig {
				txn.Put(key, value)
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

// processNodeUpdateEvent reacts to an update of *another* node.
func (s *remoteCNIserver) processNodeUpdateEvent(nodeUpdate *nodesync.NodeUpdate, txn controller.UpdateOperations) (change string, err error) {
	// read the other node ID
	var otherNodeID uint32
	if nodeUpdate.NewState != nil {
		otherNodeID = nodeUpdate.NewState.ID
	} else {
		otherNodeID = nodeUpdate.PrevState.ID
	}

	// re-configure based on node IP changes
	var operationName string

	// remove obsolete configuration
	if nodeHasIPAddress(nodeUpdate.PrevState) {
		if !nodeHasIPAddress(nodeUpdate.NewState) {
			// un-configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(nodeUpdate.PrevState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					otherNodeID, err)
				s.Logger.Error(err)
				return change, err
			}
			controller.DeleteAll(txn, connectivity)
			operationName = "disconnect"
		} else {
			// remove obsolete routes
			routes, err := s.routesToNode(nodeUpdate.PrevState)
			if err != nil {
				// treat as warning
				s.Logger.Warnf("Failed to generate config for obsolete routes for node ID=%d: %v",
					otherNodeID, err)
			} else {
				controller.DeleteAll(txn, routes)
			}
			// operation is "Update"
		}
	}

	// add new configuration
	if nodeHasIPAddress(nodeUpdate.NewState) {
		if !nodeHasIPAddress(nodeUpdate.PrevState) {
			// configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(nodeUpdate.NewState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					otherNodeID, err)
				s.Logger.Error(err)
				return change, err
			}
			controller.PutAll(txn, connectivity)
			operationName = "connect"
		} else {
			// just add updated routes
			routes, err := s.routesToNode(nodeUpdate.NewState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for obsolete routes for node ID=%d: %v",
					otherNodeID, err)
				s.Logger.Error(err)
				return change, err
			}
			controller.PutAll(txn, routes)
			operationName = "update"
		}
	}

	// update BD if node was newly connected or disconnected
	if !s.config.UseL2Interconnect &&
		nodeHasIPAddress(nodeUpdate.PrevState) != nodeHasIPAddress(nodeUpdate.NewState) {

		key, bd := s.vxlanBridgeDomain()
		txn.Put(key, bd)
	}

	change = fmt.Sprintf("%s node ID=%d", operationName, otherNodeID)
	return change, nil
}

// nodeConnectivityConfig return configuration used to connect this node with the given other node.
func (s *remoteCNIserver) nodeConnectivityConfig(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	// configuration for VXLAN tunnel
	if !s.config.UseL2Interconnect && len(s.nodeIP) > 0 {
		// VXLAN interface
		var nodeIP net.IP
		if len(node.VppIPAddresses) > 0 {
			nodeIP = node.VppIPAddresses[0].Address
		} else {
			var err error
			nodeIP, err = s.otherNodeIP(node.ID)
			if err != nil {
				s.Logger.Error(err)
				return config, err
			}
		}
		key, vxlanIf := s.vxlanIfToOtherNode(node.ID, nodeIP)
		config[key] = vxlanIf

		// ARP entry for the IP address on the opposite side
		vxlanIP, _, err := s.ipam.VxlanIPAddress(node.ID)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		key, vxlanArp := s.vxlanArpEntry(node.ID, vxlanIP)
		config[key] = vxlanArp

		// L2 FIB for the hardware address on the opposite side
		key, vxlanFib := s.vxlanFibEntry(node.ID)
		config[key] = vxlanFib
	}

	// collect configuration for L3 routes
	routes, err := s.routesToNode(node)
	if err != nil {
		return config, err
	}
	for key, route := range routes {
		config[key] = route
	}

	return config, nil
}

// routesToNode returns configuration of routes used for routing traffic destined to the given other node.
func (s *remoteCNIserver) routesToNode(node *nodesync.Node) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	var nextHop net.IP
	if s.config.UseL2Interconnect {
		// route traffic destined to the other node directly
		if len(node.VppIPAddresses) > 0 {
			nextHop = node.VppIPAddresses[0].Address
		} else {
			var err error
			nextHop, err = s.otherNodeIP(node.ID)
			if err != nil {
				s.Logger.Error(err)
				return config, err
			}
		}
	} else {
		// route traffic destined to the other node via VXLANs
		vxlanNextHop, _, err := s.ipam.VxlanIPAddress(node.ID)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		nextHop = vxlanNextHop
	}

	// route to pods of the other node
	key, routeToPods, err := s.routeToOtherNodePods(node.ID, nextHop)
	if err != nil {
		s.Logger.Error(err)
		return config, err
	}
	config[key] = routeToPods

	// route to the host stack of the other node
	key, routeToHostStack, err := s.routeToOtherNodeHostStack(node.ID, nextHop)
	if err != nil {
		s.Logger.Error(err)
		return config, err
	}
	config[key] = routeToHostStack

	// route to management IPs of the other node
	for _, mgmtIP := range node.MgmtIPAddresses {
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
func nodeHasIPAddress(node *nodesync.Node) bool {
	return node != nil && len(node.VppIPAddresses) > 0 && len(node.MgmtIPAddresses) > 0
}
