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
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/plugins/contiv/model/nodeinfo"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
)

/* Contiv Plugin */

// thisNodeResync publishes update of this node IPs for other nodes based on resync data.
func (p *Plugin) thisNodeResync(kubeStateData controller.KubeStateData, txn controller.ResyncOperations) error {
	for _, value := range kubeStateData[nodemodel.NodeKeyword] {
		node := value.(*nodemodel.Node)
		if node.GetName() == p.ServiceLabel.GetAgentLabel() {
			return p.updateThisNodeMgmtIPs(node)
		}
	}
	return nil
}

// processThisNodeChangeEvent publishes update of this node IPs for other nodes to know.
func (p *Plugin) processThisNodeChangeEvent(event *controller.KubeStateChange) error {
	if event.Resource == nodemodel.NodeKeyword {
		return p.updateThisNodeMgmtIPs(event.NewValue.(*nodemodel.Node))
	}
	return nil
}

// updateThisNodeMgmtIPs publishes update of this node IPs for other nodes to know.
func (p *Plugin) updateThisNodeMgmtIPs(node *nodemodel.Node) error {
	var k8sIPs []string
	for i := range node.Addresses {
		if node.Addresses[i].Type == nodemodel.NodeAddress_NodeInternalIP ||
			node.Addresses[i].Type == nodemodel.NodeAddress_NodeExternalIP {
			k8sIPs = appendIfMissing(k8sIPs, node.Addresses[i].Address)
		}
	}
	if len(k8sIPs) > 0 {
		ips := strings.Join(k8sIPs, MgmtIPSeparator)
		p.Log.Info("Management IPs of the node are ", ips)
		return p.nodeIDAllocator.UpdateManagementIP(ips)
	}

	p.Log.Debug("Management IPs of the node are not in ETCD yet.")
	return nil
}

/* Remote CNI Server */

// otherNodesResync re-synchronizes connectivity to other nodes.
func (s *remoteCNIserver) otherNodesResync(kubeStateData controller.KubeStateData, txn controller.ResyncOperations) error {
	// reset the internal map of other node IDs
	s.otherNodes = make(map[uint32]*nodeinfo.NodeInfo)

	// collect other node IDs and configuration for connectivity with each of them
	for _, nodeInfoProto := range kubeStateData[nodeinfo.Keyword] {
		nodeInfo := nodeInfoProto.(*nodeinfo.NodeInfo)
		nodeID := nodeInfo.Id

		// ignore for this node
		if nodeID == s.nodeID {
			continue
		}

		// collect configuration for node connectivity
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

// processOtherNodeChangeEvent reacts to a changed nodeinfo of another node.
func (s *remoteCNIserver) processOtherNodeChangeEvent(event *controller.KubeStateChange, txn controller.UpdateOperations) (change string, err error) {
	// process only NodeInfo key-values
	if event.Resource != nodeinfo.Keyword {
		return "", nil
	}

	var (
		nodeInfo, prevNodeInfo *nodeinfo.NodeInfo
		otherNodeID            uint32
	)

	// cast proto messages
	if event.NewValue != nil {
		nodeInfo = event.NewValue.(*nodeinfo.NodeInfo)
	}
	if event.PrevValue != nil {
		prevNodeInfo = event.NewValue.(*nodeinfo.NodeInfo)
	}

	// read the other node ID
	if nodeInfo != nil {
		otherNodeID = nodeInfo.Id
	} else {
		otherNodeID = prevNodeInfo.Id
	}

	// skip if nothing has really changed
	if proto.Equal(nodeInfo, prevNodeInfo) {
		return change, nil
	}

	// update internal map with node info
	if nodeHasIPAddress(nodeInfo) {
		s.otherNodes[otherNodeID] = nodeInfo
	} else {
		delete(s.otherNodes, otherNodeID)
	}

	// re-configure based on node IP changes
	var operationName string

	// remove obsolete configuration
	if nodeHasIPAddress(prevNodeInfo) {
		if !nodeHasIPAddress(nodeInfo) {
			// un-configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(prevNodeInfo)
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
			routes, err := s.routesToNode(prevNodeInfo)
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
	if nodeHasIPAddress(nodeInfo) {
		if !nodeHasIPAddress(prevNodeInfo) {
			// configure connectivity completely
			connectivity, err := s.nodeConnectivityConfig(nodeInfo)
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
			routes, err := s.routesToNode(nodeInfo)
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
	if !s.config.UseL2Interconnect && nodeHasIPAddress(prevNodeInfo) != nodeHasIPAddress(nodeInfo) {
		key, bd := s.vxlanBridgeDomain()
		txn.Put(key, bd)
	}

	change = fmt.Sprintf("%s node ID=%d", operationName, otherNodeID)
	return change, nil
}

// nodeConnectivityConfig return configuration used to connect this node with the given other node.
func (s *remoteCNIserver) nodeConnectivityConfig(nodeInfo *nodeinfo.NodeInfo) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

	// configuration for VXLAN tunnel
	if !s.config.UseL2Interconnect && len(s.nodeIP) > 0 {
		// VXLAN interface
		nodeIP, err := s.otherNodeIP(nodeInfo.Id, nodeInfo.IpAddress)
		if err != nil {
			s.Logger.Error(err)
			return config, err
		}
		key, vxlanIf := s.vxlanIfToOtherNode(nodeInfo.Id, nodeIP)
		config[key] = vxlanIf

		// ARP entry for the IP address on the opposite side
		vxlanIP, _, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
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
func (s *remoteCNIserver) routesToNode(nodeInfo *nodeinfo.NodeInfo) (config controller.KeyValuePairs, err error) {
	config = make(controller.KeyValuePairs)

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
		vxlanNextHop, _, err := s.ipam.VxlanIPAddress(nodeInfo.Id)
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
func nodeHasIPAddress(node *nodeinfo.NodeInfo) bool {
	return node != nil && (node.IpAddress != "" || node.ManagementIpAddress != "")
}
