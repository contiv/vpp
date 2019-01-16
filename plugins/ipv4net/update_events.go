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

package ipv4net

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

// Update is called for:
//   - AddPod and DeletePod
//   - NodeUpdate for other nodes
//   - Shutdown event
func (n *IPv4Net) Update(event controller.Event, txn controller.UpdateOperations) (change string, err error) {
	if addPod, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return n.addPod(addPod, txn)
	}

	if delPod, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return n.deletePod(delPod, txn)
	}

	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return n.processNodeUpdateEvent(nodeUpdate, txn)
	}

	if _, isShutdown := event.(*controller.Shutdown); isShutdown {
		return n.cleanupVswitchConnectivity(txn)
	}

	return "", nil
}

// Revert is called for AddPod.
func (n *IPv4Net) Revert(event controller.Event) error {
	addPod := event.(*podmanager.AddPod)
	pod := n.PodManager.GetLocalPods()[addPod.Pod]
	n.IPAM.ReleasePodIP(pod.ID)

	vppIface, _ := n.podInterfaceName(pod)
	n.vppIfaceToPodMutex.Lock()
	delete(n.vppIfaceToPod, vppIface)
	n.vppIfaceToPodMutex.Unlock()
	return nil
}

// addPod connects a Pod container to the network.
func (n *IPv4Net) addPod(event *podmanager.AddPod, txn controller.UpdateOperations) (change string, err error) {
	pod := n.PodManager.GetLocalPods()[event.Pod]

	// 1. try to allocate an IP address for this pod

	_, err = n.IPAM.AllocatePodIP(pod.ID, event.IPAMType, event.IPAMData)
	if err != nil {
		err = fmt.Errorf("failed to allocate new IP address for pod %v: %v", pod.ID, err)
		n.Log.Error(err)
		return "", err
	}

	// 2. enable IPv6

	// This is necessary for the latest docker where ipv6 is disabled by default.
	// OS assigns automatically ipv6 addr to a newly created TAP. We
	// try to reassign all IPs once interfaces is moved to a namespace.
	// Without explicitly enabled ipv6 we receive an error while moving
	// interface to a namespace.
	if !n.test {
		err = n.enableIPv6(pod)
		if err != nil {
			err = fmt.Errorf("failed to enable ipv6 in the namespace for pod %v: %v", pod.ID, err)
			n.Log.Error(err)
			return "", err
		}
	}

	// 3. prepare configuration for VPP <-> Pod connectivity

	config := n.podConnectivityConfig(pod)
	controller.PutAll(txn, config)

	// 4. update interface->pod map

	vppIface, _ := n.podInterfaceName(pod)
	n.vppIfaceToPodMutex.Lock()
	n.vppIfaceToPod[vppIface] = pod.ID
	n.vppIfaceToPodMutex.Unlock()

	// 5. fill event with the attributes of the configured pod connectivity for the CNI reply

	event.Interfaces = append(event.Interfaces, podmanager.PodInterface{
		HostName: podInterfaceHostName,
		IPAddresses: []*podmanager.IPWithGateway{
			{
				Version: podmanager.IPv4,
				Address: n.IPAM.GetPodIP(pod.ID),
				Gateway: n.IPAM.PodGatewayIP(),
			},
		},
	})
	_, anyDstNet, _ := net.ParseCIDR("0.0.0.0/0")
	event.Routes = append(event.Routes, podmanager.Route{
		Network: anyDstNet,
		Gateway: n.IPAM.PodGatewayIP(),
	})

	return "configure IPv4 connectivity", nil
}

// deletePod disconnects a Pod container from the network.
func (n *IPv4Net) deletePod(event *podmanager.DeletePod, txn controller.UpdateOperations) (change string, err error) {
	pod, podExists := n.PodManager.GetLocalPods()[event.Pod]
	if !podExists {
		return "", nil
	}
	ip := n.IPAM.GetPodIP(pod.ID)
	if ip == nil {
		return "", nil
	}

	// 1. prepare delete operations for transaction

	config := n.podConnectivityConfig(pod)
	controller.DeleteAll(txn, config)

	// 2. update interface->pod map

	vppIface, _ := n.podInterfaceName(pod)
	n.vppIfaceToPodMutex.Lock()
	delete(n.vppIfaceToPod, vppIface)
	n.vppIfaceToPodMutex.Unlock()

	// 3. release IP address of the POD

	err = n.IPAM.ReleasePodIP(pod.ID)
	if err != nil {
		return "", err
	}
	return "un-configure IPv4 connectivity", nil
}

// processNodeUpdateEvent reacts to an update of *another* node.
func (n *IPv4Net) processNodeUpdateEvent(nodeUpdate *nodesync.NodeUpdate, txn controller.UpdateOperations) (change string, err error) {
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
			connectivity, err := n.nodeConnectivityConfig(nodeUpdate.PrevState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					otherNodeID, err)
				n.Log.Error(err)
				return change, err
			}
			controller.DeleteAll(txn, connectivity)
			operationName = "disconnect"
		} else {
			// remove obsolete routes
			routes, err := n.routesToNode(nodeUpdate.PrevState)
			if err != nil {
				// treat as warning
				n.Log.Warnf("Failed to generate config for obsolete routes for node ID=%d: %v",
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
			connectivity, err := n.nodeConnectivityConfig(nodeUpdate.NewState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
					otherNodeID, err)
				n.Log.Error(err)
				return change, err
			}
			controller.PutAll(txn, connectivity)
			operationName = "connect"
		} else {
			// just add updated routes
			routes, err := n.routesToNode(nodeUpdate.NewState)
			if err != nil {
				err := fmt.Errorf("failed to generate config for obsolete routes for node ID=%d: %v",
					otherNodeID, err)
				n.Log.Error(err)
				return change, err
			}
			controller.PutAll(txn, routes)
			operationName = "update"
		}
	}

	// update BD if node was newly connected or disconnected
	if !n.ContivConf.GetRoutingConfig().UseL2Interconnect &&
		nodeHasIPAddress(nodeUpdate.PrevState) != nodeHasIPAddress(nodeUpdate.NewState) {

		key, bd := n.vxlanBridgeDomain()
		txn.Put(key, bd)
	}

	change = fmt.Sprintf("%s node ID=%d", operationName, otherNodeID)
	return change, nil
}

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity
// configuration in the host IP stack.
func (n *IPv4Net) cleanupVswitchConnectivity(txn controller.UpdateOperations) (change string, err error) {
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		// everything configured in the host will disappear automatically
		return
	}

	// un-configure VETHs
	key, _ := n.interconnectVethHost()
	txn.Delete(key)
	key, _ = n.interconnectVethVpp()
	txn.Delete(key)
	return "removing VPP<->Host VETHs", nil
}
