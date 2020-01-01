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

package ipnet

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	customnetmodel "github.com/contiv/vpp/plugins/crd/handler/customnetwork/model"
	extifmodel "github.com/contiv/vpp/plugins/crd/handler/externalinterface/model"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/pkg/errors"
)

// Update is called for:
//   - AddPod and DeletePod (CNI)
//   - POD k8s state changes
//   - NodeUpdate for other nodes
//   - Shutdown event
func (n *IPNet) Update(event controller.Event, txn controller.UpdateOperations) (change string, err error) {

	// add pod from CNI
	if addPod, isAddPod := event.(*podmanager.AddPod); isAddPod {
		// main pod connectivity
		change, err := n.addPod(addPod, txn)
		if err != nil {
			return "", err
		}

		// if the pod metadata is already known and pod already has an IP address, progress with pod custom ifs update
		if podMeta, hadPodMeta := n.PodManager.GetPods()[addPod.Pod]; hadPodMeta {
			if podMeta.IPAddress != "" && hasContivCustomIfAnnotation(podMeta.Annotations) {
				err = n.EventLoop.PushEvent(&PodCustomIfUpdate{
					PodID:       addPod.Pod,
					Labels:      podMeta.Labels,
					Annotations: podMeta.Annotations,
				})
				return change, err
			}
		}
		// else mark for later custom interfaces handling (after we get KubeStateChange event with metadata of the pod)
		n.pendingAddPodCustomIf[addPod.Pod] = true

		return change, err
	}

	// del pod from CNI
	if delPod, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		// delete custom interfaces
		change, err := n.updatePodCustomIfs(delPod.Pod, txn, configDelete)
		if err != nil {
			return "", err
		}

		// delete main pod connectivity
		change2, err := n.deletePod(delPod, txn)
		if err != nil {
			return "", err
		}

		return strJoinIfNotEmpty(change, change2), err
	}

	// k8s data change
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {

		case podmodel.PodKeyword:
			var changes []string
			if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.SRv6Transport &&
				n.ContivConf.GetRoutingConfig().UseDX6ForSrv6NodetoNodeTransport {
				change, err := n.updateSrv6DX6NodeToNodeTunnel(ksChange, txn)
				changes = append(changes, change)
				if err != nil {
					return "", err
				}
			}

			n.cacheCustomNetworkInfo(ksChange)
			if err = n.pushPodCustomIfUpdateEventIfNeeded(ksChange); err != nil {
				return "", err
			}

			if ksChange.NewValue == nil { // pod already disconnected, now the record is also getting removed
				// release IP address of the POD
				pod := ksChange.PrevValue.(*podmodel.Pod)
				podID := podmodel.GetID(pod)
				err = n.IPAM.ReleasePodIPs(podID)
				if err != nil {
					return "", err
				}
				changes = append(changes, "deallocate POD IP")
			}
			return strJoinIfNotEmpty(changes...), nil

		case extifmodel.Keyword:
			// external interface data change
			if ksChange.NewValue != nil {
				extIf := ksChange.NewValue.(*extifmodel.ExternalInterface)
				if ksChange.PrevValue == nil {
					return n.updateExternalIf(extIf, txn, configAdd)
				}
				prevIf := ksChange.PrevValue.(*extifmodel.ExternalInterface)
				n.updateExternalIf(prevIf, txn, configDelete)
				return n.updateExternalIf(extIf, txn, configAdd)
			}
			extIf := ksChange.PrevValue.(*extifmodel.ExternalInterface)
			return n.updateExternalIf(extIf, txn, configDelete)

		case customnetmodel.Keyword:
			// custom network data change
			if ksChange.NewValue != nil {
				nw := ksChange.NewValue.(*customnetmodel.CustomNetwork)
				if ksChange.PrevValue == nil {
					return n.updateCustomNetwork(nw, txn, configAdd)
				}
				prevNw := ksChange.PrevValue.(*customnetmodel.CustomNetwork)
				prevNwState := n.customNetworks[prevNw.Name].clone()
				n.updateCustomNetwork(prevNw, txn, configDelete)
				n.customNetworks[prevNw.Name] = prevNwState
				return n.updateCustomNetwork(nw, txn, configAdd)
			}
			nw := ksChange.PrevValue.(*customnetmodel.CustomNetwork)
			return n.updateCustomNetwork(nw, txn, configDelete)
		}
	}

	// pod custom interfaces update
	if podCustomIfUpdate, isPodCustomIfUpdate := event.(*PodCustomIfUpdate); isPodCustomIfUpdate {
		return n.updatePodCustomIfs(podCustomIfUpdate.PodID, txn, configAdd)
	}

	// node info update
	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return n.processNodeUpdateEvent(nodeUpdate, txn)
	}

	// shutdown
	if _, isShutdown := event.(*controller.Shutdown); isShutdown {
		return n.cleanupVswitchConnectivity(txn)
	}

	return "", nil
}

func (n *IPNet) cacheCustomNetworkInfo(ksChange *controller.KubeStateChange) {
	newPod, _ := ksChange.NewValue.(*podmodel.Pod)
	prevPod, _ := ksChange.PrevValue.(*podmodel.Pod)
	if prevPod == nil && newPod != nil {
		n.cacheCustomNetworkInterfaces(podmodel.GetID(newPod), configAdd)
		return
	}
	if prevPod != nil && newPod == nil {
		n.cacheCustomNetworkInterfaces(podmodel.GetID(prevPod), configDelete)
		return
	}
	n.cacheCustomNetworkInterfaces(podmodel.GetID(prevPod), configDelete)
	n.cacheCustomNetworkInterfaces(podmodel.GetID(newPod), configAdd)
}

// updateSrv6DX6NodeToNodeTunnel updates ingress part of SRv6 node-to-node tunnel
// that leads directly to remote pod (DX6 end function)
func (n *IPNet) updateSrv6DX6NodeToNodeTunnel(ksChange *controller.KubeStateChange,
	txn controller.UpdateOperations) (change string, err error) {
	// get pod with assigned IP address (for cases of just assigning or just removing IP address to/from pod)
	var pod *podmodel.Pod
	newPod, _ := ksChange.NewValue.(*podmodel.Pod)
	prevPod, _ := ksChange.PrevValue.(*podmodel.Pod)
	if n.isParsableIPAddressAdded(newPod, prevPod) { // just got assigned IP address
		pod = ksChange.NewValue.(*podmodel.Pod)
	}
	if n.isParsableIPAddressAdded(prevPod, newPod) { // just got removed IP address
		pod = ksChange.PrevValue.(*podmodel.Pod)
	}
	if pod == nil { // ignore other state changes
		return "", nil
	}

	// adding ingress for tunnel to remote pods
	if _, isLocal := n.PodManager.GetLocalPods()[podmodel.GetID(pod)]; !isLocal {
		// ingress of tunnel to remote pod -> ignoring updates of local pods
		config, err := n.srv6NodeToNodeDX6PodTunnelIngress(pod)
		if err != nil {
			return "", errors.Wrapf(err, "can't add SRv6 node-to-node tunnel crossconnecting to pod %+v",
				podmodel.GetID(pod))
		}
		if n.isParsableIPAddressAdded(newPod, prevPod) { // addition of tunnel ingress
			addToTxn(config, txn)
			return "adding ingress configuration for SRv6 node-to-node tunnel (DX6 crossconnecting directly " +
				"to remote pod)", nil
		}
		// removal of tunnel ingress
		controller.DeleteAll(txn, config)
		return "removing ingress configuration for SRv6 node-to-node tunnel (DX6 crossconnecting directly to " +
			"remote pod)", nil
	}
	return "", nil
}

// isParsableIPAddressAdded checks whether parsable IP addresses was added to pod in new state
func (n *IPNet) isParsableIPAddressAdded(podWithNewState *podmodel.Pod, podWithPrevState *podmodel.Pod) bool {
	return podWithNewState != nil && net.ParseIP(podWithNewState.IpAddress) != nil &&
		(podWithPrevState == nil || net.ParseIP(podWithPrevState.IpAddress) == nil)
}

// pushPodCustomIfUpdateEventIfNeeded pushes PodCustomIfUpdate event to event loop when pod KubeState changes
// in specific manner. Otherwise it does nothing
func (n *IPNet) pushPodCustomIfUpdateEventIfNeeded(ksChange *controller.KubeStateChange) error {
	if ksChange.NewValue != nil {
		pod := ksChange.NewValue.(*podmodel.Pod)
		podID := podmodel.GetID(pod)

		// if there is a pending addPodCustomIfs operation for this pod,
		// and the pod already has an IP address assigned, process it now
		if _, pending := n.pendingAddPodCustomIf[podID]; pending && pod.IpAddress != "" {
			delete(n.pendingAddPodCustomIf, podID)
			if hasContivCustomIfAnnotation(pod.Annotations) {
				return n.EventLoop.PushEvent(&PodCustomIfUpdate{
					PodID:       podID,
					Labels:      pod.Labels,
					Annotations: pod.Annotations,
				})
			}
		}
	}
	return nil
}

// Revert is called for AddPod.
func (n *IPNet) Revert(event controller.Event) error {
	addPod := event.(*podmanager.AddPod)
	pod := n.PodManager.GetLocalPods()[addPod.Pod]
	n.IPAM.ReleasePodIPs(pod.ID)

	vppIface, _, _ := n.podInterfaceName(pod, "", "")
	n.vppIfaceToPodMutex.Lock()
	delete(n.vppIfaceToPod, vppIface)
	n.vppIfaceToPodMutex.Unlock()
	return nil
}

// addPod connects a Pod container to the network.
func (n *IPNet) addPod(event *podmanager.AddPod, txn controller.UpdateOperations) (change string, err error) {
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

	vppIface, _, _ := n.podInterfaceName(pod, "", "")
	n.vppIfaceToPodMutex.Lock()
	n.vppIfaceToPod[vppIface] = pod.ID
	n.vppIfaceToPodMutex.Unlock()

	// 5. fill event with the attributes of the configured pod connectivity for the CNI reply

	ipVersion := podmanager.IPv4
	if isIPv6(n.IPAM.GetPodIP(pod.ID).IP) {
		ipVersion = podmanager.IPv6
	}

	event.Interfaces = append(event.Interfaces, podmanager.PodInterface{
		HostName: podInterfaceHostName,
		IPAddresses: []*podmanager.IPWithGateway{
			{
				Version: ipVersion,
				Address: n.IPAM.GetPodIP(pod.ID),
				Gateway: n.IPAM.PodGatewayIP(DefaultPodNetworkName),
			},
		},
	})
	_, anyDstNet, _ := net.ParseCIDR(anyNetAddrForAF(n.IPAM.PodGatewayIP(DefaultPodNetworkName)))

	event.Routes = append(event.Routes, podmanager.Route{
		Network: anyDstNet,
		Gateway: n.IPAM.PodGatewayIP(DefaultPodNetworkName),
	})

	return "configure IP connectivity", nil
}

// deletePod disconnects a Pod container from the network.
func (n *IPNet) deletePod(event *podmanager.DeletePod, txn controller.UpdateOperations) (change string, err error) {
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

	vppIface, _, _ := n.podInterfaceName(pod, "", "")
	n.vppIfaceToPodMutex.Lock()
	delete(n.vppIfaceToPod, vppIface)
	n.vppIfaceToPodMutex.Unlock()
	return "un-configure IP connectivity", nil
}

// updatePodCustomIfs adds or deletes pod custom interfaces configuration (if requested by pod annotations).
func (n *IPNet) updatePodCustomIfs(podID podmodel.ID, txn controller.UpdateOperations,
	eventType configEventType) (change string, err error) {
	pod := n.PodManager.GetLocalPods()[podID]
	config, updateConfig := n.podCustomIfsConfig(pod, eventType)

	// no custom ifs for this pod
	if len(config) == 0 {
		return "", nil
	}

	if eventType != configDelete {
		controller.PutAll(txn, config)
		controller.PutAll(txn, updateConfig)
		return "configure custom pod interfaces", nil
	}
	controller.DeleteAll(txn, config)
	controller.PutAll(txn, updateConfig)
	return "un-configure custom pod interfaces", nil
}

// cacheCustomNetworkInterfaces puts custom network interfaces related information about given pod to
// custom network cache
func (n *IPNet) cacheCustomNetworkInterfaces(podID podmodel.ID, eventType configEventType) {
	pod, hadPodMeta := n.PodManager.GetPods()[podID]
	if !hadPodMeta {
		return // no metadata = no custom network interfaces
	}
	for _, customIfStr := range getContivCustomIfs(pod.Annotations) {
		customIf, err := parseCustomIfInfo(customIfStr)
		if err != nil {
			n.Log.Warnf("Error parsing custom interface definition (%v), skipping the interface %s "+
				"for caching information", err, customIf)
			continue
		}
		n.cacheCustomNetworkInterface(customIf.ifNet, nil, pod, nil,
			customIf.ifName, false, eventType != configDelete)
	}
}

// updateExternalIf adds or deletes external interface configuration.
func (n *IPNet) updateExternalIf(extIf *extifmodel.ExternalInterface, txn controller.UpdateOperations,
	eventType configEventType) (change string, err error) {

	for _, node := range extIf.Nodes {
		n.cacheCustomNetworkInterface(extIf.Network, nil, nil, extIf,
			node.VppInterfaceName, false, eventType != configDelete)
	}

	config, updateConfig, err := n.externalInterfaceConfig(extIf, eventType)
	if err != nil {
		return "", err
	}

	// no external interface config for this node
	if len(config) == 0 {
		return "", nil
	}

	if eventType != configDelete {
		controller.PutAll(txn, config)
		controller.PutAll(txn, updateConfig)
		return "configure external interfaces", nil
	}
	controller.DeleteAll(txn, config)
	controller.PutAll(txn, updateConfig)
	return "un-configure external interfaces", nil
}

// updateCustomNetwork adds or deletes custom network configuration.
func (n *IPNet) updateCustomNetwork(nw *customnetmodel.CustomNetwork, txn controller.UpdateOperations,
	eventType configEventType) (change string, err error) {

	config, err := n.customNetworkConfig(nw, eventType)
	if err != nil {
		return "", err
	}

	// no external interface config for this node
	if len(config) == 0 {
		return "", nil
	}

	if eventType != configDelete {
		controller.PutAll(txn, config)
		return "configure custom network", nil
	}
	controller.DeleteAll(txn, config)
	return "un-configure custom network", nil
}

// processNodeUpdateEvent reacts to an update of *another* node.
func (n *IPNet) processNodeUpdateEvent(nodeUpdate *nodesync.NodeUpdate, txn controller.UpdateOperations) (change string,
	err error) {
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
		connectivity, err := n.otherNodeConnectivityConfig(nodeUpdate.PrevState)
		if err != nil {
			err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
				otherNodeID, err)
			n.Log.Error(err)
			return change, err
		}
		controller.DeleteAll(txn, connectivity)
		operationName = "disconnect"
	}

	// add new configuration
	if nodeHasIPAddress(nodeUpdate.NewState) {
		connectivity, err := n.otherNodeConnectivityConfig(nodeUpdate.NewState)
		if err != nil {
			err := fmt.Errorf("failed to generate config for connectivity to node ID=%d: %v",
				otherNodeID, err)
			n.Log.Error(err)
			return change, err
		}
		controller.PutAll(txn, connectivity)
		operationName = "connect/update"
	}

	// update default pod network bridge domains if node was newly connected or disconnected
	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport &&
		nodeHasIPAddress(nodeUpdate.PrevState) != nodeHasIPAddress(nodeUpdate.NewState) {

		// update bridge domain of default pod network
		key, bd := n.vxlanBridgeDomain(DefaultPodNetworkName)
		txn.Put(key, bd)
	}

	// update bridge domains of custom networks
	if nodeHasIPAddress(nodeUpdate.PrevState) != nodeHasIPAddress(nodeUpdate.NewState) {
		for _, nw := range n.customNetworks {
			if nw.config != nil && nw.config.Type == customnetmodel.CustomNetwork_L2 {
				bdKey, bd := n.l2CustomNwBridgeDomain(nw)
				txn.Put(bdKey, bd)
			}
			if nw.config != nil && nw.config.Type == customnetmodel.CustomNetwork_L3 &&
				n.ContivConf.GetRoutingConfig().NodeToNodeTransport == contivconf.VXLANTransport {
				key, bd := n.vxlanBridgeDomain(nw.config.Name)
				txn.Put(key, bd)
			}
		}
	}

	change = fmt.Sprintf("%s node ID=%d", operationName, otherNodeID)
	return change, nil
}

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity
// configuration in the host IP stack.
func (n *IPNet) cleanupVswitchConnectivity(txn controller.UpdateOperations) (change string, err error) {
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

// strJoinIfNotEmpty joins provided strings with a separator.
func strJoinIfNotEmpty(strings ...string) string {
	res := ""
	for _, str := range strings {
		if str != "" {
			if res != "" {
				res = res + ", "
			}
			res = res + str
		}
	}
	return res
}
