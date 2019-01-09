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

package ipv4net

import (
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (n *IPv4Net) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {
	var wasErr error

	// node <-> host, host -> pods
	err := n.configureVswitchConnectivity(event, txn)
	if err != nil {
		wasErr = err
		n.Log.Error(err)
	}

	// node <-> node
	err = n.otherNodesResync(txn)
	if err != nil {
		wasErr = err
		n.Log.Error(err)
	}

	// pods <-> vswitch
	if resyncCount == 1 {
		// refresh the map VPP interface logical name -> pod ID
		n.vppIfaceToPodMutex.Lock()
		n.vppIfaceToPod = make(map[string]podmodel.ID)
		for _, pod := range n.PodManager.GetLocalPods() {
			if n.IPAM.GetPodIP(pod.ID) == nil {
				continue
			}
			vppIfName, _ := n.podInterfaceName(pod)
			n.vppIfaceToPod[vppIfName] = pod.ID
		}
		n.vppIfaceToPodMutex.Unlock()
	}
	for _, pod := range n.PodManager.GetLocalPods() {
		if n.IPAM.GetPodIP(pod.ID) == nil {
			continue
		}
		config := n.podConnectivityConfig(pod)
		controller.PutAll(txn, config)
	}

	n.Log.Infof("IPv4Net plugin internal state after RESYNC: %s",
		n.internalState.StateToString())
	return wasErr
}

// configureVswitchConnectivity configures base vSwitch VPP connectivity.
// Namely, it configures:
//  - physical NIC interfaces
//  - connectivity to the host stack (Linux)
//  - one route in VPP for every host interface
//  - one route in the host stack to direct traffic destined to pods via VPP
//  - one route in the host stack to direct traffic destined to services via VPP
//  - inter-VRF routing
//  - IP neighbor scanning
func (n *IPv4Net) configureVswitchConnectivity(event controller.Event, txn controller.ResyncOperations) error {
	// configure physical NIC
	err := n.configureVswitchNICs(event, txn)
	if err != nil {
		n.Log.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	err = n.configureVswitchHostConnectivity(txn)
	if err != nil {
		n.Log.Error(err)
		return err
	}

	if n.ContivConf.InSTNMode() {
		// configure STN connectivity
		n.configureSTNConnectivity(txn)
	}

	// configure inter-VRF routing
	n.configureVswitchVrfRoutes(txn)

	// enable IP neighbor scanning (to clean up old ARP entries)
	if n.ContivConf.GetIPNeighborScanConfig().ScanIPNeighbors {
		key, ipneigh := n.enabledIPNeighborScan()
		txn.Put(key, ipneigh)
	}

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	if !n.test {
		n.subscribeVnetFibCounters()
	}

	// enable packet trace if requested (should be used for debugging only)
	if !n.test && n.ContivConf.EnablePacketTrace() {
		n.executeDebugCLI("trace add dpdk-input 100000")
		n.executeDebugCLI("trace add virtio-input 100000")
	}

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (n *IPv4Net) configureVswitchNICs(event controller.Event, txn controller.ResyncOperations) error {
	// configure the main VPP NIC interface
	err := n.configureMainVPPInterface(event, txn)
	if err != nil {
		n.Log.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if len(n.ContivConf.GetOtherVPPInterfaces()) > 0 {
		n.Log.Debug("Configuring VPP for additional interfaces")
		err = n.configureOtherVPPInterfaces(txn)
		if err != nil {
			n.Log.Error(err)
			return err
		}
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (n *IPv4Net) configureMainVPPInterface(event controller.Event, txn controller.ResyncOperations) error {
	// 1. Obtain the main interface name

	nicName := n.ContivConf.GetMainInterfaceName()
	if nicName != "" {
		n.Log.Info("Configuring physical NIC ", nicName)
	}

	// 2. Determine the node IP address

	var nicStaticIPs contivconf.IPsWithNetworks
	n.useDHCP = n.ContivConf.UseDHCP()
	if !n.useDHCP {
		nicStaticIPs = n.ContivConf.GetMainInterfaceConfiguredIPs()
		if len(nicStaticIPs) == 0 {
			nodeIP, nodeIPNet, err := n.IPAM.NodeIPAddress(n.NodeSync.GetNodeID())
			if err != nil {
				n.Log.Error("Unable to generate node IP address.")
				return err
			}
			nicStaticIPs = append(nicStaticIPs,
				&contivconf.IPWithNetwork{Address: nodeIP, Network: nodeIPNet})
		}
	} else {
		n.Log.Infof("Configuring %v to use DHCP", nicName)
	}
	if len(nicStaticIPs) > 0 {
		n.nodeIP = nicStaticIPs[0].Address
		n.nodeIPNet = nicStaticIPs[0].Network
		n.Log.Infof("Configuring %v to use %v", nicName, n.nodeIP)
	}
	if nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change); isNodeIPv4Change {
		// this resync event has been triggered to process DHCP event
		n.nodeIP = nodeIPv4Change.NodeIP
		n.nodeIPNet = nodeIPv4Change.NodeIPNet
	}

	// 3. Publish the node IP address to other nodes

	var nodeIPs contivconf.IPsWithNetworks
	if len(n.nodeIP) > 0 {
		nodeIPs = append(nodeIPs, &contivconf.IPWithNetwork{Address: n.nodeIP, Network: n.nodeIPNet})
	}
	n.NodeSync.PublishNodeIPs(nodeIPs, contivconf.IPv4)

	// 4. Configure the main interface

	if nicName != "" {
		// configure the physical NIC
		nicKey, nic := n.physicalInterface(nicName, nicStaticIPs)
		if n.useDHCP {
			// clear IP addresses
			nic.IpAddresses = []string{}
			nic.SetDhcpClient = true
			if !n.watchingDHCP {
				// start watching of DHCP notifications
				n.dhcpIndex.Watch("ipv4net", n.handleDHCPNotification)
				n.watchingDHCP = true
			}
		}
		txn.Put(nicKey, nic)
	} else {
		// configure loopback instead of the physical NIC
		n.Log.Debug("Physical NIC not found, configuring loopback instead.")
		key, loopback := n.loopbackInterface(nicStaticIPs)
		txn.Put(key, loopback)
	}

	// 5. For 2NICs non-DHCP case, configure the default route from the configuration

	if !n.ContivConf.InSTNMode() && !n.useDHCP && nicName != "" {
		defaultGw := n.ContivConf.GetStaticDefaultGW()
		if len(defaultGw) > 0 {
			key, defaultRoute := n.defaultRoute(defaultGw, nicName)
			txn.Put(key, defaultRoute)
		}
	}
	return nil
}

// configureOtherVPPInterfaces configure all physical interfaces defined in the config but the main one.
func (n *IPv4Net) configureOtherVPPInterfaces(txn controller.ResyncOperations) error {
	for _, physicalIface := range n.ContivConf.GetOtherVPPInterfaces() {
		key, iface := n.physicalInterface(physicalIface.InterfaceName, physicalIface.IPs)
		iface.SetDhcpClient = physicalIface.UseDHCP
		txn.Put(key, iface)
	}
	return nil
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (n *IPv4Net) configureVswitchHostConnectivity(txn controller.ResyncOperations) (err error) {
	var key string

	// list all IPs assigned to host interfaces
	n.hostIPs, err = n.hostLinkIPsDump()
	if err != nil {
		return err
	}

	// configure interfaces between VPP and the host network stack
	if n.ContivConf.GetInterfaceConfig().UseTAPInterfaces {
		// TAP interface
		key, vppTAP := n.interconnectTapVPP()
		txn.Put(key, vppTAP)
		key, hostVPP := n.interconnectTapHost()
		txn.Put(key, hostVPP)
	} else {
		// veth + AF_PACKET
		key, afpacket := n.interconnectAfpacket()
		txn.Put(key, afpacket)
		key, vethHost := n.interconnectVethHost()
		txn.Put(key, vethHost)
		key, vethVPP := n.interconnectVethVpp()
		txn.Put(key, vethVPP)
	}

	// configure routes from VPP to the host
	var routesToHost map[string]*l3.StaticRoute
	if !n.ContivConf.InSTNMode() {
		routesToHost = n.routesToHost(n.IPAM.HostInterconnectIPInLinux())
	} else {
		routesToHost = n.routesToHost(n.nodeIP)
	}
	for key, route := range routesToHost {
		txn.Put(key, route)
	}

	// configure the route from the host to PODs
	var routeToPods *linux_l3.StaticRoute
	if !n.ContivConf.InSTNMode() {
		key, routeToPods = n.routePODsFromHost(n.IPAM.HostInterconnectIPInVPP())
	} else {
		key, routeToPods = n.routePODsFromHost(n.stnGwIPForHost())
	}
	txn.Put(key, routeToPods)

	// route from the host to k8s service range from the host
	if n.ContivConf.GetRoutingConfig().RouteServiceCIDRToVPP {
		var routeToServices *linux_l3.StaticRoute
		if !n.ContivConf.InSTNMode() {
			key, routeToServices = n.routeServicesFromHost(n.IPAM.HostInterconnectIPInVPP())
		} else {
			key, routeToServices = n.routeServicesFromHost(n.stnGwIPForHost())
		}
		txn.Put(key, routeToServices)
	}

	return nil
}

// configureSTNConnectivity configures vswitch VPP to operate in the STN mode.
func (n *IPv4Net) configureSTNConnectivity(txn controller.ResyncOperations) {
	if len(n.nodeIP) > 0 {
		// STN rule
		key, stnrule := n.stnRule()
		txn.Put(key, stnrule)

		// proxy ARP for ARP requests from the host
		key, proxyarp := n.proxyArpForSTNGateway()
		txn.Put(key, proxyarp)

		// VPP ARP entry for the host interface
		key, arp := n.staticArpForSTNHostInterface()
		txn.Put(key, arp)
	}

	// STN routes
	stnRoutesVPP := n.stnRoutesForVPP()
	for key, route := range stnRoutesVPP {
		txn.Put(key, route)
	}
	stnRoutesHost := n.stnRoutesForHost()
	for key, route := range stnRoutesHost {
		txn.Put(key, route)
	}
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (n *IPv4Net) configureVswitchVrfRoutes(txn controller.ResyncOperations) {
	// routes from main towards POD VRF: PodSubnet + VPPHostSubnet
	routes := n.routesMainToPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// routes from POD towards main VRF: default route + VPPHostNetwork
	routes = n.routesPodToMainVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// add DROP routes into POD VRF to avoid loops: the same routes that point
	// from main VRF to POD VRF are installed into POD VRF as DROP, to not go back
	// into the main VRF via default route in case that PODs are not reachable
	routes = n.dropRoutesIntoPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}
}

// otherNodesResync re-synchronizes connectivity to other nodes.
func (n *IPv4Net) otherNodesResync(txn controller.ResyncOperations) error {
	// collect other node IDs and configuration for connectivity with each of them
	for _, node := range n.NodeSync.GetAllNodes() {
		// ignore for this node
		if node.Name == n.ServiceLabel.GetAgentLabel() {
			continue
		}

		// collect configuration for node connectivity
		if nodeHasIPAddress(node) {
			// generate configuration
			nodeConnectConfig, err := n.nodeConnectivityConfig(node)
			if err != nil {
				// treat as warning
				n.Log.Warnf("Failed to configure connectivity to node ID=%d: %v",
					node.ID, err)
				continue
			}
			for key, value := range nodeConnectConfig {
				txn.Put(key, value)
			}
		}
	}

	if !n.ContivConf.GetRoutingConfig().UseL2Interconnect {
		// bridge domain with VXLAN interfaces

		// bridge domain
		key, bd := n.vxlanBridgeDomain()
		txn.Put(key, bd)

		// BVI interface
		key, vxlanBVI, err := n.vxlanBVILoopback()
		if err != nil {
			n.Log.Error(err)
			return err
		}
		txn.Put(key, vxlanBVI)
	}

	// loopback with the gateway IP address for PODs. Also used as the unnumbered IP for the POD facing interfaces.
	key, lo := n.podGwLoopback()
	txn.Put(key, lo)

	return nil
}
