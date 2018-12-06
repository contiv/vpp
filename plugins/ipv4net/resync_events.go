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
	"fmt"
	"net"
	"sort"

	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
)

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (n *IPv4Net) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {
	var wasErr error

	// (re-)load configuration specific to this node
	n.thisNodeConfig = n.loadNodeConfig(kubeStateData)

	// ipam
	if resyncCount == 1 {
		// No need to run resync for IPAM in run-time - IP address will not be allocated
		// to a local pod without the agent knowing about it. Also there is a risk
		// of a race condition - resync triggered shortly after Add/DelPod may work
		// with K8s state data that do not yet reflect the freshly added/removed pod.
		err := n.ipam.Resync(kubeStateData)
		if err != nil {
			wasErr = err
			n.Log.Error(err)
		}
	}

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
			if n.ipam.GetPodIP(pod.ID) == nil {
				continue
			}
			vppIfName, _ := n.podInterfaceName(pod)
			n.vppIfaceToPod[vppIfName] = pod.ID
		}
		n.vppIfaceToPodMutex.Unlock()
	}
	for _, pod := range n.PodManager.GetLocalPods() {
		if n.ipam.GetPodIP(pod.ID) == nil {
			continue
		}
		config := n.podConnectivityConfig(pod)
		controller.PutAll(txn, config)
	}

	n.Log.Infof("ipv4net plugin internal state after RESYNC: %s",
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

	if n.InSTNMode() {
		// configure STN connectivity
		n.configureSTNConnectivity(txn)
	}

	// configure inter-VRF routing
	n.configureVswitchVrfRoutes(txn)

	// enable IP neighbor scanning (to clean up old ARP entries)
	key, ipneigh := n.enabledIPNeighborScan()
	txn.Put(key, ipneigh)

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	if !n.test {
		n.subscribeVnetFibCounters()
	}

	// enable packet trace if requested (should be used for debugging only)
	if !n.test && n.config.EnablePacketTrace {
		n.executeDebugCLI("trace add dpdk-input 100000")
		n.executeDebugCLI("trace add virtio-input 100000")
	}

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (n *IPv4Net) configureVswitchNICs(event controller.Event, txn controller.ResyncOperations) error {
	// dump physical interfaces present on VPP
	nics, err := n.physicalIfsDump()
	if err != nil {
		n.Log.Errorf("Failed to dump physical interfaces: %v", err)
		return err
	}
	n.Log.Infof("Existing interfaces: %v", nics)

	// configure the main VPP NIC interface
	err = n.configureMainVPPInterface(event, nics, txn)
	if err != nil {
		n.Log.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if n.thisNodeConfig != nil && len(n.thisNodeConfig.OtherVPPInterfaces) > 0 {
		n.Log.Debug("Configuring VPP for additional interfaces")
		err = n.configureOtherVPPInterfaces(nics, txn)
		if err != nil {
			n.Log.Error(err)
			return err
		}
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (n *IPv4Net) configureMainVPPInterface(event controller.Event, physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
	var err error

	// 1. Determine the name of the main VPP NIC interface

	nicName := ""
	if n.thisNodeConfig != nil {
		// use name as as specified in node config YAML
		nicName = n.thisNodeConfig.MainVPPInterface.InterfaceName
		n.Log.Debugf("Physical NIC name taken from thisNodeConfig: %v ", nicName)
	}

	if nicName == "" {
		// name not specified in config, use heuristic - select first non-virtual interface (first by index)
		var nicIdxs []int
		for nicIdx := range physicalIfaces {
			nicIdxs = append(nicIdxs, int(nicIdx))
		}
		sort.Ints(nicIdxs)
	nextNIC:
		for _, nicIdx := range nicIdxs {
			physicalIface := physicalIfaces[uint32(nicIdx)]
			// exclude "other" (non-main) NICs
			if n.thisNodeConfig != nil {
				for _, otherNIC := range n.thisNodeConfig.OtherVPPInterfaces {
					if otherNIC.InterfaceName == physicalIface {
						continue nextNIC
					}
				}
			}

			// we have the main NIC
			nicName = physicalIface
			n.Log.Debugf("Physical NIC not taken from thisNodeConfig, but heuristic was used: %v ", nicName)
			break
		}
	}

	if nicName != "" {
		n.Log.Info("Configuring physical NIC ", nicName)
	}

	// 2. Determine the node IP address, default gateway IP and whether to use DHCP

	// 2.1 Read the configuration
	var nicStaticIPs []*nodesync.IPWithNetwork
	n.useDHCP = false
	if n.thisNodeConfig != nil && n.thisNodeConfig.MainVPPInterface.IP != "" {
		nicIP, nicIPNet, err := net.ParseCIDR(n.thisNodeConfig.MainVPPInterface.IP)
		if err != nil {
			n.Log.Errorf("Failed to parse main interface IP address from the config: %v", err)
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nicIP, Network: nicIPNet})
	} else if n.thisNodeConfig != nil && n.thisNodeConfig.MainVPPInterface.UseDHCP {
		n.useDHCP = true
	} else if n.ipam.NodeInterconnectDHCPEnabled() {
		// inherit DHCP from global setting
		n.useDHCP = true
	}

	// 2.2 STN case, IP address taken from the stolen interface
	if n.InSTNMode() {
		// determine name of the stolen interface
		var stolenIface string
		if n.thisNodeConfig != nil && n.thisNodeConfig.StealInterface != "" {
			stolenIface = n.thisNodeConfig.StealInterface
		} else if n.config.StealInterface != "" {
			stolenIface = n.config.StealInterface
		} // else go with the first stolen interface

		// obtain STN interface configuration
		var kernelDriver, pciAddr string
		nicStaticIPs, n.defaultGw, n.stnRoutes, kernelDriver, pciAddr, err = n.getStolenInterfaceConfig(stolenIface)
		if err != nil {
			n.Log.Errorf("Unable to get STN interface info: %v, disabling the interface.", err)
			return err
		}
		if nicName == "" && kernelDriver == vmxnet3KernelDriver {
			nicName = vmxnet3IfNameFromPCI(pciAddr)
			n.Log.Errorf("vmxnet3 interface name derived from the PCI address: %s", nicName)
		}
	}

	// 2.3 Set node IP address
	if n.useDHCP {
		// ip address is assigned by DHCP server
		n.Log.Infof("Configuring %v to use DHCP", nicName)
		if nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change); isNodeIPv4Change {
			// this resync event has been triggered to process DHCP event
			n.nodeIP = nodeIPv4Change.NodeIP
			n.nodeIPNet = nodeIPv4Change.NodeIPNet
			n.defaultGw = nodeIPv4Change.DefaultGw
		}
	} else if len(nicStaticIPs) > 0 {
		n.nodeIP = nicStaticIPs[0].Address
		n.nodeIPNet = nicStaticIPs[0].Network
		n.Log.Infof("Configuring %v to use %v", nicName, n.nodeIP)
	} else {
		nodeIP, nodeIPNet, err := n.ipam.NodeIPAddress(n.NodeSync.GetNodeID())
		if err != nil {
			n.Log.Error("Unable to generate node IP address.")
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nodeIP, Network: nodeIPNet})
		n.nodeIP = nodeIP
		n.nodeIPNet = nodeIPNet
		n.Log.Infof("Configuring %v to use %v", nicName, nodeIP.String())
	}
	// publish the node IP address to other nodes
	var nodeIPs []*nodesync.IPWithNetwork
	if len(n.nodeIP) > 0 {
		nodeIPs = append(nodeIPs, &nodesync.IPWithNetwork{Address: n.nodeIP, Network: n.nodeIPNet})
	}
	n.NodeSync.PublishNodeIPs(nodeIPs, nodesync.IPv4)

	// 3. Configure the main interface

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
		n.mainPhysicalIf = nicName
	} else {
		// configure loopback instead of the physical NIC
		n.Log.Debug("Physical NIC not found, configuring loopback instead.")
		key, loopback := n.loopbackInterface(nicStaticIPs)
		txn.Put(key, loopback)
		n.mainPhysicalIf = ""
	}

	// 4. For 2NICs non-DHCP case, configure the default route from the configuration

	if !n.InSTNMode() && !n.useDHCP {
		if n.mainPhysicalIf != "" && n.thisNodeConfig != nil && n.thisNodeConfig.Gateway != "" {
			// configure default gateway from the config file
			n.defaultGw = net.ParseIP(n.thisNodeConfig.Gateway)
			if n.defaultGw == nil {
				err = fmt.Errorf("failed to parse gateway IP address from the config (%s)",
					n.thisNodeConfig.Gateway)
				return err
			}
			key, defaultRoute := n.defaultRoute(n.defaultGw, nicName)
			txn.Put(key, defaultRoute)
		}
	}

	return nil
}

// configureOtherVPPInterfaces configure all physical interfaces defined in the config but the main one.
func (n *IPv4Net) configureOtherVPPInterfaces(physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
	n.otherPhysicalIfs = []string{}

	// match existing interfaces and build configuration
	interfaces := make(map[string]*interfaces.Interface)
	for _, physicalIface := range physicalIfaces {
		for _, ifaceCfg := range n.thisNodeConfig.OtherVPPInterfaces {
			if ifaceCfg.InterfaceName == physicalIface {
				ipAddr, ipNet, err := net.ParseCIDR(ifaceCfg.IP)
				if err != nil {
					err := fmt.Errorf("failed to parse IP address configured for interface %s: %v",
						ifaceCfg.InterfaceName, err)
					return err
				}
				key, iface := n.physicalInterface(physicalIface, []*nodesync.IPWithNetwork{
					{Address: ipAddr, Network: ipNet},
				})
				interfaces[key] = iface
			}
		}
	}

	// configure the interfaces on VPP
	if len(interfaces) > 0 {
		for key, iface := range interfaces {
			txn.Put(key, iface)
			n.otherPhysicalIfs = append(n.otherPhysicalIfs, iface.Name)
		}
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
	if n.config.UseTAPInterfaces {
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
	if !n.InSTNMode() {
		routesToHost = n.routesToHost(n.ipam.HostInterconnectIPInLinux())
	} else {
		routesToHost = n.routesToHost(n.nodeIP)
	}
	for key, route := range routesToHost {
		txn.Put(key, route)
	}

	// configure the route from the host to PODs
	var routeToPods *linux_l3.StaticRoute
	if !n.InSTNMode() {
		key, routeToPods = n.routePODsFromHost(n.ipam.HostInterconnectIPInVPP())
	} else {
		key, routeToPods = n.routePODsFromHost(n.defaultGw)
	}
	txn.Put(key, routeToPods)

	// route from the host to k8s service range from the host
	if n.config.RouteServiceCIDRToVPP {
		var routeToServices *linux_l3.StaticRoute
		if !n.InSTNMode() {
			key, routeToServices = n.routeServicesFromHost(n.ipam.HostInterconnectIPInVPP())
		} else {
			key, routeToServices = n.routeServicesFromHost(n.defaultGw)
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

	// bridge domain with VXLAN interfaces
	if !n.config.UseL2Interconnect {
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
	return nil
}
