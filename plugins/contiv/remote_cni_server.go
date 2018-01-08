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
	"sync"

	"git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/stn"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/model/l3"
	"golang.org/x/net/context"
)

// remoteCNIserver represents the remote CNI server instance. It accepts the requests from the contiv-CNI
// (acting as a GRPC-client) and configures the networking between VPP and the PODs.
type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	// VPP local client transaction factory
	vppTxnFactory func() linux.DataChangeDSL

	// kvdbsync plugin with ability to filter the change events
	proxy kvdbproxy.Proxy

	// GoVPP channel for direct binary API calls (if needed)
	govppChan *api.Channel

	// VPP interface index map
	swIfIndex ifaceidx.SwIfIndex

	// map of configured containers
	configuredContainers *containeridx.ConfigIndex

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// counter of connected containers. It is used for generating afpacket names and assigned IP addresses.
	// TODO: do not rely on counter, since it can overflow uint8 after many container add/remove transactions
	counter int

	// agent microservice label
	agentLabel string

	// unique identifier of the node
	nodeID uint8

	// node specific configuration
	nodeConfigs []OneNodeConfig

	// other configuration
	tcpChecksumOffloadDisabled bool

	// the variables ensures that add/del requests are processed
	// only when vswitch connectivity is configured
	vswitchConnectivityConfigured bool
	vswitchCond                   *sync.Cond

	// if the flag is true only veth without stn and tcp stack is configured
	disableTCPstack bool

	// if the flag is true, TAP interfaces are used instead of VETHs for VPP-Pod
	// interconnection.
	useTAPInterfaces bool

	// version of the TAP interface to use (if useTAPInterfaces==true)
	tapVersion uint8

	// Rx/Tx ring size for TAPv2
	tapV2RxRingSize uint16
	tapV2TxRingSize uint16
}

const (
	resultOk               uint32 = 0
	resultErr              uint32 = 1
	linuxIfMaxLen                 = 15
	afPacketNamePrefix            = "afpacket"
	tapNamePrefix                 = "tap"
	podNameExtraArg               = "K8S_POD_NAME"
	podNamespaceExtraArg          = "K8S_POD_NAMESPACE"
	vethHostEndLogicalName        = "veth-vpp1"
	vethHostEndName               = "vpp1"
	vethVPPEndLogicalName         = "veth-vpp2"
	vethVPPEndName                = "vpp2"
	tapHostEndName                = "vpp1"
	tapVPPEndLogicalName          = "tap-vpp2"
	tapVPPEndName                 = "vpp2"
	podIfIPPrefix                 = "10.2.1"
)

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linux.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govppChan *api.Channel, index ifaceidx.SwIfIndex, agentLabel string,
	config *Config, nodeID uint8) (*remoteCNIserver, error) {
	ipam, err := ipam.New(logger, nodeID, &config.IPAMConfig)
	if err != nil {
		return nil, err
	}
	server := &remoteCNIserver{
		Logger:                     logger,
		vppTxnFactory:              vppTxnFactory,
		proxy:                      proxy,
		configuredContainers:       configuredContainers,
		govppChan:                  govppChan,
		swIfIndex:                  index,
		agentLabel:                 agentLabel,
		nodeID:                     nodeID,
		ipam:                       ipam,
		nodeConfigs:                config.NodeConfig,
		tcpChecksumOffloadDisabled: config.TCPChecksumOffloadDisabled,
		useTAPInterfaces:           config.UseTAPInterfaces,
		tapVersion:                 config.TAPInterfaceVersion,
		tapV2RxRingSize:            config.TAPv2RxRingSize,
		tapV2TxRingSize:            config.TAPv2TxRingSize,
		disableTCPstack:            config.TCPstackDisabled,
	}
	server.vswitchCond = sync.NewCond(&server.Mutex)
	return server, nil
}

// resync is called by the plugin infra when the state of the GRPC server needs to be resynchronized,
// including the initialization phase
func (s *remoteCNIserver) resync() error {
	s.Lock()
	defer s.Unlock()

	err := s.configureVswitchConnectivity()
	if err != nil {
		s.Logger.Error(err)
	}

	return err
}

// close is called by the plugin infra when the CNI server needs to be stopped.
func (s *remoteCNIserver) close() {
	s.cleanupVswitchConnectivity()
}

// Add handles CNI Add request, connects the container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)
	return s.configureContainerConnectivity(request)
}

// Delete handles CNI Delete request, disconnects the container from the network.
func (s *remoteCNIserver) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Delete request received ", *request)
	return s.unconfigureContainerConnectivity(request)
}

// configureVswitchConnectivity configures base vSwitch VPP connectivity to the host IP stack and to the other hosts.
// Namely, it configures:
//  - physical NIC interface + static routes to PODs on other hosts
//  - veth pair to host IP stack + AF_PACKET on VPP side
//  - default static route to the host via the veth pair
func (s *remoteCNIserver) configureVswitchConnectivity() error {

	s.Logger.Info("Applying base vSwitch config.")
	s.Logger.Info("Existing interfaces: ", s.swIfIndex.GetMapping().ListNames())

	// only apply the config if resync hasn't done it already
	if _, _, found := s.swIfIndex.LookupIdx(s.interconnectAfpacketName()); found {
		s.Logger.Info("VSwitch connectivity is considered configured, skipping...")
		s.vswitchConnectivityConfigured = true
		s.vswitchCond.Broadcast()
		return nil
	}

	// used to persist the changes made by this function
	changes := map[string]proto.Message{}

	// configure physical NIC
	// NOTE that needs to be done as the first step, before adding any other interfaces to VPP to properly fnd the physical NIC name.
	if s.swIfIndex != nil {
		s.Logger.Info("Existing interfaces: ", s.swIfIndex.GetMapping().ListNames())

		// find physical NIC name
		nicName := ""
		config := s.loadNodeSpecificConfig()
		if config != nil && strings.Trim(config.MainVppInterfaceName, " ") != "" {
			nicName = config.MainVppInterfaceName
			s.Logger.Debugf("Physical NIC name taken from config: %v ", nicName)
		} else { //if not configured for this node -> use heuristic
			for _, name := range s.swIfIndex.GetMapping().ListNames() {
				if strings.HasPrefix(name, "local") || strings.HasPrefix(name, "loop") ||
					strings.HasPrefix(name, "host") || strings.HasPrefix(name, "tap") {
					continue
				} else {
					nicName = name
					break
				}
			}
			s.Logger.Debugf("Physical NIC not taken from config, but heuristic was used: %v ", nicName)
		}
		if nicName != "" {
			// configure the physical NIC and static routes to other hosts
			s.Logger.Info("Configuring physical NIC ", nicName)

			// add the NIC config into the transaction
			txn1 := s.vppTxnFactory().Put()

			nic, err := s.physicalInterface(nicName)
			if err != nil {
				return fmt.Errorf("Can't create structure for interface %v due to error: %v", nicName, err)
			}
			txn1.VppInterface(nic)
			changes[vpp_intf.InterfaceKey(nicName)] = nic

			// execute the config transaction
			err = txn1.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		} else {
			// configure loopback instead of physical NIC
			s.Logger.Debug("Physical NIC not found, configuring loopback instead.")

			// add the NIC config into the transaction
			txn1 := s.vppTxnFactory().Put()

			loop, err := s.physicalInterfaceLoopback()
			if err != nil {
				return fmt.Errorf("Can't create structure for loopback interface due to error: %v", err)
			}
			txn1.VppInterface(loop)
			changes[vpp_intf.InterfaceKey(loop.Name)] = loop

			// execute the config transaction
			err = txn1.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		}
		// configure VPP for other interfaces that were configured in contiv plugin yaml configuration
		if config != nil && len(config.OtherVPPInterfaces) > 0 {
			s.Logger.Debug("Configuring VPP for additional interfaces")

			// match existing interfaces and configuration settings and create VPP configuration objects
			interfaces := make(map[string]*vpp_intf.Interfaces_Interface)
			for _, name := range s.swIfIndex.GetMapping().ListNames() {
				for _, intIP := range config.OtherVPPInterfaces {
					if intIP.InterfaceName == name {
						interfaces[name] = s.physicalInterfaceWithCustomIPAddress(name, intIP.IP)
					}
				}
			}

			// send created configuration to VPP
			if len(interfaces) > 0 {
				txn2 := s.vppTxnFactory().Put()
				for intfName, intf := range interfaces {
					txn2.VppInterface(intf)
					changes[vpp_intf.InterfaceKey(intfName)] = intf
				}
				err := txn2.Send().ReceiveReply()
				if err != nil {
					s.Logger.Error(err)
					return err
				}
			}
		}
	} else {
		s.Logger.Warn("swIfIndex is NULL")
	}

	// configure veths to host IP stack + AF_PACKET or Tap + default route to host
	tapHost := s.interconnectTap()
	vethHost := s.interconnectVethHost()
	vethVpp := s.interconnectVethVpp()
	interconnectAF := s.interconnectAfpacket()
	routeToHost := s.defaultRouteToHost()
	routeFromHost := s.routeFromHost()
	l4Features := s.l4Features(!s.disableTCPstack)

	// configure VETHs first
	txn3 := s.vppTxnFactory().Put()

	if s.useTAPInterfaces {
		txn3.VppInterface(tapHost)
	} else {
		txn3.LinuxInterface(vethHost).
			LinuxInterface(vethVpp)
	}

	err := txn3.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if s.useTAPInterfaces {
		err = s.configureInterfconnectHostTap()
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	// configure AF_PACKET (if host is interconnected using vEth is used), routes and enable L4 features
	txn4 := s.vppTxnFactory().Put().
		StaticRoute(routeToHost).
		LinuxRoute(routeFromHost).
		L4Features(l4Features)

	if !s.useTAPInterfaces {
		txn4.VppInterface(interconnectAF)
	}

	err = txn4.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// store changes for persisting
	if s.useTAPInterfaces {
		changes[vpp_intf.InterfaceKey(tapHost.Name)] = tapHost
	} else {
		changes[linux_intf.InterfaceKey(vethHost.Name)] = vethHost
		changes[linux_intf.InterfaceKey(vethVpp.Name)] = vethVpp
		changes[vpp_intf.InterfaceKey(interconnectAF.Name)] = interconnectAF
	}

	changes[vpp_l3.RouteKey(routeToHost.VrfId, routeToHost.DstIpAddr, routeToHost.NextHopAddr)] = routeToHost
	changes[linux_l3.StaticRouteKey(routeFromHost.Name)] = routeFromHost
	changes[vpp_l4.FeatureKey()] = l4Features

	// persist the changes made by this function in ETCD
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	s.vswitchConnectivityConfigured = true
	s.vswitchCond.Broadcast()

	return err
}

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {
	vethHost := s.interconnectVethHost()
	vethVpp := s.interconnectVethVpp()
	tapHost := s.interconnectTap()

	// unconfigure VPP-host interconnect veth interfaces
	txn := s.vppTxnFactory().Delete()

	if s.useTAPInterfaces {
		txn.VppInterface(tapHost.Name)
	} else {
		txn.LinuxInterface(vethHost.Name).
			LinuxInterface(vethVpp.Name)
	}

	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Warn(err)
	}
}

// configureContainerConnectivity connects the POD to vSwitch VPP based on the CNI server configuration:
// either via virtual ethernet interface pair and AF_PACKET, or via TAP interface.
// It also configures the VPP TCP stack for this container, in case it would be LD_PRELOAD-ed.
func (s *remoteCNIserver) configureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {

	// do not connect any containers until the base vswitch config is successfully applied
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	var (
		vppIf     *vpp_intf.Interfaces_Interface
		podIfName string
	)

	changes := map[string]proto.Message{}
	s.counter++

	// Assign IP address for this POD.
	podIP, err := s.ipam.NextPodIP(request.NetworkNamespace)
	if err != nil {
		return nil, fmt.Errorf("Can't get new IP address for pod: %v", err)
	}
	podIPCIDR := podIP.String() + "/32"
	podIPNet := &net.IPNet{IP: podIP}
	podIPNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)

	// Prepare objects to be configured by the vpp-agent.
	veth1 := s.veth1FromRequest(request, podIPCIDR)
	veth2 := s.veth2FromRequest(request)
	afpacket := s.afpacketFromRequest(request, !s.disableTCPstack, podIPCIDR)
	tap := s.tapFromRequest(request, !s.disableTCPstack, podIPCIDR)
	vppRoute := s.vppRouteFromRequest(request, podIPCIDR)
	loop := s.loopbackFromRequest(request, podIP.String())
	appNs := s.appNamespaceFromRequest(request)
	if s.useTAPInterfaces {
		// configure TAP-based pod-VPP connectivity
		vppIf = tap
		podIfName = "FIXME" /* TODO: add TAP support to linuxplugin */
	} else {
		// configure VETHs+AF_PACKET-based pod-VPP connectivity
		vppIf = afpacket
		podIfName = veth1.Name
	}
	stnRule := s.stnRule(podIP, vppIf.Name)
	vppArp := s.vppArpEntry(vppIf.Name, podIP, s.hwAddrForContainer())
	podArp := s.podArpEntry(request, podIfName, vppIf.PhysAddress)
	podLinkRoute := s.podLinkRouteFromRequest(request, podIfName)
	podDefaultRoute := s.podDefaultRouteFromRequest(request, podIfName)

	// TODO: merge transactions into one once linuxplugin supports TAPs and all race-conditions are fixed.

	// Configure host-side interfaces first.
	txn1 := s.vppTxnFactory().Put()
	if s.useTAPInterfaces {
		txn1.VppInterface(tap)
	} else {
		txn1.LinuxInterface(veth1).
			LinuxInterface(veth2)
	}

	// Link scope route must be added before default route
	txn1.LinuxRoute(podLinkRoute)

	err = txn1.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	if s.useTAPInterfaces {
		s.configureHostTAP(request, podIPNet)
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
	}

	// Configure Pod-VPP connectivity.
	txn2 := s.vppTxnFactory().Put()

	if !s.useTAPInterfaces {
		txn2.VppInterface(afpacket)
	}

	if !s.disableTCPstack {
		// Configure VPPTCP stack.
		txn2.VppInterface(loop).
			StnRule(stnRule).
			AppNamespace(appNs)
	} else {
		// Configure route PodIP -> AF_PACKET / TAP.
		txn2.StaticRoute(vppRoute)
	}

	// Add ARP entries for both directions: VPP->container & container->VPP.
	txn2.Arp(vppArp).
		LinuxArpEntry(podArp)

	// Add default route for the container.
	txn2.LinuxRoute(podDefaultRoute)

	// Configure connectivity via vpp-agent.
	err = txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		//return s.generateCniErrorReply(err)
	}

	// If requested, disable TCP checksum offload on the eth0 veth/tap interface in the container.
	if s.tcpChecksumOffloadDisabled {
		err = s.disableTCPChecksumOffload(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
	}

	// Store changes for persisting
	changes[vpp_intf.InterfaceKey(vppIf.Name)] = vppIf
	if !s.useTAPInterfaces {
		changes[linux_intf.InterfaceKey(veth1.Name)] = veth1
		changes[linux_intf.InterfaceKey(veth2.Name)] = veth2
	}
	if !s.disableTCPstack {
		changes[vpp_intf.InterfaceKey(loop.Name)] = loop
		changes[stn.Key(stnRule.RuleName)] = stnRule
		changes[vpp_l4.AppNamespacesKey(appNs.NamespaceId)] = appNs
	} else {
		changes[vpp_l3.RouteKey(vppRoute.VrfId, vppRoute.DstIpAddr, vppRoute.NextHopAddr)] = vppRoute
	}
	changes[vpp_l3.ArpEntryKey(vppArp.Interface, vppArp.IpAddress)] = vppArp
	changes[linux_l3.StaticArpKey(podArp.Name)] = podArp
	changes[linux_l3.StaticRouteKey(podLinkRoute.Name)] = podLinkRoute
	changes[linux_l3.StaticRouteKey(podDefaultRoute.Name)] = podDefaultRoute

	// Persist the configuration.
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// Store configuration internally for other plugins to read.
	if s.configuredContainers != nil {
		extraArgs := s.parseCniExtraArgs(request.ExtraArguments)
		s.Logger.WithFields(logging.Fields{
			"PodName":      extraArgs[podNameExtraArg],
			"PodNamespace": extraArgs[podNamespaceExtraArg],
		}).Info("Adding into configured container index")

		// Group configuration of all objects associated with the pod.
		config := &containeridx.Config{
			PodName:      extraArgs[podNameExtraArg],
			PodNamespace: extraArgs[podNamespaceExtraArg],
			VppIf:        vppIf,
		}
		if !s.useTAPInterfaces {
			config.Veth1 = veth1
			config.Veth2 = veth2
		}
		if !s.disableTCPstack {
			config.Loopback = loop
			config.StnRule = stnRule
			config.AppNamespace = appNs
		} else {
			config.VppRoute = vppRoute
		}
		config.VppARPEntry = vppArp
		config.PodARPEntry = podArp
		config.PodLinkRoute = podLinkRoute
		config.PodDefaultRoute = podDefaultRoute

		// Register the container in the internal map.
		s.configuredContainers.RegisterContainer(request.ContainerId, config)
	}

	// Prepare response for CNI.
	createdIfs := s.generateCniInterfaceDetails(vppIf.Name, request.NetworkNamespace, podIPCIDR)
	reply := &cni.CNIReply{
		Result:     resultOk,
		Interfaces: createdIfs,
		Routes: []*cni.CNIReply_Route{
			{
				Dst: "0.0.0.0/0",
				Gw:  s.ipam.PodGatewayIP().String(),
			},
		},
	}
	return reply, err
}

// unconfigureContainerConnectivity disconnects the POD from vSwitch VPP.
func (s *remoteCNIserver) unconfigureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
	var err error
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	if s.configuredContainers == nil { /* should not be nil unless this is a unit test */
		err = fmt.Errorf("configuration was not stored for container: %s", request.ContainerId)
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	config, found := s.configuredContainers.LookupContainer(request.ContainerId)
	if !found {
		s.Logger.Warnf("cannot find configuration for container: %s\n", request.ContainerId)
		reply := &cni.CNIReply{
			Result: resultOk,
		}
		return reply, nil
	}

	// Delete ARPs, routes and STN rule.
	txn1 := s.vppTxnFactory().Delete()

	if !s.disableTCPstack {
		txn1.StnRule(config.StnRule.RuleName).
			AppNamespace(config.AppNamespace.NamespaceId)
	} else {
		txn1.StaticRoute(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr)
	}

	txn1.Arp(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress).
		LinuxArpEntry(config.PodARPEntry.Name)

	txn1.LinuxRoute(config.PodLinkRoute.Name).
		LinuxRoute(config.PodDefaultRoute.Name)

	err = txn1.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// Delete interfaces.
	txn2 := s.vppTxnFactory().Delete()

	txn2.VppInterface(config.VppIf.Name)
	if !s.useTAPInterfaces {
		txn2.LinuxInterface(config.Veth1.Name).
			LinuxInterface(config.Veth2.Name)
	}
	if !s.disableTCPstack {
		txn2.VppInterface(config.Loopback.Name)
	}

	err = txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	// Check if the TAP interface was removed in the host stack as well.
	if s.useTAPInterfaces {
		err = s.unconfigureHostTAP(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateCniErrorReply(err)
		}
	}

	// Collect keys to be removed from ETCD.
	removedKeys := []string{vpp_intf.InterfaceKey(config.VppIf.Name)}
	if !s.useTAPInterfaces {
		removedKeys = append(removedKeys,
			linux_intf.InterfaceKey(config.Veth1.Name),
			linux_intf.InterfaceKey(config.Veth2.Name))
	}
	if !s.disableTCPstack {
		removedKeys = append(removedKeys,
			vpp_intf.InterfaceKey(config.Loopback.Name),
			stn.Key(config.StnRule.RuleName),
			vpp_l4.AppNamespacesKey(config.AppNamespace.NamespaceId))
	} else {
		removedKeys = append(removedKeys,
			vpp_l3.RouteKey(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr))
	}
	removedKeys = append(removedKeys,
		vpp_l3.ArpEntryKey(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress),
		linux_l3.StaticArpKey(config.PodARPEntry.Name),
		linux_l3.StaticRouteKey(config.PodLinkRoute.Name),
		linux_l3.StaticRouteKey(config.PodDefaultRoute.Name))

	// Removed persisted configuration from ETCD.
	err = s.persistChanges(removedKeys, nil)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	if s.configuredContainers != nil {
		s.configuredContainers.UnregisterContainer(request.ContainerId)
	}

	err = s.ipam.ReleasePodIP(request.NetworkNamespace)
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}

	reply := &cni.CNIReply{
		Result: resultOk,
	}
	return reply, nil
}

// loadNodeSpecificConfig loads config specific for this node (given by its name).
func (s *remoteCNIserver) loadNodeSpecificConfig() *OneNodeConfig {
	for _, oneNodeConfig := range s.nodeConfigs {
		if oneNodeConfig.NodeName == s.agentLabel {
			return &oneNodeConfig
		}
	}
	return nil
}

// parseCniExtraArgs parses CNI extra arguments from a string into a map.
func (s *remoteCNIserver) parseCniExtraArgs(input string) map[string]string {
	res := map[string]string{}

	pairs := strings.Split(input, ";")
	for i := range pairs {
		kv := strings.Split(pairs[i], "=")
		if len(kv) == 2 {
			res[kv[0]] = kv[1]
		}
	}
	return res
}

// generateCniErrorReply generates CNI error reply with the proper result code and error message.
func (s *remoteCNIserver) generateCniErrorReply(err error) (*cni.CNIReply, error) {
	reply := &cni.CNIReply{
		Result: resultErr,
		Error:  err.Error(),
	}
	return reply, err
}

// generateCniInterfaceDetails fills the CNI reply with the data of an interface.
func (s *remoteCNIserver) generateCniInterfaceDetails(ifName string, nsName string, podIP string) []*cni.CNIReply_Interface {
	return []*cni.CNIReply_Interface{
		{
			Name:    ifName,
			Sandbox: nsName,
			IpAddresses: []*cni.CNIReply_Interface_IP{
				{
					Version: cni.CNIReply_Interface_IP_IPV4,
					Address: podIP,
					Gateway: s.ipam.PodGatewayIP().String(),
				},
			},
		},
	}
}

// persistChanges persists the changes passed as input arguments into ETCD.
func (s *remoteCNIserver) persistChanges(removedKeys []string, putChanges map[string]proto.Message) error {
	var err error
	// TODO rollback in case of error

	for _, key := range removedKeys {
		// ignore the next delete event on this key
		s.proxy.AddIgnoreEntry(key, datasync.Delete)

		// delete the key
		_, err = s.proxy.Delete(key)
		if err != nil {
			return err
		}
	}

	for k, v := range putChanges {
		// ignore the next put event on this key
		s.proxy.AddIgnoreEntry(k, datasync.Put)

		// put the key
		err = s.proxy.Put(k, v)
		if err != nil {
			return err
		}
	}
	return err
}
