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
	"github.com/ligato/vpp-agent/clientv1/defaultplugins"
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

type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	vppLinuxTxnFactory          func() linux.DataChangeDSL
	vppDefaultPluginsTxnFactory func() defaultplugins.DataChangeDSL
	proxy                       kvdbproxy.Proxy
	govppChan                   *api.Channel
	swIfIndex                   ifaceidx.SwIfIndex
	configuredContainers        *containeridx.ConfigIndex

	// ipam module used by the CNI server
	ipam *ipam.IPAM

	// counter of connected containers. It is used for generating afpacket names
	// and assigned ip addresses.
	counter int

	// agent microservice label
	agentLabel string

	// unique identifier of the node
	uid uint8

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
	podIfIPPrefix                 = "10.2.1"
)

func newRemoteCNIServer(logger logging.Logger, vppLinuxTxnFactory func() linux.DataChangeDSL,
	vppDefaultPluginsTxnFactory func() defaultplugins.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govppChan *api.Channel, index ifaceidx.SwIfIndex, agentLabel string,
	config *Config, uid uint8) (*remoteCNIserver, error) {
	ipam, err := ipam.New(logger, uid, &config.IPAMConfig)
	if err != nil {
		return nil, err
	}
	server := &remoteCNIserver{
		Logger:                      logger,
		vppLinuxTxnFactory:          vppLinuxTxnFactory,
		vppDefaultPluginsTxnFactory: vppDefaultPluginsTxnFactory,
		proxy:                      proxy,
		configuredContainers:       configuredContainers,
		govppChan:                  govppChan,
		swIfIndex:                  index,
		agentLabel:                 agentLabel,
		uid:                        uid,
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

func (s *remoteCNIserver) close() {
	s.cleanupVswitchConnectivity()
}

func (s *remoteCNIserver) resync() error {
	s.Lock()
	defer s.Unlock()

	err := s.configureVswitchConnectivity()
	if err != nil {
		s.Logger.Error(err)
	}
	return err
}

// configureVswitchConnectivity configures basic vSwitch VPP connectivity to the host IP stack and to the other hosts.
// Namely, it configures:
//  - physical NIC interface + static routes to PODs on other hosts
//  - loopback instead of physical NIC if NIC is not found
//  - veth pair to host IP stack + AF_PACKET on VPP side
//  - default static route to the host via the veth pair
func (s *remoteCNIserver) configureVswitchConnectivity() error {

	s.Logger.Info("Applying basic vSwitch config.")
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
		config := s.specificConfigForCurrentNode()
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
			txn1 := s.vppLinuxTxnFactory().Put()

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
			txn1 := s.vppLinuxTxnFactory().Put()

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
				txn2 := s.vppLinuxTxnFactory().Put()
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

	// configure veths to host IP stack + AF_PACKET + default route to host
	vethHost := s.interconnectVethHost()
	vethVpp := s.interconnectVethVpp()
	interconnectAF := s.interconnectAfpacket()
	routeToHost := s.defaultRouteToHost()
	routeFromHost := s.routeFromHost()
	l4Features := s.l4Features(!s.disableTCPstack)

	// configure VETHs first
	txn3 := s.vppLinuxTxnFactory().Put().
		LinuxInterface(vethHost).
		LinuxInterface(vethVpp)

	err := txn3.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure AF_PACKET, routes and enable L4 features
	txn4 := s.vppLinuxTxnFactory().Put().
		VppInterface(interconnectAF).
		StaticRoute(routeToHost).
		LinuxRoute(routeFromHost).
		L4Features(l4Features)

	err = txn4.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// store changes for persisting
	changes[linux_intf.InterfaceKey(vethHost.Name)] = vethHost
	changes[linux_intf.InterfaceKey(vethVpp.Name)] = vethVpp
	changes[vpp_intf.InterfaceKey(interconnectAF.Name)] = interconnectAF
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

func (s *remoteCNIserver) specificConfigForCurrentNode() *OneNodeConfig {
	for _, oneNodeConfig := range s.nodeConfigs {
		if oneNodeConfig.NodeName == s.agentLabel {
			return &oneNodeConfig
		}
	}
	return nil
}

// cleanupVswitchConnectivity cleans up basic vSwitch VPP connectivity configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {
	vethHost := s.interconnectVethHost()
	vethVpp := s.interconnectVethVpp()

	txn := s.vppLinuxTxnFactory().Delete().
		LinuxInterface(vethHost.Name).
		LinuxInterface(vethVpp.Name)

	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Warn(err)
	}
}

// Add connects the container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)
	return s.configureContainerConnectivity(request)
}

func (s *remoteCNIserver) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Delete request received ", *request)
	return s.unconfigureContainerConnectivity(request)
}

// configureContainerConnectivity creates veth pair where
// one end is ns1 namespace, the other is in default namespace.
// the end in default namespace is connected to VPP using afpacket.
func (s *remoteCNIserver) configureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
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
	afpacket := s.afpacketFromRequest(request)
	tap := s.tapFromRequest(request)
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
	txn1 := s.vppLinuxTxnFactory().Put()
	if s.useTAPInterfaces {
		txn1.VppInterface(tap)
	} else {
		txn1.LinuxInterface(veth1).
			LinuxInterface(veth2)
	}
	err = txn1.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	if s.useTAPInterfaces {
		s.configureHostTAP(request, podIPNet)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}

	// Configure Pod-VPP connectivity.
	txn2 := s.vppLinuxTxnFactory().Put()

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

	// Add routes for the container.
	txn2.LinuxRoute(podLinkRoute).
		LinuxRoute(podDefaultRoute)

	// Configure connectivity via vpp-agent.
	err = txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	if !s.disableTCPstack {
		// Configure container proxy.
		err = s.configureContainerProxy(podIP, vppIf.Name)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}

	// If requested, disable TCP checksum offload on the eth0 veth/tap interface in the container.
	if s.tcpChecksumOffloadDisabled {
		err = s.disableTCPChecksumOffload(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
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
		return s.generateErrorResponse(err)
	}

	// Store configuration internally for other plugins to read.
	if s.configuredContainers != nil {
		extraArgs := s.parseExtraArgs(request.ExtraArguments)
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
	createdIfs := s.createdInterfaces(vppIf.Name, request.NetworkNamespace, podIPCIDR)
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
		return s.generateErrorResponse(err)
	}

	config, found := s.configuredContainers.LookupContainer(request.ContainerId)
	if !found {
		s.Logger.Warnf("cannot find configuration for container: %s\n", request.ContainerId)
		reply := &cni.CNIReply{
			Result: resultOk,
		}
		return reply, nil
	}

	// Delete all objects used for the pod connectivity in one transaction.
	txn := s.vppLinuxTxnFactory().Delete()

	txn.VppInterface(config.VppIf.Name)
	if !s.useTAPInterfaces {
		txn.LinuxInterface(config.Veth1.Name).
			LinuxInterface(config.Veth2.Name)
	}

	if !s.disableTCPstack {
		txn.VppInterface(config.Loopback.Name).
			StnRule(config.StnRule.RuleName).
			AppNamespace(config.AppNamespace.NamespaceId)
	} else {
		txn.StaticRoute(config.VppRoute.VrfId, config.VppRoute.DstIpAddr, config.VppRoute.NextHopAddr)
	}

	txn.Arp(config.VppARPEntry.Interface, config.VppARPEntry.IpAddress).
		LinuxArpEntry(config.PodARPEntry.Name)

	txn.LinuxRoute(config.PodLinkRoute.Name).
		LinuxRoute(config.PodDefaultRoute.Name)

	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// Check if the TAP interface was removed in the host stack as well.
	if s.useTAPInterfaces {
		/* TODO: add TAP support to linuxplugin */
		err = s.unconfigureHostTAP(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
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
		return s.generateErrorResponse(err)
	}

	if s.configuredContainers != nil {
		s.configuredContainers.UnregisterContainer(request.ContainerId)
	}

	err = s.ipam.ReleasePodIP(request.NetworkNamespace)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	reply := &cni.CNIReply{
		Result: resultOk,
	}
	return reply, nil
}

func (s *remoteCNIserver) generateErrorResponse(err error) (*cni.CNIReply, error) {
	reply := &cni.CNIReply{
		Result: resultErr,
		Error:  err.Error(),
	}
	return reply, err
}

func (s *remoteCNIserver) persistChanges(removedKeys []string, putChanges map[string]proto.Message) error {
	var err error
	// TODO rollback in case of error

	for _, key := range removedKeys {
		s.proxy.AddIgnoreEntry(key, datasync.Delete)
		_, err = s.proxy.Delete(key)
		if err != nil {
			return err
		}
	}

	for k, v := range putChanges {
		s.proxy.AddIgnoreEntry(k, datasync.Put)
		err = s.proxy.Put(k, v)
		if err != nil {
			return err
		}
	}
	return err
}

// createdInterfaces fills the structure containing data of created interfaces
// that is a part of reply to Add request
func (s *remoteCNIserver) createdInterfaces(ifName string, nsName string, podIP string) []*cni.CNIReply_Interface {
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

func (s *remoteCNIserver) parseExtraArgs(input string) map[string]string {
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
