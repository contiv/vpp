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
	"bytes"
	"net"
	"strings"
	"sync"
	"time"

	"fmt"

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
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	"github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/linuxcalls"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	"golang.org/x/net/context"
)

type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	vppTxnFactory        func() linux.DataChangeDSL
	proxy                kvdbproxy.Proxy
	govppChan            *api.Channel
	swIfIndex            ifaceidx.SwIfIndex
	configuredContainers *containeridx.ConfigIndex
	// hostCalls encapsulates calls for managing linux networking
	hostCalls

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
}

const (
	resultOk             uint32 = 0
	resultErr            uint32 = 1
	linuxIfMaxLen               = 15
	afPacketNamePrefix          = "afpacket"
	tapNamePrefix               = "tap"
	podNameExtraArg             = "K8S_POD_NAME"
	podNamespaceExtraArg        = "K8S_POD_NAMESPACE"
	vethHostEndName             = "vpp1"
	vethVPPEndName              = "vpp2"
	podIfIPPrefix               = "10.2.1"
)

func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linux.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govppChan *api.Channel, index ifaceidx.SwIfIndex, agentLabel string, config *Config, uid uint8) (*remoteCNIserver, error) {
	ipam, err := ipam.New(logger, uid, &config.IPAMConfig)
	if err != nil {
		return nil, err
	}
	server := &remoteCNIserver{
		Logger:                     logger,
		vppTxnFactory:              vppTxnFactory,
		proxy:                      proxy,
		configuredContainers:       configuredContainers,
		hostCalls:                  &linuxCalls{},
		govppChan:                  govppChan,
		swIfIndex:                  index,
		agentLabel:                 agentLabel,
		uid:                        uid,
		ipam:                       ipam,
		nodeConfigs:                config.NodeConfig,
		tcpChecksumOffloadDisabled: config.TCPChecksumOffloadDisabled,
		useTAPInterfaces:           config.UseTAPInterfaces,
		tapVersion:                 config.TAPInterfaceVersion,
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
	if _, _, found := s.swIfIndex.LookupIdx(vethVPPEndName); found {
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
			txn := s.vppTxnFactory().Put()

			loop, err := s.physicalInterfaceLoopback()
			if err != nil {
				return fmt.Errorf("Can't create structure for loopback interface due to error: %v", err)
			}
			txn.VppInterface(loop)
			changes[vpp_intf.InterfaceKey(loop.Name)] = loop

			// execute the config transaction
			err = txn.Send().ReceiveReply()
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
				tx := s.vppTxnFactory().Put()
				for intfName, intf := range interfaces {
					tx.VppInterface(intf)
					changes[vpp_intf.InterfaceKey(intfName)] = intf
				}
				err := tx.Send().ReceiveReply()
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
	route := s.defaultRouteToHost()

	// configure linux interfaces
	txn1 := s.vppTxnFactory().Put().
		LinuxInterface(vethHost).
		LinuxInterface(vethVpp)

	err := txn1.Send().ReceiveReply()
	if err != nil {
		// ths transaction may fail if interfaces/routes are already configured, log only
		s.Logger.Warn(err)
	}

	// configure AF_PACKET for the veth - this transaction must be successful in order to continue
	txn2 := s.vppTxnFactory().Put().VppInterface(interconnectAF)

	err = txn2.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// wait until AF_PACKET is configured otherwise the route is ignored
	// note: this is workaround this should be handled in vpp-agent
	for i := 0; i < 10; i++ {
		if _, _, found := s.swIfIndex.LookupIdx(vethVPPEndName); found {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// configure default static route to the host
	txn3 := s.vppTxnFactory().Put().StaticRoute(route)
	err = txn3.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// store changes for persisting
	changes[linux_intf.InterfaceKey(vethHost.Name)] = vethHost
	changes[linux_intf.InterfaceKey(vethVpp.Name)] = vethVpp
	changes[vpp_intf.InterfaceKey(interconnectAF.Name)] = interconnectAF
	_, dstNet, _ := net.ParseCIDR(route.DstIpAddr)
	changes[l3.RouteKey(route.VrfId, dstNet, route.NextHopAddr)] = route

	// configure route to PODs on the host
	// TODO: we should persist this too, once this functionality is implemented in linuxplugin
	err = s.configureRouteOnHost()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// persist the changes made by this function in ETCD
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if !s.disableTCPstack {
		err = s.enableTCPSession()
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

	txn := s.vppTxnFactory().Delete().
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
		res             = resultOk
		errMsg          = ""
		createdIfs      []*cni.CNIReply_Interface
		nsIndex         uint32
		vppIfNamePrefix string
		vppIf           *vpp_intf.Interfaces_Interface
	)

	changes := map[string]proto.Message{}
	s.counter++

	// assign IP address for this POD
	podIP, err := s.ipam.NextPodIP(request.NetworkNamespace)
	if err != nil {
		return nil, fmt.Errorf("Can't get new IP address for pod: %v", err)
	}
	podIPCIDR := podIP.String() + "/32"
	podIPNet := &net.IPNet{IP: podIP}
	podIPNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)

	// Prepare objects to be configured by the vpp-agent.
	txn := s.vppTxnFactory().Put()
	veth1 := s.veth1FromRequest(request, podIPCIDR)
	veth2 := s.veth2FromRequest(request)
	afpacket := s.afpacketFromRequest(request)
	tap := s.tapFromRequest(request)
	route := s.vppRouteFromRequest(request, podIPCIDR)
	loop := s.loopbackFromRequest(request, podIP.String())

	// Configure either VETHs+AF_PACKET or TAP based on the configuration.
	if s.useTAPInterfaces {
		vppIf = tap
		vppIfNamePrefix = "tap-"
		s.WithFields(logging.Fields{"tap": tap /*, "route": route*/}).Info("Configuring")
		txn.VppInterface(tap)
	} else {
		vppIf = afpacket
		vppIfNamePrefix = "host-" + afpacket.Afpacket.HostIfName
		s.WithFields(logging.Fields{"veth1": veth1, "veth2": veth2, "afpacket": afpacket /*, "route": route*/}).Info("Configuring")
		txn.LinuxInterface(veth1).
			LinuxInterface(veth2).
			VppInterface(afpacket)
	}

	// + loopback interface for VPPTCP stack.
	if !s.disableTCPstack {
		txn.VppInterface(loop)
	}

	// Configure interfaces via vpp-agent.
	err = txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// TODO get rid of this sleep
	time.Sleep(500 * time.Millisecond)

	if s.useTAPInterfaces {
		// Configure TAP interface created in the host by VPP.
		tapTmpHostIfName := s.tapTmpHostNameFromRequest(request)
		tapHostIfName := s.tapHostNameFromRequest(request)
		containerNs := &linux_intf.LinuxInterfaces_Interface_Namespace{
			Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
			Filepath: request.NetworkNamespace,
		}
		nsMgmtCtx := linuxcalls.NewNamespaceMgmtCtx()

		//if s.tapVersion != 2 {
		// Move TAP into the namespace of the container.
		err = linuxcalls.SetInterfaceNamespace(nsMgmtCtx, tapTmpHostIfName,
			containerNs, s.Logger, nil)
		/* TODO: investigate the (non-fatal) error thrown here.
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
		*/
		//}

		// Switch to the namespace of the container.
		revertNs, err := linuxcalls.ToGenericNs(containerNs).SwitchNamespace(nsMgmtCtx, s.Logger)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}

		// Rename the interface from the temporary host-wide unique name to eth0.
		err = linuxcalls.RenameInterface(tapTmpHostIfName, tapHostIfName, nil)
		if err != nil {
			revertNs()
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}

		// Set TAP interface MAC address to make it compatible with STN.
		err = linuxcalls.SetInterfaceMac(tapHostIfName, s.macAddrForContainer(), nil)
		if err != nil {
			revertNs()
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}

		// Set TAP interface IP to that of the Pod.
		err = linuxcalls.AddInterfaceIP(tapHostIfName, podIPNet, nil)
		if err != nil {
			revertNs()
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}

		// Go back to the namespace of the vswitch.
		revertNs()
	}

	// Get index of the VPP interface connected to the Pod.
	var vppIfIndex uint32
	var vppIfFound bool
	err = nil
	if s.useTAPInterfaces {
		vppIfIndex, _, vppIfFound = s.swIfIndex.LookupIdx(tap.Name)
		if !vppIfFound {
			err = fmt.Errorf("cannot find interface details for: %s", tap.Name)
		}
	} else {
		vppIfIndex, _, vppIfFound = s.swIfIndex.LookupIdx(afpacket.Name)
		if !vppIfFound {
			err = fmt.Errorf("cannot find interface details for: %s", afpacket.Name)
		}
	}
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// Get details for the VPP interface connected to the Pod.
	vppIfDetails, err := s.getVppInterfaceDetails(vppIfNamePrefix, vppIfIndex)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}
	vppIfNameLen := bytes.IndexByte(vppIfDetails.InterfaceName, 0)
	vppIfName := string(vppIfDetails.InterfaceName[:vppIfNameLen])

	s.Logger.WithFields(logging.Fields{
		"ifIndex": vppIfIndex,
		"ifName":  vppIfName,
	}).Info("Found interface connecting Pod with VPP")

	if !s.disableTCPstack {
		err = s.setupStn(podIP.String(), vppIfIndex)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
		s.Logger.Info("Stn configured")

		nsIndex, err = s.addAppNamespace(request.ContainerId, s.loopbackNameFromRequest(request))
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
		s.Logger.Info("App namespace configured")
	} else {
		// Adding route (container IP -> afPacket) in a separate transaction.
		// afpacket/tap must be already configured.
		s.Logger.Info("Configuring static route:", route)
		err = s.vppTxnFactory().Put().StaticRoute(route).Send().ReceiveReply()
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}

	// Add ARP entry VPP->container.
	err = s.configureArpOnVpp(request, vppIfIndex, s.macAddrForContainer(), podIP)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// Add ARP entry container->VPP.
	vppIfMac := net.HardwareAddr(vppIfDetails.L2Address[:vppIfDetails.L2AddressLength])
	s.Logger.Debug("AfPacket/TAP mac", vppIfMac.String())
	err = s.configureArpInContainer(vppIfMac, request)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// Configure routes in the container.
	err = s.configureRoutesInContainer(request)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	if !s.disableTCPstack {
		// Some magical VPP bug workaround.
		err = s.fixPodToPodCommunication(podIP.String(), vppIfName)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}

	// Disable TCP checksum offload on the eth0 veth/tap interface in the container.
	// TODO: this is a temporary workaround, should be reverted once TCP checksum offload issues are resolved on VPP
	if s.tcpChecksumOffloadDisabled {
		err = s.disableTCPChecksumOffload(request)
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}

	// Persist the configuration.
	if s.useTAPInterfaces {
		changes[vpp_intf.InterfaceKey(tap.Name)] = tap
	} else {
		changes[linux_intf.InterfaceKey(veth1.Name)] = veth1
		changes[linux_intf.InterfaceKey(veth2.Name)] = veth2
		changes[vpp_intf.InterfaceKey(afpacket.Name)] = afpacket
	}
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
		s.configuredContainers.RegisterContainer(request.ContainerId, &containeridx.Config{
			PodName:      extraArgs[podNameExtraArg],
			PodNamespace: extraArgs[podNamespaceExtraArg],
			Veth1:        veth1,
			Veth2:        veth2,
			PodVppIf:     vppIf,
			NsIndex:      nsIndex,
		})
	}

	// Prepare response for CNI.
	createdIfs = s.createdInterfaces(vppIfName, request.NetworkNamespace, podIPCIDR)
	reply := &cni.CNIReply{
		Result:     res,
		Error:      errMsg,
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
	s.Lock()
	for !s.vswitchConnectivityConfigured {
		s.vswitchCond.Wait()
	}
	defer s.Unlock()

	var (
		err    error
		res    = resultOk
		errMsg = ""
	)

	veth1 := s.veth1NameFromRequest(request)
	veth2 := s.veth2NameFromRequest(request)
	afpacket := s.afpacketNameFromRequest(request)
	tap := s.tapNameFromRequest(request)
	loop := s.loopbackNameFromRequest(request)

	if s.useTAPInterfaces {
		s.Info("Removing", []string{tap, loop})
		err = s.vppTxnFactory().
			Delete().
			VppInterface(tap).
			VppInterface(loop).
			Put().Send().ReceiveReply()
	} else {
		s.Info("Removing", []string{veth1, veth2, afpacket, loop})
		err = s.vppTxnFactory().
			Delete().
			LinuxInterface(veth1).
			LinuxInterface(veth2).
			VppInterface(afpacket).
			VppInterface(loop).
			Put().Send().ReceiveReply()
	}
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	if s.useTAPInterfaces {
		err = s.persistChanges(
			[]string{vpp_intf.InterfaceKey(tap)},
			nil,
		)
	} else {
		err = s.persistChanges(
			[]string{linux_intf.InterfaceKey(veth1),
				linux_intf.InterfaceKey(veth2),
				vpp_intf.InterfaceKey(afpacket),
			},
			nil,
		)
	}
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
		Result: res,
		Error:  errMsg,
	}
	return reply, err
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
