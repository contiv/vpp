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
	"net"
	"strings"
	"sync"

	"git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"
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
	ipam *IPAM

	// generalSetup is true if the config that needs to be applied once (with the first container)
	// is configured
	generalSetup bool
	// counter of connected containers. It is used for generating afpacket names
	// and assigned ip addresses.
	counter int

	// agent microservice label
	agentLabel string
}

const (
	resultOk             uint32 = 0
	resultErr            uint32 = 1
	vethNameMaxLen              = 15
	podSubnetCIDR               = "10.1.0.0/16"
	podSubnetPrefix             = "10.1"
	podNetworkPrefixLen         = 24
	afPacketNamePrefix          = "afpacket"
	podNameExtraArg             = "K8S_POD_NAME"
	podNamespaceExtraArg        = "K8S_POD_NAMESPACE"
	nicNetworkPerfix            = "192.168.16"
	vethHostEndIP               = "192.168.17.24"
	vethVPPEndIP                = "192.168.17.25"
	vethHostEndName             = "v1"
	afPacketIPPrefix            = "10.2.1"
)

func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linux.DataChangeDSL, proxy kvdbproxy.Proxy,
	configuredContainers *containeridx.ConfigIndex, govpp govppmux.API, index ifaceidx.SwIfIndex, agentLabel string) *remoteCNIserver {
	//TODO: remove once all features are supported in Vpp Agent
	var govppChan *api.Channel
	if govpp != nil {
		govppChan, _ = govpp.NewAPIChannel()
	}
	return &remoteCNIserver{
		Logger:               logger,
		vppTxnFactory:        vppTxnFactory,
		proxy:                proxy,
		configuredContainers: configuredContainers,
		hostCalls:            &linuxCalls{},
		govppChan:            govppChan,
		swIfIndex:            index,
		agentLabel:           agentLabel,
		ipam:                 newIPAM(logger, podSubnetCIDR, podNetworkPrefixLen, agentLabel),
	}
}

// configureVswitchConnectivity configures basic vSwitch VPP connectivity to the host IP stack and to the other hosts.
// Namely, it configures:
//  - veth pair to host IP stack + AF_PACKET on VPP side
//  - default static route to the host via the veth pair
//  - physical NIC interface + static routes to PODs on other hosts
//  - loopback instead of physical NIC if NIC is not found
func (s *remoteCNIserver) configureVswitchConnectivity() error {

	s.Logger.Info("Applying basic vSwitch config.")

	// TODO: only do this config if resync hasn't done it already

	// used to persist the changes made by this function
	changes := map[string]proto.Message{}

	// configure veths to host IP stack + AF_PACKET + default route to host
	vethHost := s.interconnectVethHost()
	vethVpp := s.interconnectVethVpp()
	interconnectAF := s.interconnectAfpacket()
	route := s.defaultRouteToHost()

	txn := s.vppTxnFactory().Put().
		LinuxInterface(vethHost).
		LinuxInterface(vethVpp).
		VppInterface(interconnectAF).
		StaticRoute(route)

	err := txn.Send().ReceiveReply()
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

	// configure physical NIC
	if s.swIfIndex != nil {
		s.Logger.Debug("Existing interfaces: ", s.swIfIndex.GetMapping().ListNames())

		// find physical NIC name
		nicName := ""
		for _, name := range s.swIfIndex.GetMapping().ListNames() {
			if strings.HasPrefix(name, "local") || strings.HasPrefix(name, "loop") ||
				strings.HasPrefix(name, "host") || strings.HasPrefix(name, "tap") {
				continue
			} else {
				nicName = name
				break
			}
		}
		if nicName != "" {
			// configure the physical NIC and static routes to other hosts
			s.Logger.Debug("Configuring physical NIC ", nicName)

			// add the NIC config into the transaction
			txn1 := s.vppTxnFactory().Put()

			nic := s.physicalInterface(nicName)
			txn1.VppInterface(nic)
			changes[vpp_intf.InterfaceKey(nicName)] = nic

			// execute the config transaction
			err := txn1.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}

			// add static routes to other hosts into the transaction
			txn2 := s.vppTxnFactory().Put()

			var i uint8
			for i = 0; i < 255; i++ {
				// creates routes to all possible hosts
				// TODO: after proper IPAM implementation, only routes to existing hosts should be added
				if i != s.ipam.getPodNetworkSubnetID() {
					r := s.routeToOtherHost(i)
					txn2.StaticRoute(r)
					_, dstNet, _ := net.ParseCIDR(r.DstIpAddr)
					changes[l3.RouteKey(r.VrfId, dstNet, r.NextHopAddr)] = r
				}
			}

			// execute the config transaction
			err = txn2.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		} else {
			// configure loopback instead of physical NIC
			s.Logger.Debug("Physical NIC not found, configuring loopback instead.")

			// add the NIC config into the transaction
			txn := s.vppTxnFactory().Put()

			loop := s.physicalInterfaceLoopback()
			txn.VppInterface(loop)
			changes[vpp_intf.InterfaceKey(loop.Name)] = loop

			// execute the config transaction
			err := txn.Send().ReceiveReply()
			if err != nil {
				s.Logger.Error(err)
				return err
			}
		}
	}

	// persist the changes made by this function in ETCD
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	return nil
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
	defer s.Unlock()

	var (
		res        = resultOk
		errMsg     = ""
		createdIfs []*cni.CNIReply_Interface
	)

	if !s.generalSetup {
		// TODO: trigger this automatically after RESYNC is done
		err := s.configureVswitchConnectivity()
		if err != nil {
			s.Logger.Error(err)
			return s.generateErrorResponse(err)
		}
	}
	s.generalSetup = true

	changes := map[string]proto.Message{}
	s.counter++

	// assign IP address for this POD
	podIP := s.ipam.getNextPodIP() + "/32"

	veth1 := s.veth1FromRequest(request, podIP)
	veth2 := s.veth2FromRequest(request)
	afpacket := s.afpacketFromRequest(request)
	route := s.vppRouteFromRequest(request, podIP)

	s.WithFields(logging.Fields{"veth1": veth1, "veth2": veth2, "afpacket": afpacket, "route": route}).Info("Configuring")

	txn := s.vppTxnFactory().
		Put().
		LinuxInterface(veth1).
		LinuxInterface(veth2).
		VppInterface(afpacket)
	err := txn.Send().ReceiveReply()

	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	// adding route (container IP -> afPacket) in a separate transaction.
	// afpacket must be already configured
	err = s.vppTxnFactory().Put().StaticRoute(route).Send().ReceiveReply()
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	macAddr, err := s.retrieveContainerMacAddr(request.NetworkNamespace, request.InterfaceName)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}
	s.Debug("Container mac: ", macAddr)

	err = s.configureArpOnVpp(request, macAddr, podIP)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	afMac, err := s.getAfPacketMac("host-" + afpacket.Afpacket.HostIfName)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}
	s.Logger.Debug("AfPacket mac", afMac.String())

	err = s.configureArpInContainer(afMac, request)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	err = s.configureRoutesInContainer(request)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	changes[linux_intf.InterfaceKey(veth1.Name)] = veth1
	changes[linux_intf.InterfaceKey(veth2.Name)] = veth2
	changes[vpp_intf.InterfaceKey(afpacket.Name)] = afpacket
	err = s.persistChanges(nil, changes)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}
	createdIfs = s.createdInterfaces(veth1)

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
			Afpacket:     afpacket,
			Route:        route,
		})
	}

	reply := &cni.CNIReply{
		Result:     res,
		Error:      errMsg,
		Interfaces: createdIfs,
		Routes: []*cni.CNIReply_Route{
			{
				Dst: "0.0.0.0/0",
				Gw:  s.ipam.getPodGatewayIP(),
			},
		},
		Dns: []*cni.CNIReply_DNS{
			{
				Nameservers: []string{vethHostEndIP},
			},
		},
	}
	return reply, err
}

func (s *remoteCNIserver) unconfigureContainerConnectivity(request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Lock()
	defer s.Unlock()

	var (
		res    = resultOk
		errMsg = ""
	)

	veth1 := s.veth1NameFromRequest(request)
	veth2 := s.veth2NameFromRequest(request)
	afpacket := s.afpacketNameFromRequest(request)
	s.Info("Removing", []string{veth1, veth2, afpacket})

	err := s.vppTxnFactory().
		Delete().
		LinuxInterface(veth1).
		LinuxInterface(veth2).
		VppInterface(afpacket).
		Put().Send().ReceiveReply()

	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	err = s.persistChanges(
		[]string{linux_intf.InterfaceKey(veth1),
			linux_intf.InterfaceKey(veth2),
			vpp_intf.InterfaceKey(afpacket),
		},
		nil,
	)
	if err != nil {
		s.Logger.Error(err)
		return s.generateErrorResponse(err)
	}

	if s.configuredContainers != nil {
		s.configuredContainers.UnregisterContainer(request.ContainerId)
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
func (s *remoteCNIserver) createdInterfaces(veth *linux_intf.LinuxInterfaces_Interface) []*cni.CNIReply_Interface {
	return []*cni.CNIReply_Interface{
		{
			Name:    veth.Name,
			Sandbox: veth.Namespace.Name,
			IpAddresses: []*cni.CNIReply_Interface_IP{
				{
					Version: cni.CNIReply_Interface_IP_IPV4,
					Address: veth.IpAddresses[0],
					Gateway: s.ipam.getPodGatewayIP(),
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
