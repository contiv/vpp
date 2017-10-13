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
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/ligato/cn-infra/logging"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"

	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"golang.org/x/net/context"
	"strconv"
	"strings"
	"sync"
)

type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	vppTxnFactory        func() linux.DataChangeDSL
	proxy                kvdbproxy.Proxy
	configuredContainers *containeridx.ConfigIndex

	// bdCreated is true if the bridge domain on the vpp for apackets is configured
	bdCreated bool
	// counter of connected containers. It is used for generating afpacket names
	// and assigned ip addresses.
	counter int
	// created afPacket that are in the bridge domain
	// map is used to support quick removal
	afPackets map[string]interface{}
}

const (
	resultOk             uint32 = 0
	resultErr            uint32 = 1
	vethNameMaxLen              = 15
	bdName                      = "bd1"
	bviName                     = "loop1"
	ipMask                      = "24"
	ipPrefix                    = "10.0.0"
	bviIP                       = ipPrefix + ".254"
	bviIPWithPrefix             = bviIP + "/" + ipMask
	afPacketNamePrefix          = "afpacket"
	podNameExtraArg             = "K8S_POD_NAME"
	podNamespaceExtraArg        = "K8S_POD_NAMESPACE"
	vethHostEndIP               = "192.168.16.24"
	vethVPPEndIP                = "192.168.16.25"
)

func newRemoteCNIServer(logger logging.Logger, vppTxnFactory func() linux.DataChangeDSL, proxy kvdbproxy.Proxy, configuredContainers *containeridx.ConfigIndex) *remoteCNIserver {
	return &remoteCNIserver{Logger: logger, vppTxnFactory: vppTxnFactory, afPackets: map[string]interface{}{}, proxy: proxy, configuredContainers: configuredContainers}
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

	changes := map[string]proto.Message{}
	s.counter++

	veth1 := s.veth1FromRequest(request)
	veth2 := s.veth2FromRequest(request)
	afpacket := s.afpacketFromRequest(request)

	// create entry in the afpacket map => add afpacket into bridge domain
	s.afPackets[afpacket.Name] = nil

	bd := s.bridgeDomain()

	s.WithFields(logging.Fields{"veth1": veth1, "veth2": veth2, "afpacket": afpacket, "bd": bd}).Info("Configuring")

	txn := s.vppTxnFactory().
		Put().
		LinuxInterface(veth1).
		LinuxInterface(veth2).
		VppInterface(afpacket)

	if !s.bdCreated {
		bvi := s.bviInterface()
		vethHost := s.interconnectVethHost()
		vethVpp := s.interconnectVethVpp()
		interconnectAF := s.interconnectAfpacket()

		txn.VppInterface(bvi).
			LinuxInterface(vethHost).
			LinuxInterface(vethVpp).
			VppInterface(interconnectAF)

		changes[vpp_intf.InterfaceKey(bvi.Name)] = bvi
		changes[vpp_intf.InterfaceKey(interconnectAF.Name)] = interconnectAF
		changes[linux_intf.InterfaceKey(vethHost.Name)] = vethHost
		changes[linux_intf.InterfaceKey(vethVpp.Name)] = vethVpp
	}

	err := txn.BD(bd).
		Send().ReceiveReply()

	if err == nil {
		s.bdCreated = true

		changes[linux_intf.InterfaceKey(veth1.Name)] = veth1
		changes[linux_intf.InterfaceKey(veth2.Name)] = veth2
		changes[vpp_intf.InterfaceKey(afpacket.Name)] = afpacket
		changes[l2.BridgeDomainKey(bd.Name)] = bd
		err = s.persistChanges(nil, changes)
		if err != nil {
			errMsg = err.Error()
			res = resultErr
			s.Logger.Error(err)
		} else {
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
				})
			}
		}

	} else {
		res = resultErr
		errMsg = err.Error()
		delete(s.afPackets, afpacket.Name)
		s.Logger.Error(err)
	}

	reply := &cni.CNIReply{
		Result:     res,
		Error:      errMsg,
		Interfaces: createdIfs,
		Routes: []*cni.CNIReply_Route{
			{
				Dst: "0.0.0.0/0",
				Gw:  bviIP,
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
	// remove afpacket from bridge domain
	delete(s.afPackets, afpacket)

	bd := s.bridgeDomain()

	err := s.vppTxnFactory().
		Delete().
		LinuxInterface(veth1).
		LinuxInterface(veth2).
		VppInterface(afpacket).
		Put().BD(bd).
		Send().ReceiveReply()

	if err == nil {
		err = s.persistChanges(
			[]string{linux_intf.InterfaceKey(veth1),
				linux_intf.InterfaceKey(veth2),
				vpp_intf.InterfaceKey(afpacket),
			},
			map[string]proto.Message{l2.BridgeDomainKey(bd.Name): bd},
		)
		if err != nil {
			errMsg = err.Error()
			res = resultErr
			s.Logger.Error(err)
		} else {
			if s.configuredContainers != nil {
				s.configuredContainers.UnregisterContainer(request.ContainerId)
			}
		}
	} else {
		res = resultErr
		errMsg = err.Error()
		s.Logger.Error(err)
	}

	reply := &cni.CNIReply{
		Result: res,
		Error:  errMsg,
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
					Gateway: bviIP,
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

//
// +-------------------------------------------------+
// |                                                 |
// |                         +----------------+      |
// |                         |     Loop1      |      |
// |      Bridge domain      |     BVI        |      |
// |                         +----------------+      |
// |    +------+       +------+                      |
// |    |  AF1 |       | AFn  |                      |
// |    |      |  ...  |      |                      |
// |    +------+       +------+                      |
// |      ^                                          |
// |      |                                          |
// +------|------------------------------------------+
//        v
// +------------+
// |            |
// | Veth2      |
// |            |
// +------------+
//        ^
//        |
// +------|------------+
// |  NS1 v            |
// |  +------------+   |
// |  |            |   |
// |  | Veth1      |   |
// |  |            |   |
// |  +------------+   |
// |                   |
// +-------------------+

func (s *remoteCNIserver) veth1NameFromRequest(request *cni.CNIRequest) string {
	return request.InterfaceName + request.ContainerId
}

func (s *remoteCNIserver) veth1HostIfNameFromRequest(request *cni.CNIRequest) string {
	return request.InterfaceName
}

func (s *remoteCNIserver) veth2NameFromRequest(request *cni.CNIRequest) string {
	if len(request.ContainerId) > vethNameMaxLen {
		return request.ContainerId[:vethNameMaxLen]
	}
	return request.ContainerId
}

func (s *remoteCNIserver) afpacketNameFromRequest(request *cni.CNIRequest) string {
	return afPacketNamePrefix + s.veth2NameFromRequest(request)
}

func (s *remoteCNIserver) ipAddrForContainer() string {
	return ipPrefix + "." + strconv.Itoa(s.counter) + "/" + ipMask
}

func (s *remoteCNIserver) veth1FromRequest(request *cni.CNIRequest) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       s.veth1NameFromRequest(request),
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: s.veth1HostIfNameFromRequest(request),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth2NameFromRequest(request),
		},
		IpAddresses: []string{s.ipAddrForContainer()},
		Namespace: &linux_intf.LinuxInterfaces_Interface_Namespace{
			Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
			Filepath: request.NetworkNamespace,
		},
	}
}

func (s *remoteCNIserver) veth2FromRequest(request *cni.CNIRequest) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       s.veth2NameFromRequest(request),
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: s.veth2NameFromRequest(request),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth1NameFromRequest(request),
		},
	}
}

func (s *remoteCNIserver) afpacketFromRequest(request *cni.CNIRequest) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:    s.afpacketNameFromRequest(request),
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: s.veth2NameFromRequest(request),
		},
	}
}

func (s *remoteCNIserver) bridgeDomain() *l2.BridgeDomains_BridgeDomain {
	var ifs = []*l2.BridgeDomains_BridgeDomain_Interfaces{
		{
			Name: bviName,
			BridgedVirtualInterface: true,
		}}

	for af := range s.afPackets {
		ifs = append(ifs, &l2.BridgeDomains_BridgeDomain_Interfaces{
			Name: af,
			BridgedVirtualInterface: false,
		})
	}

	return &l2.BridgeDomains_BridgeDomain{
		Name:                bdName,
		Flood:               true,
		UnknownUnicastFlood: true,
		Forward:             true,
		Learn:               true,
		ArpTermination:      false,
		MacAge:              0, /* means disable aging */
		Interfaces:          ifs,
	}
}

func (s *remoteCNIserver) bviInterface() *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        bviName,
		Enabled:     true,
		IpAddresses: []string{bviIPWithPrefix},
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
	}
}

func (s *remoteCNIserver) interconnectVethHost() *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       "vppv1",
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: "v1",
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: "vppv2",
		},
		IpAddresses: []string{vethHostEndIP + "/24"},
	}
}

func (s *remoteCNIserver) interconnectVethVpp() *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       "vppv2",
		Type:       linux_intf.LinuxInterfaces_VETH,
		Enabled:    true,
		HostIfName: "vppv2",
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: "vppv1",
		},
	}
}

func (s *remoteCNIserver) interconnectAfpacket() *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:    "afToHost",
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: "vppv2",
		},
		IpAddresses: []string{vethVPPEndIP + "/24"},
	}
}
