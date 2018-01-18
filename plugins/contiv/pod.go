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
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/contiv/vpp/plugins/contiv/model/cni"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/stn"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/defaultplugins/l4plugin/model/l4"
	"github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/linuxcalls"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	l3_linux "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/linuxcalls"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxplugin/l3plugin/model/l3"
)

// disableTCPChecksumOffload disables TCP checksum offload on the eth0 in the container
func (s *remoteCNIserver) disableTCPChecksumOffload(request *cni.CNIRequest) error {
	// parse PID from the network namespace
	pid, err := s.getPIDFromNwNsPath(request.NetworkNamespace)
	if err != nil {
		return err
	}

	// execute the ethtool in the namespace of given PID
	cmdStr := fmt.Sprintf("nsenter -t %d -n ethtool --offload eth0 rx off tx off", pid)
	s.Logger.Infof("Executing CMD: %s", cmdStr)

	cmdArr := strings.Split(cmdStr, " ")
	cmd := exec.Command("nsenter", cmdArr[1:]...)

	// check the output of the exec
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Logger.Errorf("CMD exec returned error: %v", err)
		return err
	}
	s.Logger.Infof("CMD output: %s", output)

	return nil
}

// getPIDFromNwNsPath returns PID of the main process of the given network namespace path
func (s *remoteCNIserver) getPIDFromNwNsPath(ns string) (int, error) {
	strArr := strings.Split(ns, "/")
	if len(strArr) == 0 {
		return -1, fmt.Errorf("invalid network namespace - no slash char detected in %s", ns)
	}
	pid := -1
	for _, str := range strArr {
		if i, err := strconv.Atoi(str); err == nil {
			pid = i
			s.Logger.Infof("Container PID derived from NS %s: %d", ns, pid)
			break
		}
	}
	if pid == -1 {
		return -1, fmt.Errorf("unable to detect container PID from NS %s", ns)
	}
	return pid, nil
}

// configureHostTAP configures TAP interface created in the host by VPP.
// TODO: move to the linuxplugin
func (s *remoteCNIserver) configureHostTAP(request *cni.CNIRequest, podIPNet *net.IPNet, vppHw string) error {
	tapTmpHostIfName := s.tapTmpHostNameFromRequest(request)
	tapHostIfName := s.tapHostNameFromRequest(request)
	containerNs := &linux_intf.LinuxInterfaces_Interface_Namespace{
		Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	nsMgmtCtx := linuxcalls.NewNamespaceMgmtCtx()

	// Move TAP into the namespace of the container.
	err := linuxcalls.SetInterfaceNamespace(nsMgmtCtx, tapTmpHostIfName,
		containerNs, s.Logger, nil)
	/* TODO: investigate the (non-fatal) error thrown here.
	if err != nil {
		s.Logger.Error(err)
		return s.generateCniErrorReply(err)
	}
	*/

	// Switch to the namespace of the container.
	revertNs, err := linuxcalls.ToGenericNs(containerNs).SwitchNamespace(nsMgmtCtx, s.Logger)
	if err != nil {
		return err
	}
	defer revertNs()

	// Rename the interface from the temporary host-wide unique name to eth0.
	err = linuxcalls.RenameInterface(tapTmpHostIfName, tapHostIfName, nil)
	if err != nil {
		return err
	}

	// Set TAP interface MAC address to make it compatible with STN.
	err = linuxcalls.SetInterfaceMac(tapHostIfName, s.hwAddrForContainer(), nil)
	if err != nil {
		return err
	}

	// Set TAP interface IP to that of the Pod.
	err = linuxcalls.AddInterfaceIP(tapHostIfName, podIPNet, nil)
	if err != nil {
		return err
	}

	// FIXME: following items ARP + link scope route + default route should be configured by linux plugin
	dev, err := netlink.LinkByName(request.InterfaceName)
	if err != nil {
		return err
	}

	destination := net.IPNet{IP: s.ipam.PodGatewayIP(), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff)}
	macAddr, err := net.ParseMAC(vppHw)
	if err != nil {
		return err
	}

	err = l3_linux.AddArpEntry("pod-vpp arp", &netlink.Neigh{
		LinkIndex:    dev.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		Type:         1,
		IP:           s.ipam.PodGatewayIP(),
		HardwareAddr: macAddr,
	}, s.Logger, nil)
	if err != nil {
		return err
	}

	err = l3_linux.AddStaticRoute("pod-link-scope", &netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Dst:       &destination,
		Scope:     netlink.SCOPE_LINK,
	}, s.Logger, nil)
	if err != nil {
		return err
	}

	_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return err
	}

	return l3_linux.AddStaticRoute("pod default route", &netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Dst:       defaultDst,
		Gw:        s.ipam.PodGatewayIP(),
	}, s.Logger, nil)
}

// unconfigureHostTAP removes TAP interface from the host stack if it wasn't
// already done by VPP itself.
// TODO: move to the linuxplugin
func (s *remoteCNIserver) unconfigureHostTAP(request *cni.CNIRequest) error {
	tapHostIfName := s.tapHostNameFromRequest(request)
	containerNs := &linux_intf.LinuxInterfaces_Interface_Namespace{
		Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	nsMgmtCtx := linuxcalls.NewNamespaceMgmtCtx()

	// Switch to the namespace of the container.
	revertNs, err := linuxcalls.ToGenericNs(containerNs).SwitchNamespace(nsMgmtCtx, s.Logger)
	if err != nil {
		return err
	}
	defer revertNs()

	err = linuxcalls.DeleteInterface(tapHostIfName, nil)
	if err == nil {
		s.WithField("tap", tapHostIfName).Warn("TAP interface was not removed in the host stack by VPP")
	}

	return nil
}

func (s *remoteCNIserver) veth1NameFromRequest(request *cni.CNIRequest) string {
	return request.InterfaceName + request.ContainerId
}

func (s *remoteCNIserver) veth1HostIfNameFromRequest(request *cni.CNIRequest) string {
	return request.InterfaceName
}

func (s *remoteCNIserver) veth2NameFromRequest(request *cni.CNIRequest) string {
	return request.ContainerId
}

func (s *remoteCNIserver) veth2HostIfNameFromRequest(request *cni.CNIRequest) string {
	if len(request.ContainerId) > linuxIfMaxLen {
		return request.ContainerId[:linuxIfMaxLen]
	}
	return request.ContainerId
}

func (s *remoteCNIserver) afpacketNameFromRequest(request *cni.CNIRequest) string {
	return afPacketNamePrefix + s.veth2NameFromRequest(request)
}

func (s *remoteCNIserver) tapNameFromRequest(request *cni.CNIRequest) string {
	return tapNamePrefix + s.tapTmpHostNameFromRequest(request)
}

func (s *remoteCNIserver) tapTmpHostNameFromRequest(request *cni.CNIRequest) string {
	if len(request.ContainerId) > linuxIfMaxLen {
		return request.ContainerId[:linuxIfMaxLen]
	}
	return request.ContainerId
}

func (s *remoteCNIserver) tapHostNameFromRequest(request *cni.CNIRequest) string {
	return request.InterfaceName
}

func (s *remoteCNIserver) loopbackNameFromRequest(request *cni.CNIRequest) string {
	return "loop" + s.veth2NameFromRequest(request)
}

func (s *remoteCNIserver) ipAddrForPodVPPIf() string {
	return podIfIPPrefix + "." + strconv.Itoa(s.counter+1) + "/32"
}

func (s *remoteCNIserver) hwAddrForContainer() string {
	return "00:00:00:00:00:02"
}

func (s *remoteCNIserver) generateHwAddrForPodVPPIf() string {
	hwAddr := make(net.HardwareAddr, 6)
	rand.Read(hwAddr)
	hwAddr[0] = 2
	hwAddr[1] = 0xfe
	return hwAddr.String()
}

func (s *remoteCNIserver) veth1FromRequest(request *cni.CNIRequest, podIP string) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:        s.veth1NameFromRequest(request),
		Type:        linux_intf.LinuxInterfaces_VETH,
		Enabled:     true,
		HostIfName:  s.veth1HostIfNameFromRequest(request),
		PhysAddress: s.hwAddrForContainer(),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth2NameFromRequest(request),
		},
		IpAddresses: []string{podIP},
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
		HostIfName: s.veth2HostIfNameFromRequest(request),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth1NameFromRequest(request),
		},
	}
}

func (s *remoteCNIserver) afpacketFromRequest(request *cni.CNIRequest, configureContainerProxy bool, containerProxyIP string) *vpp_intf.Interfaces_Interface {
	af := &vpp_intf.Interfaces_Interface{
		Name:    s.afpacketNameFromRequest(request),
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: s.veth2HostIfNameFromRequest(request),
		},
		IpAddresses: []string{s.ipAddrForPodVPPIf()},
		PhysAddress: s.generateHwAddrForPodVPPIf(),
	}
	if configureContainerProxy {
		af.ContainerIpAddress = containerProxyIP
	}
	return af
}

func (s *remoteCNIserver) tapFromRequest(request *cni.CNIRequest, configureContainerProxy bool, containerProxyIP string) *vpp_intf.Interfaces_Interface {
	tap := &vpp_intf.Interfaces_Interface{
		Name:    s.tapNameFromRequest(request),
		Type:    vpp_intf.InterfaceType_TAP_INTERFACE,
		Enabled: true,
		Tap: &vpp_intf.Interfaces_Interface_Tap{
			HostIfName: s.tapTmpHostNameFromRequest(request),
		},
		IpAddresses: []string{s.ipAddrForPodVPPIf()},
		PhysAddress: s.generateHwAddrForPodVPPIf(),
	}
	if s.tapVersion == 2 {
		tap.Tap.Version = 2
		tap.Tap.RxRingSize = uint32(s.tapV2RxRingSize)
		tap.Tap.TxRingSize = uint32(s.tapV2TxRingSize)
	}
	if configureContainerProxy {
		tap.ContainerIpAddress = containerProxyIP
	}
	return tap
}

func (s *remoteCNIserver) loopbackFromRequest(request *cni.CNIRequest, loopIP string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        s.loopbackNameFromRequest(request),
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{loopIP},
	}
}

func (s *remoteCNIserver) vppRouteFromRequest(request *cni.CNIRequest, podIP string) *vpp_l3.StaticRoutes_Route {
	route := &vpp_l3.StaticRoutes_Route{
		DstIpAddr: podIP,
	}
	if s.useTAPInterfaces {
		route.OutgoingInterface = s.tapNameFromRequest(request)
	} else {
		route.OutgoingInterface = s.afpacketNameFromRequest(request)
	}
	return route
}

func (s *remoteCNIserver) stnRule(ipAddress net.IP, ifname string) *stn.StnRule {
	return &stn.StnRule{
		RuleName:  "rule-" + ifname,   //used as unique id for rules in etcd (managed by vpp-agent)
		IpAddress: ipAddress.String(), //ipv4
		Interface: ifname,
	}
}

func (s *remoteCNIserver) appNamespaceFromRequest(request *cni.CNIRequest) *vpp_l4.AppNamespaces_AppNamespace {
	return &vpp_l4.AppNamespaces_AppNamespace{
		NamespaceId: request.ContainerId,
		Secret:      42,
		Interface:   s.loopbackNameFromRequest(request),
	}
}

func (s *remoteCNIserver) vppArpEntry(podIfName string, podIP net.IP, macAddr string) *vpp_l3.ArpTable_ArpTableEntry {
	return &vpp_l3.ArpTable_ArpTableEntry{
		Interface:   podIfName,
		IpAddress:   podIP.String(),
		PhysAddress: macAddr,
		Static:      true,
	}
}

func (s *remoteCNIserver) podArpEntry(request *cni.CNIRequest, ifName string, macAddr string) *linux_l3.LinuxStaticArpEntries_ArpEntry {
	containerNs := &linux_l3.LinuxStaticArpEntries_ArpEntry_Namespace{
		Type:     linux_l3.LinuxStaticArpEntries_ArpEntry_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	return &linux_l3.LinuxStaticArpEntries_ArpEntry{
		Name:      request.ContainerId,
		Namespace: containerNs,
		Interface: ifName,
		Family:    netlink.FAMILY_V4, /* TODO: not nice, add enum to protobuf */
		State: &linux_l3.LinuxStaticArpEntries_ArpEntry_NudState{
			Type: linux_l3.LinuxStaticArpEntries_ArpEntry_NudState_PERMANENT,
		},
		IpAddr:    s.ipam.PodGatewayIP().String(),
		HwAddress: macAddr,
	}
}

func (s *remoteCNIserver) podLinkRouteFromRequest(request *cni.CNIRequest, ifName string) *linux_l3.LinuxStaticRoutes_Route {
	containerNs := &linux_l3.LinuxStaticRoutes_Route_Namespace{
		Type:     linux_l3.LinuxStaticRoutes_Route_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	return &linux_l3.LinuxStaticRoutes_Route{
		Name:      "LINK-" + request.ContainerId,
		Default:   false,
		Namespace: containerNs,
		Interface: ifName,
		Scope: &linux_l3.LinuxStaticRoutes_Route_Scope{
			Type: linux_l3.LinuxStaticRoutes_Route_Scope_LINK,
		},
		DstIpAddr: s.ipam.PodGatewayIP().String() + "/32",
	}
}

func (s *remoteCNIserver) podDefaultRouteFromRequest(request *cni.CNIRequest, ifName string) *linux_l3.LinuxStaticRoutes_Route {
	containerNs := &linux_l3.LinuxStaticRoutes_Route_Namespace{
		Type:     linux_l3.LinuxStaticRoutes_Route_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	return &linux_l3.LinuxStaticRoutes_Route{
		Name:      "DEFAULT-" + request.ContainerId,
		Default:   true,
		Namespace: containerNs,
		Interface: ifName,
		Scope: &linux_l3.LinuxStaticRoutes_Route_Scope{
			Type: linux_l3.LinuxStaticRoutes_Route_Scope_GLOBAL,
		},
		GwAddr: s.ipam.PodGatewayIP().String(),
	}
}
