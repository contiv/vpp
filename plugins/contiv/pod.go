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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	linux_intf "github.com/ligato/vpp-agent/plugins/linux/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linux/model/l3"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vpp/model/l3"
	vpp_l4 "github.com/ligato/vpp-agent/plugins/vpp/model/l4"
	"github.com/ligato/vpp-agent/plugins/vpp/model/stn"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// PodConfig groups applied configuration for a container
type PodConfig struct {
	// ID identifies the Pod
	ID string
	// PodName from the CNI request
	PodName string
	// PodNamespace from the CNI request
	PodNamespace string
	// Veth1 one end end of veth pair that is in the given container namespace.
	// Nil if TAPs are used instead.
	Veth1 *linux_intf.LinuxInterfaces_Interface
	// Veth2 is the other end of veth pair in the default namespace
	// Nil if TAPs are used instead.
	Veth2 *linux_intf.LinuxInterfaces_Interface
	// VppIf is AF_PACKET/TAP interface connecting pod to VPP
	VppIf *vpp_intf.Interfaces_Interface
	// PodTap is the host end of the tap connecting pod to VPP
	// Nil if TAPs are not used
	PodTap *linux_intf.LinuxInterfaces_Interface
	// Loopback interface associated with the pod.
	// Nil if VPP TCP stack is disabled.
	Loopback *vpp_intf.Interfaces_Interface
	// StnRule is STN rule used to "punt" any traffic via VETHs/TAPs with no match in VPP TCP stack.
	// Nil if VPP TCP stack is disabled.
	StnRule *stn.STN_Rule
	// AppNamespace is the application namespace associated with the pod.
	// Nil if VPP TCP stack is disabled.
	AppNamespace *vpp_l4.AppNamespaces_AppNamespace
	// VppARPEntry is ARP entry configured in VPP to route traffic from VPP to pod.
	VppARPEntry *vpp_l3.ArpTable_ArpEntry
	// PodARPEntry is ARP entry configured in the pod to route traffic from pod to VPP.
	PodARPEntry *linux_l3.LinuxStaticArpEntries_ArpEntry
	// VppRoute is the route from VPP to the container
	VppRoute *vpp_l3.StaticRoutes_Route
	// PodLinkRoute is the route from pod to the default gateway.
	PodLinkRoute *linux_l3.LinuxStaticRoutes_Route
	// PodDefaultRoute is the default gateway for the pod.
	PodDefaultRoute *linux_l3.LinuxStaticRoutes_Route
}

const podInterfaceName = "eth0" // name of the main interface in the POD network namespace

// podConfigToProto transform config structure to structure that will be persisted
// Beware: Intentionally not all data from config will be persisted, only necessary ones.
func podConfigToProto(cfg *PodConfig) *container.Persisted {
	persisted := &container.Persisted{}
	persisted.ID = cfg.ID
	persisted.PodName = cfg.PodName
	persisted.PodNamespace = cfg.PodNamespace
	if cfg.Veth1 != nil {
		persisted.Veth1Name = cfg.Veth1.Name
	}
	if cfg.Veth2 != nil {
		persisted.Veth2Name = cfg.Veth2.Name
	}
	if cfg.VppIf != nil {
		persisted.VppIfName = cfg.VppIf.Name
	}
	if cfg.PodTap != nil {
		persisted.PodTapName = cfg.PodTap.Name
	}
	if cfg.Loopback != nil {
		persisted.LoopbackName = cfg.Loopback.Name
	}
	if cfg.StnRule != nil {
		persisted.StnRuleName = cfg.StnRule.RuleName
	}
	if cfg.AppNamespace != nil {
		persisted.AppNamespaceID = cfg.AppNamespace.NamespaceId
	}
	if cfg.VppARPEntry != nil {
		persisted.VppARPEntryIP = cfg.VppARPEntry.IpAddress
		persisted.VppARPEntryInterface = cfg.VppARPEntry.Interface
	}
	if cfg.PodARPEntry != nil {
		persisted.PodARPEntryName = cfg.PodARPEntry.Name
	}
	if cfg.VppRoute != nil {
		persisted.VppRouteVrf = cfg.VppRoute.VrfId
		persisted.VppRouteNextHop = cfg.VppRoute.NextHopAddr
		persisted.VppRouteDest = cfg.VppRoute.DstIpAddr
	}
	if cfg.PodLinkRoute != nil {
		persisted.PodLinkRouteName = cfg.PodLinkRoute.Name
	}
	if cfg.PodDefaultRoute != nil {
		persisted.PodDefaultRouteName = cfg.PodDefaultRoute.Name
	}

	return persisted
}

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

func (s *remoteCNIserver) enableIPv6(request *cni.CNIRequest) error {
	// parse PID from the network namespace
	pid, err := s.getPIDFromNwNsPath(request.NetworkNamespace)
	if err != nil {
		return err
	}

	// execute the sysctl in the namespace of given PID
	cmdStr := fmt.Sprintf("nsenter -t %d -n sysctl net.ipv6.conf.all.disable_ipv6=0", pid)
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

func (s *remoteCNIserver) ipAddrForPodVPPIf(podIP string) string {
	tapPrefix, _ := ipv4ToUint32(*s.ipam.VPPIfIPPrefix())

	podAddr, _ := ipv4ToUint32(net.ParseIP(podIP))
	podMask, _ := ipv4ToUint32(net.IP(s.ipam.PodNetwork().Mask))
	podSuffix := podAddr &^ podMask

	tapAddress := uint32ToIpv4(tapPrefix + podSuffix)

	return net.IP.String(tapAddress) + "/32"
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
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  s.veth1HostIfNameFromRequest(request),
		PhysAddress: s.hwAddrForContainer(),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth2NameFromRequest(request),
		},
		IpAddresses: []string{podIP},
		Namespace: &linux_intf.LinuxInterfaces_Interface_Namespace{
			Name:     request.ContainerId,
			Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
			Filepath: request.NetworkNamespace,
		},
	}
}

func (s *remoteCNIserver) veth2FromRequest(request *cni.CNIRequest) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:       s.veth2NameFromRequest(request),
		Type:       linux_intf.LinuxInterfaces_VETH,
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: s.veth2HostIfNameFromRequest(request),
		Veth: &linux_intf.LinuxInterfaces_Interface_Veth{
			PeerIfName: s.veth1NameFromRequest(request),
		},
	}
}

func (s *remoteCNIserver) afpacketFromRequest(request *cni.CNIRequest, podIP string, configureContainerProxy bool, containerProxyIP string) *vpp_intf.Interfaces_Interface {
	af := &vpp_intf.Interfaces_Interface{
		Name:    s.afpacketNameFromRequest(request),
		Type:    vpp_intf.InterfaceType_AF_PACKET_INTERFACE,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetPodVrfID(),
		Afpacket: &vpp_intf.Interfaces_Interface_Afpacket{
			HostIfName: s.veth2HostIfNameFromRequest(request),
		},
		IpAddresses: []string{s.ipAddrForPodVPPIf(podIP)},
		PhysAddress: s.generateHwAddrForPodVPPIf(),
	}
	if configureContainerProxy {
		af.ContainerIpAddress = containerProxyIP
	}
	return af
}

func (s *remoteCNIserver) tapFromRequest(request *cni.CNIRequest, podIP string, configureContainerProxy bool, containerProxyIP string) *vpp_intf.Interfaces_Interface {
	tap := &vpp_intf.Interfaces_Interface{
		Name:    s.tapNameFromRequest(request),
		Type:    vpp_intf.InterfaceType_TAP_INTERFACE,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetPodVrfID(),
		Tap: &vpp_intf.Interfaces_Interface_Tap{
			HostIfName: s.tapTmpHostNameFromRequest(request),
		},
		IpAddresses: []string{s.ipAddrForPodVPPIf(podIP)},
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

func (s *remoteCNIserver) podTAP(request *cni.CNIRequest, podIPNet *net.IPNet) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:    "pod-" + s.tapTmpHostNameFromRequest(request),
		Type:    linux_intf.LinuxInterfaces_AUTO_TAP,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Tap: &linux_intf.LinuxInterfaces_Interface_Tap{
			TempIfName: s.tapTmpHostNameFromRequest(request),
		},
		HostIfName: s.tapHostNameFromRequest(request),
		Namespace: &linux_intf.LinuxInterfaces_Interface_Namespace{
			Name:     request.ContainerId,
			Type:     linux_intf.LinuxInterfaces_Interface_Namespace_FILE_REF_NS,
			Filepath: request.NetworkNamespace,
		},
		PhysAddress: s.hwAddrForContainer(),
		IpAddresses: []string{podIPNet.String()},
	}
}

func (s *remoteCNIserver) loopbackFromRequest(request *cni.CNIRequest, loopIP string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        s.loopbackNameFromRequest(request),
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{loopIP},
		Vrf:         s.GetPodVrfID(),
	}
}

func (s *remoteCNIserver) vppRouteFromRequest(request *cni.CNIRequest, podIP string) *vpp_l3.StaticRoutes_Route {
	route := &vpp_l3.StaticRoutes_Route{
		DstIpAddr: podIP,
		VrfId:     s.GetPodVrfID(),
	}
	if s.useTAPInterfaces {
		route.OutgoingInterface = s.tapNameFromRequest(request)
	} else {
		route.OutgoingInterface = s.afpacketNameFromRequest(request)
	}
	return route
}

func (s *remoteCNIserver) stnRule(ipAddress net.IP, ifname string) *stn.STN_Rule {
	return &stn.STN_Rule{
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

func (s *remoteCNIserver) vppArpEntry(podIfName string, podIP net.IP, macAddr string) *vpp_l3.ArpTable_ArpEntry {
	return &vpp_l3.ArpTable_ArpEntry{
		Interface:   podIfName,
		IpAddress:   podIP.String(),
		PhysAddress: macAddr,
		Static:      true,
	}
}

func (s *remoteCNIserver) podArpEntry(request *cni.CNIRequest, ifName string, macAddr string) *linux_l3.LinuxStaticArpEntries_ArpEntry {
	containerNs := &linux_l3.LinuxStaticArpEntries_ArpEntry_Namespace{
		Name:     request.ContainerId,
		Type:     linux_l3.LinuxStaticArpEntries_ArpEntry_Namespace_FILE_REF_NS,
		Filepath: request.NetworkNamespace,
	}
	return &linux_l3.LinuxStaticArpEntries_ArpEntry{
		Name:      request.ContainerId,
		Namespace: containerNs,
		Interface: ifName,
		IpFamily: &linux_l3.LinuxStaticArpEntries_ArpEntry_IpFamily{
			Family: linux_l3.LinuxStaticArpEntries_ArpEntry_IpFamily_IPV4,
		},
		State: &linux_l3.LinuxStaticArpEntries_ArpEntry_NudState{
			Type: linux_l3.LinuxStaticArpEntries_ArpEntry_NudState_PERMANENT,
		},
		IpAddr:    s.ipam.PodGatewayIP().String(),
		HwAddress: macAddr,
	}
}

func (s *remoteCNIserver) podLinkRouteFromRequest(request *cni.CNIRequest, ifName string) *linux_l3.LinuxStaticRoutes_Route {
	containerNs := &linux_l3.LinuxStaticRoutes_Route_Namespace{
		Name:     request.ContainerId,
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
		Name:     request.ContainerId,
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

// ipv4ToUint32 is simple utility function for conversion between IPv4 and uint32.
func ipv4ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("Ip address %v is not ipv4 address (or ipv6 convertible to ipv4 address)", ip)
	}
	var tmp uint32
	for _, bytePart := range ip {
		tmp = tmp<<8 + uint32(bytePart)
	}
	return tmp, nil
}

// uint32ToIpv4 is simple utility function for conversion between IPv4 and uint32.
func uint32ToIpv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4()
}

// verifyPodIP verifies that the specified namespace contains the interface with the specified IP address
// and waits until it is actually configured, or returns an error after timeout.
func (s *remoteCNIserver) verifyPodIP(nsPath string, ifName string, ip net.IP) error {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNs, err := netns.Get()
	if err != nil {
		s.Logger.Error("Error by getting current namespace", err)
		return err
	}
	defer origNs.Close()

	containerNs, err := netns.GetFromPath(nsPath)
	if err != nil {
		s.Logger.Error("Error by getting container namespace:", err)
		return err
	}
	defer containerNs.Close()

	err = netns.Set(containerNs)
	if err != nil {
		s.Logger.Error("Error by switching to container namespace:", err)
		return err
	}
	defer netns.Set(origNs)

	// loop until the interface can be found
	var link netlink.Link
	for i := 0; i < 100; i++ {
		link, err = netlink.LinkByName(ifName)
		if link != nil {
			break
		}
		s.Logger.Debugf("Link %s not yet found in the namespace %s, waiting", ifName, nsPath)
		time.Sleep(10 * time.Millisecond)
	}
	if link == nil {
		err := fmt.Errorf("cannot find the link %s in the namespace %s", ifName, nsPath)
		s.Logger.Error(err)
		return err
	}

	// loop until the interface IP can be found
	for i := 0; i < 100; i++ {
		addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err == nil {
			for _, a := range addr {
				if a.IP.Equal(ip) {
					s.Logger.Infof("IP address %s found on the %s interface in the namespace %s, check OK", ip, ifName, nsPath)
					return nil
				}
			}
			break
		}
		s.Logger.Debugf("IP address %s not yet found on the %s interface in the namespace %s, waiting", ip, ifName, nsPath)
		time.Sleep(10 * time.Millisecond)
	}

	err = fmt.Errorf("cannot find the IP address %s on the %s interface in the namespace %s", ip, ifName, nsPath)
	s.Logger.Error(err)
	return err
}
