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
	"os/exec"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/contiv/vpp/plugins/contiv/bin_api/session"
	"github.com/contiv/vpp/plugins/contiv/bin_api/stn"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/ip"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/bin_api/vpe"
	vpp_intf "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/l3plugin/model/l3"
	linux_intf "github.com/ligato/vpp-agent/plugins/linuxplugin/ifplugin/model/interfaces"
	"github.com/vishvananda/netlink"
)

func (s *remoteCNIserver) configureRoutesInContainer(request *cni.CNIRequest) error {
	return s.WithNetNSPath(request.NetworkNamespace, func(netns ns.NetNS) error {
		destination := ipToIPNet(s.ipam.PodGatewayIP())
		defaultNextHop := s.ipam.PodGatewayIP()
		dev, err := s.LinkByName(request.InterfaceName)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		err = s.RouteAdd(&netlink.Route{
			LinkIndex: dev.Attrs().Index,
			Dst:       &destination,
			Scope:     netlink.SCOPE_LINK,
		})
		if err != nil {
			s.Logger.Error(err)
			return err
		}
		return s.AddDefaultRoute(defaultNextHop, dev)
	})
}

func (s *remoteCNIserver) retrieveContainerMacAddr(namespace string, ifname string) ([]byte, error) {

	var macAddr []byte
	err := s.WithNetNSPath(namespace, func(netNS ns.NetNS) error {
		link, err := s.LinkByName(ifname)
		if err != nil {
			return err
		}
		macAddr = link.Attrs().HardwareAddr
		return err

	})
	return macAddr, err

}

func (s *remoteCNIserver) configureArpOnVpp(request *cni.CNIRequest, macAddr []byte, podIP net.IP) error {

	ifName := s.afpacketNameFromRequest(request)
	if s.swIfIndex == nil {
		s.Logger.Warn("SwIfIndex is not available")
		return nil
	}
	idx, _, exists := s.swIfIndex.LookupIdx(ifName)
	if !exists {
		return fmt.Errorf("afpacket %v doesn't exist", ifName)
	}

	req := &ip.IPNeighborAddDel{
		SwIfIndex:  idx,
		IsAdd:      1,
		MacAddress: macAddr,
		IsNoAdjFib: 1,
		DstAddress: []byte(podIP.To4()),
	}

	reply := &ip.IPNeighborAddDelReply{}
	err := s.govppChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("Adding arp entry returned non zero error code (%v)", reply.Retval)
	}
	return err
}

func (s *remoteCNIserver) configureArpInContainer(macAddr net.HardwareAddr, request *cni.CNIRequest) error {

	gw := s.ipam.PodGatewayIP()
	return s.WithNetNSPath(request.NetworkNamespace, func(ns ns.NetNS) error {
		link, err := s.LinkByName(request.InterfaceName)
		if err != nil {
			return err
		}
		return s.NeighAdd(&netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       netlink.FAMILY_V4,
			State:        netlink.NUD_PERMANENT,
			Type:         1,
			IP:           gw,
			HardwareAddr: macAddr,
		})

	})
}

func (s *remoteCNIserver) getAfPacketMac(afPacket string) (net.HardwareAddr, error) {
	req := &interfaces.SwInterfaceDump{
		NameFilter:      []byte(afPacket),
		NameFilterValid: 1,
	}
	var mac net.HardwareAddr
	found := false

	if s.govppChan == nil {
		s.Logger.Warn("GoVpp not available")
		return mac, nil
	}

	ctx := s.govppChan.SendMultiRequest(req)

	for {
		ifDetails := &interfaces.SwInterfaceDetails{}
		stop, err := ctx.ReceiveReply(ifDetails)
		if stop {
			break // break out of the loop
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(string(ifDetails.InterfaceName), afPacket) {
			mac = net.HardwareAddr(ifDetails.L2Address[:ifDetails.L2AddressLength])
			found = true
		}
	}

	if !found {
		return nil, fmt.Errorf("unable to look up MAC for if %v", afPacket)
	}
	return mac, nil

}

func (s *remoteCNIserver) setupStn(podIP string, ifname string) error {
	req := &stn.StnAddDelRule{
		IsIP4:     1,
		IsAdd:     1,
		IPAddress: net.ParseIP(podIP).To4(),
	}

	if s.swIfIndex == nil {
		return fmt.Errorf("unable to lookup interface %v", ifname)
	}

	idx, _, found := s.swIfIndex.LookupIdx(ifname)
	if !found {
		return fmt.Errorf("interface %v not found", ifname)
	}

	req.SwIfIndex = idx

	if s.govppChan == nil {
		s.Logger.Warn("GoVpp not available")
		return nil
	}

	reply := stn.StnAddDelRuleReply{}

	err := s.govppChan.SendRequest(req).ReceiveReply(&reply)

	if reply.Retval != 0 {
		return fmt.Errorf("adding stn rule returned non-zero return code: %d", reply.Retval)
	}

	return err
}

func (s *remoteCNIserver) addAppNamespace(podNamespace string, ifname string) (nsIndex uint32, err error) {
	req := &session.AppNamespaceAddDel{
		Secret:         42,
		NamespaceID:    []byte(podNamespace),
		NamespaceIDLen: uint8(len(podNamespace)),
	}

	if s.swIfIndex == nil {
		return 0, fmt.Errorf("unable to lookup interface %v", ifname)
	}

	idx, _, found := s.swIfIndex.LookupIdx(ifname)
	if !found {
		return 0, fmt.Errorf("interface %v not found", ifname)
	}

	req.SwIfIndex = idx

	if s.govppChan == nil {
		s.Logger.Warn("GoVpp not available")
		return 0, nil
	}

	reply := session.AppNamespaceAddDelReply{}

	err = s.govppChan.SendRequest(req).ReceiveReply(&reply)

	if reply.Retval != 0 {
		return 0, fmt.Errorf("adding app namespace returned non-zero return code: %d", reply.Retval)
	}

	return reply.AppnsIndex, err
}

func (s *remoteCNIserver) fixPodToPodCommunication(podIP string, ifname string) error {
	return s.executeCli("ip container " + podIP + " " + ifname)
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

func (s *remoteCNIserver) executeCli(command string) error {
	if s.govppChan == nil {
		s.Logger.Warn("GoVpp not available")
		return nil
	}

	req := &vpe.CliInband{}
	req.Length = uint32(len(command))
	req.Cmd = []byte(command)

	reply := &vpe.CliInbandReply{}
	err := s.govppChan.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return err
	}

	if reply.Retval != 0 {
		return fmt.Errorf("execution of cli command returned non-zero return code: %d", reply.Retval)
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
	if len(request.ContainerId) > vethNameMaxLen {
		return request.ContainerId[:vethNameMaxLen]
	}
	return request.ContainerId
}

func (s *remoteCNIserver) afpacketNameFromRequest(request *cni.CNIRequest) string {
	return afPacketNamePrefix + s.veth2NameFromRequest(request)
}

func (s *remoteCNIserver) loopbackNameFromRequest(request *cni.CNIRequest) string {
	return "loop" + s.veth2NameFromRequest(request)
}

func (s *remoteCNIserver) ipAddrForAfPacket() string {
	return afPacketIPPrefix + "." + strconv.Itoa(s.counter+1) + "/32"
}

func (s *remoteCNIserver) veth1FromRequest(request *cni.CNIRequest, podIP string) *linux_intf.LinuxInterfaces_Interface {
	return &linux_intf.LinuxInterfaces_Interface{
		Name:        s.veth1NameFromRequest(request),
		Type:        linux_intf.LinuxInterfaces_VETH,
		Enabled:     true,
		HostIfName:  s.veth1HostIfNameFromRequest(request),
		PhysAddress: "00:00:00:00:00:02",
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
		IpAddresses: []string{s.ipAddrForAfPacket()},
	}
}

func (s *remoteCNIserver) loopbackFromRequest(request *cni.CNIRequest, loopIP string) *vpp_intf.Interfaces_Interface {
	return &vpp_intf.Interfaces_Interface{
		Name:        s.loopbackNameFromRequest(request),
		Type:        vpp_intf.InterfaceType_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{loopIP},
	}
}

func (s *remoteCNIserver) vppRouteFromRequest(request *cni.CNIRequest, podIP string) *l3.StaticRoutes_Route {
	return &l3.StaticRoutes_Route{
		DstIpAddr:         podIP,
		OutgoingInterface: s.afpacketNameFromRequest(request),
	}
}

func ipToIPNet(ip net.IP) net.IPNet {
	return net.IPNet{IP: ip, Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff)}
}
