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
	"strconv"
	"strings"
	"encoding/binary"
	"git.fd.io/govpp.git/api"
	"github.com/vishvananda/netlink"

	linux_intf "github.com/ligato/vpp-agent/plugins/linuxv2/model/interfaces"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/stats"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpe"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/vppv2/model/l2"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
)

const (
	vxlanVNI               = 10         // VXLAN Network Identifier (or VXLAN Segment ID)
	vxlanSplitHorizonGroup = 1          // As VXLAN tunnels are added to a BD, they must be configured with the same and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may loop among servers with the same VXLAN segment because VXLAN tunnels are fully meshed among servers.
	vxlanBVIInterfaceName  = "vxlanBVI" // name of the VXLAN BVI interface.
	vxlanBDName            = "vxlanBD"  // name of the VXLAN bridge domain
)

func (s *remoteCNIserver) routePODsFromHost(nextHopIP string) *linux_l3.LinuxStaticRoute {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: vethHostEndLogicalName,
		Scope:             linux_l3.LinuxStaticRoute_GLOBAL,
		DstNetwork:        s.ipam.PodSubnet().String(),
		GwAddr:            nextHopIP,
	}
	if s.useTAPInterfaces {
		route.OutgoingInterface = TapHostEndLogicalName
	}
	return route
}

func (s *remoteCNIserver) routeServicesFromHost(nextHopIP string) *linux_l3.LinuxStaticRoute {
	route := &linux_l3.LinuxStaticRoute{
		OutgoingInterface: vethHostEndLogicalName,
		Scope:             linux_l3.LinuxStaticRoute_GLOBAL,
		DstNetwork:        s.ipam.ServiceNetwork().String(),
		GwAddr:            nextHopIP,
	}
	if s.useTAPInterfaces {
		route.OutgoingInterface = TapHostEndLogicalName
	}
	return route
}

func (s *remoteCNIserver) defaultRoute(gwIP string, outIfName string) *vpp_l3.StaticRoute {
	route := &vpp_l3.StaticRoute{
		DstNetwork:       "0.0.0.0/0",
		NextHopAddr:       gwIP,
		OutgoingInterface: outIfName,
		VrfId:             s.GetMainVrfID(),
	}
	return route
}

func (s *remoteCNIserver) routesPodToMainVRF() (*vpp_l3.StaticRoute, *vpp_l3.StaticRoute) {
	r1 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: "0.0.0.0/0",
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	r2 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.VPPHostNetwork().String(),
		VrfId:      s.GetPodVrfID(),
		ViaVrfId:   s.GetMainVrfID(),
	}
	return r1, r2
}

func (s *remoteCNIserver) routesToPodVRF() (*vpp_l3.StaticRoute, *vpp_l3.StaticRoute) {
	r1 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.PodSubnet().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	r2 := &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: s.ipam.VPPHostSubnet().String(),
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
	return r1, r2
}

func (s *remoteCNIserver) dropRoutesIntoPodVRF() (*vpp_l3.StaticRoute, *vpp_l3.StaticRoute) {
	r1 := s.dropRoute(s.GetPodVrfID(), s.ipam.PodSubnet())

	r2 := s.dropRoute(s.GetPodVrfID(), s.ipam.VPPHostSubnet())
	return r1, r2
}

func (s *remoteCNIserver) routesToHost(nextHopIP string) []*vpp_l3.StaticRoute {
	// list all IPs assigned to host interfaces
	ips, err := s.getHostLinkIPs()
	if err != nil {
		s.Logger.Errorf("Error by listing host IPs: %v", err)
		return nil
	}

	// generate a /32 static route from VPP for each of the host's IPs
	routes := make([]*vpp_l3.StaticRoute, 0)
	for _, ip := range ips {
		routes = append(routes, &vpp_l3.StaticRoute{
			DstNetwork:        fmt.Sprintf("%s/32", ip.String()),
			NextHopAddr:       nextHopIP,
			OutgoingInterface: s.hostInterconnectIfName,
			VrfId:             s.GetMainVrfID(),
		})
	}

	return routes
}

func (s *remoteCNIserver) interconnectTap() *vpp_intf.Interface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	tap := &vpp_intf.Interface{
		Name:    TapVPPEndLogicalName,
		Type:    vpp_intf.Interface_TAP_INTERFACE,
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
		Link: &vpp_intf.Interface_Tap{
			Tap: &vpp_intf.Interface_TapLink{},
		},
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
		PhysAddress: HostInterconnectMAC,
	}
	if s.tapVersion == 2 {
		tap.GetTap().Version = 2
		tap.GetTap().RxRingSize = uint32(s.tapV2RxRingSize)
		tap.GetTap().TxRingSize = uint32(s.tapV2TxRingSize)
	}

	return tap
}

func (s *remoteCNIserver) interconnectTapHost() *linux_intf.LinuxInterface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	return &linux_intf.LinuxInterface{
		Name: TapHostEndLogicalName,
		Type: linux_intf.LinuxInterface_TAP_TO_VPP,
		Link: &linux_intf.LinuxInterface_Tap{
			Tap: &linux_intf.LinuxInterface_TapLink{
				VppTapIfName: TapVPPEndLogicalName,
			},
		},
		Mtu:         s.config.MTUSize,
		HostIfName:  TapHostEndName,
		Enabled:     true,
		IpAddresses: []string{s.ipam.VEthHostEndIP().String() + "/" + strconv.Itoa(size)},
	}
}

func (s *remoteCNIserver) interconnectVethHost() *linux_intf.LinuxInterface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	return &linux_intf.LinuxInterface{
		Name: vethHostEndLogicalName,
		Type: linux_intf.LinuxInterface_VETH,
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: vethVPPEndLogicalName},
		},
		Mtu:         s.config.MTUSize,
		Enabled:     true,
		HostIfName:  vethHostEndName,
		IpAddresses: []string{s.ipam.VEthHostEndIP().String() + "/" + strconv.Itoa(size)},
	}
}

func (s *remoteCNIserver) interconnectVethVpp() *linux_intf.LinuxInterface {
	return &linux_intf.LinuxInterface{
		Name: vethVPPEndLogicalName,
		Type: linux_intf.LinuxInterface_VETH,
		Link: &linux_intf.LinuxInterface_Veth{
			Veth: &linux_intf.LinuxInterface_VethLink{PeerIfName: vethHostEndLogicalName},
		},
		Mtu:        s.config.MTUSize,
		Enabled:    true,
		HostIfName: vethVPPEndName,
	}
}

func (s *remoteCNIserver) interconnectAfpacketName() string {
	return afPacketNamePrefix + "-" + vethVPPEndName
}

func (s *remoteCNIserver) interconnectAfpacket() *vpp_intf.Interface {
	size, _ := s.ipam.VPPHostNetwork().Mask.Size()
	return &vpp_intf.Interface{
		Name: s.interconnectAfpacketName(),
		Type: vpp_intf.Interface_AF_PACKET_INTERFACE,
		Link: &vpp_intf.Interface_Afpacket{
			Afpacket: &vpp_intf.Interface_AfpacketLink{
				HostIfName: vethVPPEndName,
			},
		},
		Mtu:     s.config.MTUSize,
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
		IpAddresses: []string{s.ipam.VEthVPPEndIP().String() + "/" + strconv.Itoa(size)},
	}
}

func (s *remoteCNIserver) physicalInterface(name string, ipAddress string) *vpp_intf.Interface {
	return &vpp_intf.Interface{
		Name:        name,
		Type:        vpp_intf.Interface_ETHERNET_CSMACD,
		Enabled:     true,
		Vrf:         s.GetMainVrfID(),
		IpAddresses: []string{ipAddress},
	}
}

func (s *remoteCNIserver) physicalInterfaceLoopback(ipAddress string) *vpp_intf.Interface {
	return &vpp_intf.Interface{
		Name:        "loopbackNIC",
		Type:        vpp_intf.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		Vrf:         s.GetMainVrfID(),
		IpAddresses: []string{ipAddress},
	}
}

func (s *remoteCNIserver) vxlanBVILoopback() (*vpp_intf.Interface, error) {
	vxlanIP, err := s.ipam.VxlanIPWithPrefix(s.ipam.NodeID())
	if err != nil {
		return nil, err
	}
	return &vpp_intf.Interface{
		Name:        vxlanBVIInterfaceName,
		Type:        vpp_intf.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		IpAddresses: []string{vxlanIP.String()},
		PhysAddress: s.hwAddrForVXLAN(s.ipam.NodeID()),
		Vrf:         s.GetPodVrfID(),
	}, nil
}

func (s *remoteCNIserver) hwAddrForVXLAN(nodeID uint32) string {
	if nodeID < 256 {
		// generate backward compatible MAC address
		return fmt.Sprintf("1a:2b:3c:4d:5e:%02x", nodeID)
	}
	// the first octet is intentionally different from the one above
	// in order to ensure unique IP foreach nodeID

	res := []byte{0x12, 0x2b, 0, 0, 0, 0}

	// the first two bytes are constant, the last four are equal to nodeID
	binary.BigEndian.PutUint32(res[2:], nodeID)

	return net.HardwareAddr(res).String()

}

func (s *remoteCNIserver) vxlanBridgeDomain(bviInterface string) *vpp_l2.BridgeDomain {
	return &vpp_l2.BridgeDomain{
		Name:                vxlanBDName,
		Learn:               false,
		Forward:             true,
		Flood:               false,
		UnknownUnicastFlood: false,
		Interfaces: []*vpp_l2.BridgeDomain_Interface{
			{
				Name: bviInterface,
				BridgedVirtualInterface: true,
				SplitHorizonGroup:       vxlanSplitHorizonGroup,
			},
		},
	}
}

func (s *remoteCNIserver) vxlanArpEntry(nodeID uint32, hostIP string) *vpp_l3.ARPEntry {
	return &vpp_l3.ARPEntry{
		Interface:   vxlanBVIInterfaceName,
		IpAddress:   hostIP,
		PhysAddress: s.hwAddrForVXLAN(nodeID),
		Static:      true,
	}
}

func (s *remoteCNIserver) vxlanFibEntry(macAddr string, outIfName string) *vpp_l2.FIBEntry {
	return &vpp_l2.FIBEntry{
		BridgeDomain:            vxlanBDName,
		PhysAddress:             macAddr,
		OutgoingInterface:       outIfName,
		StaticConfig:            true,
		BridgedVirtualInterface: false,
		Action:                  vpp_l2.FIBEntry_FORWARD,
	}
}

func (s *remoteCNIserver) computeRoutesToHost(hostID uint32, nextHopIP string) (podsRoute *vpp_l3.StaticRoute, hostRoute *vpp_l3.StaticRoute, err error) {
	podsRoute, err = s.routeToOtherHostPods(hostID, nextHopIP)
	if err != nil {
		err = fmt.Errorf("Can't construct route to pods of host %v: %v ", hostID, err)
		return
	}
	hostRoute, err = s.routeToOtherHostStack(hostID, nextHopIP)
	if err != nil {
		err = fmt.Errorf("Can't construct route to host %v: %v ", hostID, err)
		return
	}
	return
}

func (s *remoteCNIserver) routeToOtherHostPods(hostID uint32, nextHopIP string) (*vpp_l3.StaticRoute, error) {
	podNetwork, err := s.ipam.OtherNodePodNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute pod network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(podNetwork, nextHopIP)
}

func (s *remoteCNIserver) routeToOtherHostStack(hostID uint32, nextHopIP string) (*vpp_l3.StaticRoute, error) {
	hostNw, err := s.ipam.OtherNodeVPPHostNetwork(hostID)
	if err != nil {
		return nil, fmt.Errorf("Can't compute vswitch network for host ID %v, error: %v ", hostID, err)
	}
	return s.routeToOtherHostNetworks(hostNw, nextHopIP)
}

func (s *remoteCNIserver) routeToOtherManagementIP(managementIP string, nextHopIP string) *vpp_l3.StaticRoute {
	r := &vpp_l3.StaticRoute{
		DstNetwork:  managementIP + "/32",
		NextHopAddr: nextHopIP,
	}
	if s.useL2Interconnect {
		r.VrfId = s.GetMainVrfID()
	} else {
		r.OutgoingInterface = vxlanBVIInterfaceName
		r.VrfId = s.GetPodVrfID()
	}
	return r
}

func (s *remoteCNIserver) routeToOtherManagementIPViaPodVRF(managementIP string) *vpp_l3.StaticRoute {
	return &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_INTER_VRF,
		DstNetwork: managementIP + "/32",
		VrfId:      s.GetMainVrfID(),
		ViaVrfId:   s.GetPodVrfID(),
	}
}

func (s *remoteCNIserver) routeToOtherHostNetworks(destNetwork *net.IPNet, nextHopIP string) (*vpp_l3.StaticRoute, error) {
	r := &vpp_l3.StaticRoute{
		DstNetwork:  destNetwork.String(),
		NextHopAddr: nextHopIP,
	}
	if s.useL2Interconnect {
		r.VrfId = s.GetMainVrfID()
	} else {
		r.OutgoingInterface = vxlanBVIInterfaceName
		r.VrfId = s.GetPodVrfID()
	}
	return r, nil
}

func (s *remoteCNIserver) computeVxlanToHost(hostID uint32, hostIP string) (*vpp_intf.Interface, error) {
	return &vpp_intf.Interface{
		Name:    fmt.Sprintf("vxlan%d", hostID),
		Type:    vpp_intf.Interface_VXLAN_TUNNEL,
		Link: &vpp_intf.Interface_Vxlan{
			Vxlan: &vpp_intf.Interface_VxlanLink{
				SrcAddress: s.ipPrefixToAddress(s.nodeIP),
				DstAddress: hostIP,
				Vni:        vxlanVNI,
			},
		},
		Enabled: true,
		Vrf:     s.GetMainVrfID(),
	}, nil
}

func (s *remoteCNIserver) addInterfaceToVxlanBD(bd *vpp_l2.BridgeDomain, ifName string) {
	bd.Interfaces = append(bd.Interfaces, &vpp_l2.BridgeDomain_Interface{
		Name:              ifName,
		SplitHorizonGroup: vxlanSplitHorizonGroup,
	})
}

func (s *remoteCNIserver) removeInterfaceFromVxlanBD(bd *vpp_l2.BridgeDomain, ifName string) {
	for i := range bd.Interfaces {
		if bd.Interfaces[i].Name == ifName {
			bd.Interfaces[i] = bd.Interfaces[len(bd.Interfaces)-1]
			bd.Interfaces[len(bd.Interfaces)-1] = nil
			bd.Interfaces = bd.Interfaces[:len(bd.Interfaces)-1]
			break
		}
	}
}

func (s *remoteCNIserver) otherHostIP(hostID uint32, hostIPPrefix string) string {
	// determine next hop IP - either use provided one, or calculate based on hostIPPrefix
	if hostIPPrefix != "" {
		// hostIPPrefix defined, just trim prefix length
		return s.ipPrefixToAddress(hostIPPrefix)
	}

	// hostIPPrefix not defined, determine based on hostID
	nodeIP, err := s.ipam.NodeIPAddress(hostID)
	if err != nil {
		s.Logger.Errorf("Can't get Host IP address for host ID %v, error: %v ", hostID, err)
		return ""
	}
	return nodeIP.String()
}

func (s *remoteCNIserver) ipPrefixToAddress(ip string) string {
	if strings.Contains(ip, "/") {
		return ip[:strings.Index(ip, "/")]
	}
	return ip
}

func (s *remoteCNIserver) getHostLinkIPs() ([]net.IP, error) {
	if s.hostIPs != nil {
		return s.hostIPs, nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		s.Logger.Error("Unable to list host links:", err)
		return nil, err
	}

	s.hostIPs = make([]net.IP, 0)
	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") && !strings.HasPrefix(l.Attrs().Name, "docker") &&
			!strings.HasPrefix(l.Attrs().Name, "virbr") && !strings.HasPrefix(l.Attrs().Name, "vpp") {
			// not a virtual interface, list its IP addresses
			addrList, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				s.Logger.Error("Unable to list link IPs:", err)
				return nil, err
			}
			// return all IPs
			for _, addr := range addrList {
				s.hostIPs = append(s.hostIPs, addr.IP)
			}
		}
	}
	return s.hostIPs, nil
}


func (s *remoteCNIserver) enableIPNeighborScan() error {
	s.Logger.Info("Enabling IP neighbor scanning")
	txn := s.vppTxnFactory().Put()

	txn.IPScanNeighbor(&vpp_l3.IPScanNeighbor{
		Mode:           vpp_l3.IPScanNeighbor_IPv4,
		ScanInterval:   uint32(s.config.IPNeighborScanInterval),
		StaleThreshold: uint32(s.config.IPNeighborStaleThreshold),
	})

	err := txn.Send().ReceiveReply()
	if err != nil {
		s.Logger.Error("Error by enabling IP neighbor scanning:", err)
	}
	return err
}

func (s *remoteCNIserver) subscribeVnetFibCounters() error {

	notifChan := make(chan api.Message, 1)
	_, err := s.govppChan.SubscribeNotification(notifChan, &stats.VnetIP4FibCounters{})

	if err != nil {
		s.Logger.Error("Error by subscribing to NewVnetIP4FibCounters:", err)
	}

	// read from the notif channel in a go routine to not block once the channel is full
	go func() {
		for {
			<-notifChan
		}
	}()

	return err
}

func (s *remoteCNIserver) executeDebugCLI(cmd string) (string, error) {
	s.Logger.Infof("Executing debug CLI: %s", cmd)

	req := &vpe.CliInband{
		Cmd: []byte(cmd),
	}
	reply := &vpe.CliInbandReply{}

	err := s.govppChan.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		s.Logger.Error("Error by executing debug CLI:", err)
		return "", err
	}
	return string(reply.Reply), err
}

func (s *remoteCNIserver) dropRoute(vrfID uint32, dstAddr *net.IPNet) *vpp_l3.StaticRoute {
	s.Logger.Infof("Adding drop route in VRF %d to %s", vrfID, dstAddr)

	return &vpp_l3.StaticRoute{
		Type:       vpp_l3.StaticRoute_DROP,
		DstNetwork: dstAddr.String(),
		VrfId:      vrfID,
	}

}
