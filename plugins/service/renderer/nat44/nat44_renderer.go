/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package nat44

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	govpp "git.fd.io/govpp.git/api"
	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/api/models/vpp/nat"
	nat_api "github.com/ligato/vpp-binapi/binapi/nat"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipv4net"
	"github.com/contiv/vpp/plugins/service/config"
	"github.com/contiv/vpp/plugins/service/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
)

const (
	// Label for DNAT with identities; used to exclude VXLAN port and main interface IP
	// (with the exception of node-ports) from dynamic mappings.
	identityDNATLabel = "DNAT-identities"

	vxlanPort = 4789 // port used byt VXLAN
)

const (
	defaultIdleTCPTimeout   = 3 * time.Hour   // inactive timeout for TCP NAT sessions
	defaultIdleOtherTimeout = 5 * time.Minute // inactive timeout for other NAT sessions
)

// serviceIPType represents type of IP address where the service is accessible: node / cluster / external
type serviceIPType int

const (
	nodeIP serviceIPType = iota
	clusterIP
	externalIP
)

var (
	tcpNatSessionCount          uint64
	otherNatSessionCount        uint64
	deletedTCPNatSessionCount   uint64
	deletedOtherNatSessionCount uint64
	natSessionDeleteErrorCount  uint64
)

// Renderer implements rendering of services for IPv4 in VPP.
//
// The renderer maps ContivService instances into corresponding NAT44-DNAT model
// instances, installed into VPP by the Ligato/VPP-agent as a set of static mappings.
// Frontends and Backends are reflected in the global NAT44 configuration
// as `in` & `out` interface features, respectively.
//
// NAT global configuration and DNAT instances generated in the Renderer are
// sent to the Ligato/VPP-agent via the local client interface. The Ligato/VPP-agent
// in turn updates the VPP-NAT44 configuration through binary APIs. For each
// transaction, the agent's vpp/ifplugin determines the minimum set of operations
// that need to be executed to reflect the configuration changes.
//
// To allow access from service to itself, the Contiv plugin is asked to provide
// the virtual NAT loopback IP address, which is then inserted into the `TwiceNAT`
// address pool. `self-twice-nat` feature is enabled for every static mapping.
//
// Until VPP supports timing-out of NAT sessions, the renderer also performs
// periodic cleanup of inactive NAT sessions.
//
// An extra feature of the renderer, outside the scope of services, is a management
// of the dynamic source-NAT for node-outbound traffic, configured to enable
// Internet access even for pods with private IPv4 addresses.
// If dynamic SNAT is enabled in the Contiv configuration, the default interface
// IP (interface used to connect the node with the default GW) is added into
// the NAT main address pool and the interface itself is switched into
// the post-routing NAT mode (`output` feature) - both during Resync.
//
// For more implementation details, please study the developer's guide for
// services: `docs/dev-guide/SERVICES.md` from the top directory.
type Renderer struct {
	Deps

	snatOnly     bool /* do not render services, only dynamic SNAT */
	natGlobalCfg *vpp_nat.Nat44Global
	nodeIPs      *renderer.IPAddresses

	/* dynamic SNAT */
	defaultIfName string
	defaultIfIP   net.IP
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPv4Net          ipv4net.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	GoVPPChan        govpp.Channel      /* used for direct NAT binary API calls */
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
// Set <snatOnly> to true if the renderer should only configure SNAT and leave
// services to another renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	rndr.snatOnly = snatOnly
	rndr.natGlobalCfg = &vpp_nat.Nat44Global{
		Forwarding: true,
	}
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	// run async NAT session cleanup routine
	go rndr.idleNATSessionCleanup()
	return nil
}

// AddService installs destination-NAT rules for a newly added service.
func (rndr *Renderer) AddService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	dnat := rndr.contivServiceToDNat(service)
	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add service '%v'", service.ID))
	txn.Put(vpp_nat.DNAT44Key(dnat.Label), dnat)
	return nil
}

// UpdateService updates destination-NAT rules for a changed service.
func (rndr *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}
	newDNAT := rndr.contivServiceToDNat(newService)
	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update service '%v'", newService.ID))
	txn.Put(vpp_nat.DNAT44Key(newDNAT.Label), newDNAT)
	return nil
}

// DeleteService removes destination-NAT configuration associated with a freshly
// un-deployed service.
func (rndr *Renderer) DeleteService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete service '%v'", service.ID))
	txn.Delete(vpp_nat.DNAT44Key(service.ID.String()))
	return nil
}

// UpdateNodePortServices updates configuration of nodeport services to reflect
// the changed list of all node IPs in the cluster.
func (rndr *Renderer) UpdateNodePortServices(nodeIPs *renderer.IPAddresses,
	npServices []*renderer.ContivService) error {

	if rndr.snatOnly {
		return nil
	}
	// Update cached internal node IPs.
	rndr.nodeIPs = nodeIPs

	// Update DNAT of all node-port services via ligato/vpp-agent.
	txn := rndr.UpdateTxnFactory("update nodeport services")
	for _, npService := range npServices {
		newDNAT := rndr.contivServiceToDNat(npService)
		txn.Put(vpp_nat.DNAT44Key(newDNAT.Label), newDNAT)
	}
	return nil
}

// UpdateLocalFrontendIfs enables out2in VPP/NAT feature for interfaces connecting
// clients with VPP.
func (rndr *Renderer) UpdateLocalFrontendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}

	// Re-build the list of interfaces with enabled NAT features.
	rndr.natGlobalCfg = proto.Clone(rndr.natGlobalCfg).(*vpp_nat.Nat44Global)
	// - keep non-frontends unchanged
	newNatIfs := []*vpp_nat.Nat44Global_Interface{}
	for _, natIf := range rndr.natGlobalCfg.NatInterfaces {
		if natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of frontends
	for frontendIf := range newIfNames {
		if frontendIf == rndr.defaultIfName {
			// Default interface is in the NAT post-routing mode,
			// i.e. do not configure with the pure `out` feature.
			continue
		}
		newNatIfs = append(newNatIfs,
			&vpp_nat.Nat44Global_Interface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	rndr.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	txn := rndr.UpdateTxnFactory("update frontends")
	txn.Put(vpp_nat.GlobalNAT44Key(), rndr.natGlobalCfg)
	return nil
}

// UpdateLocalBackendIfs enables in2out VPP/NAT feature for interfaces connecting
// service backends with VPP.
func (rndr *Renderer) UpdateLocalBackendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}

	// Re-build the list of interfaces with enabled NAT features.
	rndr.natGlobalCfg = proto.Clone(rndr.natGlobalCfg).(*vpp_nat.Nat44Global)
	// - keep non-backends unchanged
	newNatIfs := []*vpp_nat.Nat44Global_Interface{}
	for _, natIf := range rndr.natGlobalCfg.NatInterfaces {
		if !natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of backends
	for backendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&vpp_nat.Nat44Global_Interface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	rndr.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	txn := rndr.UpdateTxnFactory("update backends")
	txn.Put(vpp_nat.GlobalNAT44Key(), rndr.natGlobalCfg)
	return nil
}

// Resync completely replaces the current NAT configuration with the provided
// full state of K8s services.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// In case the renderer is supposed to configure only the dynamic source-NAT,
	// just pretend there are no services, frontends and backends to be configured.
	if rndr.snatOnly {
		resyncEv = renderer.NewResyncEventData()
	}

	// Configure SNAT only if it is explicitly enabled in the Contiv configuration.
	rndr.defaultIfName = ""
	rndr.defaultIfIP = nil
	if rndr.ContivConf.NatExternalTraffic() {
		// Get interface used by default for cluster-outbound traffic.
		rndr.defaultIfName, rndr.defaultIfIP = rndr.getDefaultInterface()

		// If intra-cluster traffic flows without encapsulation through the same
		// interface as the cluster-outbound traffic, then we have to disable
		// the dynamic SNAT.
		// Policies require that intra-cluster traffic is not SNATed, but in
		// the pure L2 mode without VXLANs this cannot be achieved with the VPP/NAT
		// plugin. On the other hand, with VXLANs we can define identity NAT to
		// exclude VXLAN-encapsulated traffic from being SNATed.
		if rndr.IPv4Net.GetVxlanBVIIfName() == "" &&
			rndr.defaultIfName == rndr.ContivConf.GetMainInterfaceName() {
			rndr.defaultIfName = ""
			rndr.defaultIfIP = nil
		}

		// Default interface is in the NAT post-routing mode, i.e. do not configure
		// with the pure `out` feature.
		resyncEv.FrontendIfs.Del(rndr.defaultIfName)
	}

	// Update cached internal node IP.
	rndr.nodeIPs = resyncEv.NodeIPs

	// Resync DNAT configuration.
	for _, service := range resyncEv.Services {
		dnat := rndr.contivServiceToDNat(service)
		txn.Put(vpp_nat.DNAT44Key(dnat.Label), dnat)
	}
	dnat := rndr.exportIdentityMappings()
	txn.Put(vpp_nat.DNAT44Key(dnat.Label), dnat)

	// Re-build the global NAT config.
	rndr.natGlobalCfg = &vpp_nat.Nat44Global{
		Forwarding: true,
	}
	if rndr.Config.DisableNATVirtualReassembly {
		rndr.natGlobalCfg.VirtualReassembly = &vpp_nat.VirtualReassembly{
			DropFragments: true, // drop fragmented packets
		}
	}
	// - address pool
	if rndr.defaultIfIP != nil {
		// Address for SNAT:
		rndr.natGlobalCfg.AddressPool = append(rndr.natGlobalCfg.AddressPool,
			&vpp_nat.Nat44Global_Address{
				Address: rndr.defaultIfIP.String(),
				VrfId:   ^uint32(0),
			})
	}
	// Address for self-TwiceNAT:
	if !rndr.snatOnly {
		rndr.natGlobalCfg.AddressPool = append(rndr.natGlobalCfg.AddressPool,
			&vpp_nat.Nat44Global_Address{
				Address:  rndr.IPAM.NatLoopbackIP().String(),
				VrfId:    ^uint32(0),
				TwiceNat: true,
			})
	}
	// - frontends
	for frontendIf := range resyncEv.FrontendIfs {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&vpp_nat.Nat44Global_Interface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - backends
	for backendIf := range resyncEv.BackendIfs {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&vpp_nat.Nat44Global_Interface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	//  - post-routing
	if rndr.defaultIfName != "" {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&vpp_nat.Nat44Global_Interface{
				Name:          rndr.defaultIfName,
				IsInside:      false,
				OutputFeature: true,
			})
	}
	// - add to the transaction
	txn.Put(vpp_nat.GlobalNAT44Key(), rndr.natGlobalCfg)
	return nil
}

// getDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (rndr *Renderer) getDefaultInterface() (ifName string, ifAddress net.IP) {
	mainPhysicalIf := rndr.ContivConf.GetMainInterfaceName()
	mainIP, mainIPNet := rndr.IPv4Net.GetNodeIP()

	if rndr.ContivConf.InSTNMode() || rndr.ContivConf.UseDHCP() {
		return mainPhysicalIf, mainIP
	}

	defaultGw := rndr.ContivConf.GetStaticDefaultGW()
	if len(defaultGw) > 0 {
		if mainPhysicalIf != "" {
			if mainIPNet != nil && mainIPNet.Contains(defaultGw) {
				return mainPhysicalIf, mainIP
			}
		}
		for _, physicalIf := range rndr.ContivConf.GetOtherVPPInterfaces() {
			for _, ip := range physicalIf.IPs {
				if ip.Network != nil && ip.Network.Contains(defaultGw) {
					return physicalIf.InterfaceName, ip.Address
				}
			}
		}
	}

	return "", nil
}

// contivServiceToDNat returns DNAT configuration corresponding to a given service.
func (rndr *Renderer) contivServiceToDNat(service *renderer.ContivService) *vpp_nat.DNat44 {
	dnat := &vpp_nat.DNat44{}
	dnat.Label = service.ID.String()
	dnat.StMappings = rndr.exportDNATMappings(service)
	return dnat
}

// exportDNATMappings exports the corresponding list of D-NAT mappings from a Contiv service.
func (rndr *Renderer) exportDNATMappings(service *renderer.ContivService) []*vpp_nat.DNat44_StaticMapping {
	mappings := []*vpp_nat.DNat44_StaticMapping{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		mappings = append(mappings, rndr.exportServiceIPMappings(service, rndr.nodeIPs, nodeIP)...)
	}

	// Export NAT mappings for cluster & external IPs.
	mappings = append(mappings, rndr.exportServiceIPMappings(service, service.ClusterIPs, clusterIP)...)
	mappings = append(mappings, rndr.exportServiceIPMappings(service, service.ExternalIPs, externalIP)...)

	return mappings
}

// exportServiceIPMappings exports the corresponding list of D-NAT mappings from a list of service IPs of the given service.
func (rndr *Renderer) exportServiceIPMappings(service *renderer.ContivService,
	serviceIPs *renderer.IPAddresses, ipType serviceIPType) (mappings []*vpp_nat.DNat44_StaticMapping) {

	routingCfg := rndr.ContivConf.GetRoutingConfig()
	for _, ip := range serviceIPs.List() {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		// Add one mapping for each port.
		for portName, port := range service.Ports {
			if ipType == nodeIP && port.NodePort == 0 {
				continue
			} else if ipType != nodeIP && port.Port == 0 {
				continue
			}
			mapping := &vpp_nat.DNat44_StaticMapping{}
			if ipType == externalIP && service.TrafficPolicy == renderer.ClusterWide {
				mapping.TwiceNat = vpp_nat.DNat44_StaticMapping_ENABLED
			} else {
				mapping.TwiceNat = vpp_nat.DNat44_StaticMapping_SELF
			}
			mapping.ExternalIp = ip.String()
			if ipType == nodeIP {
				mapping.ExternalPort = uint32(port.NodePort)
			} else {
				mapping.ExternalPort = uint32(port.Port)
			}
			switch port.Protocol {
			case renderer.TCP:
				mapping.Protocol = vpp_nat.DNat44_TCP
			case renderer.UDP:
				mapping.Protocol = vpp_nat.DNat44_UDP
			}
			for _, backend := range service.Backends[portName] {
				if service.TrafficPolicy != renderer.ClusterWide && !backend.Local {
					// Do not NAT+LB remote backends.
					continue
				}
				local := &vpp_nat.DNat44_StaticMapping_LocalIP{
					LocalIp:   backend.IP.String(),
					LocalPort: uint32(backend.Port),
				}
				if backend.Local {
					local.Probability = uint32(rndr.Config.ServiceLocalEndpointWeight)
				} else {
					local.Probability = 1
				}
				if rndr.isThisNodeOrHostIP(backend.IP) {
					local.VrfId = routingCfg.MainVRFID
				} else {
					if rndr.ContivConf.GetRoutingConfig().UseL2Interconnect &&
						(!rndr.isLocalPodIP(backend.IP)) {
						// L2 mode: use main VRF for non-local PODs and other node's IPs
						local.VrfId = routingCfg.MainVRFID
					} else {
						// use POD VRF for local PODs (both L2 & VXLAN mode)
						// and non-local PODs + non-local node IPs in VXLAN mode
						local.VrfId = routingCfg.PodVRFID
					}
				}
				mapping.LocalIps = append(mapping.LocalIps, local)
				mapping.SessionAffinity = service.SessionAffinityTimeout
			}
			if len(mapping.LocalIps) == 0 {
				continue
			}
			if len(mapping.LocalIps) == 1 {
				// For single backend we use "0" to represent the probability
				// (not really configured).
				mapping.LocalIps[0].Probability = 0
			}
			mappings = append(mappings, mapping)
		}
	}
	return mappings
}

// isThisNodeOrHostIP returns true if the given IP is current node's node (VPP) or host (mgmt) IP, false otherwise.
func (rndr *Renderer) isThisNodeOrHostIP(ip net.IP) bool {
	nodeIP, _ := rndr.IPv4Net.GetNodeIP()
	if ip.Equal(nodeIP) {
		return true
	}
	for _, hostIP := range rndr.IPv4Net.GetHostIPs() {
		if hostIP.Equal(ip) {
			return true
		}
	}
	return false
}

// isLocalPodIP returns true if the given IP is this node's local POD IP.
func (rndr *Renderer) isLocalPodIP(ip net.IP) bool {
	return rndr.IPAM.PodSubnetThisNode().Contains(ip)
}

// exportIdentityMappings returns DNAT configuration with identities to exclude
// VXLAN port and main interface IP (with the exception of node-ports)
// from dynamic mappings.
func (rndr *Renderer) exportIdentityMappings() *vpp_nat.DNat44 {
	idNat := &vpp_nat.DNat44{
		Label: identityDNATLabel,
	}

	if rndr.defaultIfIP != nil {
		routingCfg := rndr.ContivConf.GetRoutingConfig()
		/* identity NAT for the VXLAN tunnel - incoming packets */
		vxlanID := &vpp_nat.DNat44_IdentityMapping{
			IpAddress: rndr.defaultIfIP.String(),
			Protocol:  vpp_nat.DNat44_UDP,
			Port:      vxlanPort,
			VrfId:     routingCfg.MainVRFID,
		}
		/* identity NAT for the VXLAN tunnel - outgoing packets */
		mainIfID1 := &vpp_nat.DNat44_IdentityMapping{
			IpAddress: rndr.defaultIfIP.String(),
			Protocol:  vpp_nat.DNat44_UDP, /* Address-only mappings are dumped with UDP as protocol */
			VrfId:     routingCfg.PodVRFID,
		}
		/* identity NAT for the STN (host-facing) traffic */
		mainIfID2 := &vpp_nat.DNat44_IdentityMapping{
			IpAddress: rndr.defaultIfIP.String(),
			Protocol:  vpp_nat.DNat44_UDP, /* Address-only mappings are dumped with UDP as protocol */
			VrfId:     routingCfg.MainVRFID,
		}
		idNat.IdMappings = append(idNat.IdMappings, vxlanID)
		idNat.IdMappings = append(idNat.IdMappings, mainIfID1)
		idNat.IdMappings = append(idNat.IdMappings, mainIfID2)
	}

	return idNat
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// idleNATSessionCleanup performs periodic cleanup of inactive NAT sessions.
// This should be removed once VPP supports timing out of the NAT sessions.
func (rndr *Renderer) idleNATSessionCleanup() {
	// run only if requested
	if !rndr.Config.CleanupIdleNATSessions {
		return
	}

	tcpTimeout := time.Duration(rndr.Config.TCPNATSessionTimeout) * time.Minute
	otherTimeout := time.Duration(rndr.Config.OtherNATSessionTimeout) * time.Minute
	if tcpTimeout == 0 {
		tcpTimeout = defaultIdleTCPTimeout
	}
	if otherTimeout == 0 {
		otherTimeout = defaultIdleOtherTimeout
	}

	rndr.Log.Infof("NAT session cleanup enabled, TCP timeout=%v, other timeout=%v.", tcpTimeout, otherTimeout)

	// register gauges
	rndr.Stats.RegisterGaugeFunc("tcpNatSessions", "Total count of TCP NAT sessions", tcpNatSessionsGauge)
	rndr.Stats.RegisterGaugeFunc("otherNatSessions", "Total count of non-TCP NAT sessions", otherNatSessionsGauge)
	rndr.Stats.RegisterGaugeFunc("deletedTCPNatSessions", "Total count of deleted TCP NAT sessions", deletedTCPNatSessionsGauge)
	rndr.Stats.RegisterGaugeFunc("deletedOtherNatSessions", "Total count of deleted non-TCP NAT sessions", deletedOtherNatSessionsGauge)
	rndr.Stats.RegisterGaugeFunc("natSessionDeleteErrors", "Count of errors by NAT session delete", natSessionDeleteErrorsGauge)

	// VPP counts the time from 0 since its start. Let's assume it is now
	// (it shouldn't be more than few seconds since its start).
	zeroTime := time.Now()

	for {
		<-time.After(otherTimeout)

		rndr.Log.Debugf("NAT session cleanup started.")

		natUsers := make([]*nat_api.Nat44UserDetails, 0)
		delRules := make([]*nat_api.Nat44DelSession, 0)
		var tcpCount uint64
		var otherCount uint64

		// dump NAT users
		req1 := &nat_api.Nat44UserDump{}
		reqCtx1 := rndr.GoVPPChan.SendMultiRequest(req1)
		for {
			msg := &nat_api.Nat44UserDetails{}
			stop, err := reqCtx1.ReceiveReply(msg)
			if stop {
				break // break out of the loop
			}
			if err != nil {
				rndr.Log.Errorf("Error by dumping NAT users: %v", err)
			}
			natUsers = append(natUsers, msg)
		}

		// dump NAT sessions per user
		for _, natUser := range natUsers {
			req2 := &nat_api.Nat44UserSessionDump{
				IPAddress: natUser.IPAddress,
				VrfID:     natUser.VrfID,
			}
			reqCtx2 := rndr.GoVPPChan.SendMultiRequest(req2)

			for {
				msg := &nat_api.Nat44UserSessionDetails{}
				stop, err := reqCtx2.ReceiveReply(msg)
				if stop {
					break // break out of the loop
				}
				if err != nil {
					rndr.Log.Errorf("Error by dumping NAT sessions: %v", err)
				}
				if msg.Protocol == 6 {
					tcpCount++
				} else {
					otherCount++
				}

				lastHeard := zeroTime.Add(time.Duration(msg.LastHeard) * time.Second)
				if lastHeard.Before(time.Now()) {
					if (msg.Protocol == 6 && time.Since(lastHeard) > tcpTimeout) ||
						(msg.Protocol != 6 && time.Since(lastHeard) > otherTimeout) {
						// inactive session
						delRule := &nat_api.Nat44DelSession{
							IsIn:     1,
							Address:  msg.InsideIPAddress,
							Port:     msg.InsidePort,
							Protocol: uint8(msg.Protocol),
							VrfID:    natUser.VrfID,
						}
						if msg.ExtHostValid > 0 {
							delRule.ExtHostValid = 1

							if msg.IsTwicenat > 0 {
								delRule.ExtHostAddress = msg.ExtHostNatAddress
								delRule.ExtHostPort = msg.ExtHostNatPort
							} else {
								delRule.ExtHostAddress = msg.ExtHostAddress
								delRule.ExtHostPort = msg.ExtHostPort
							}
						}

						delRules = append(delRules, delRule)
					}
				}
			}

		}

		rndr.Log.Debugf("There are %d TCP / %d other NAT sessions, %d will be deleted", tcpCount, otherCount, len(delRules))
		atomic.StoreUint64(&tcpNatSessionCount, tcpCount)
		atomic.StoreUint64(&otherNatSessionCount, otherCount)

		// delete the old sessions
		for _, r := range delRules {
			msg := &nat_api.Nat44DelSessionReply{}
			err := rndr.GoVPPChan.SendRequest(r).ReceiveReply(msg)
			if err != nil || msg.Retval != 0 {
				rndr.Log.Warnf("Error by deleting NAT session: %v, retval=%d, req: %v", err, msg.Retval, r)
				atomic.AddUint64(&natSessionDeleteErrorCount, 1)
			} else {
				if r.Protocol == 6 {
					atomic.AddUint64(&deletedTCPNatSessionCount, 1)
					atomic.StoreUint64(&tcpNatSessionCount, atomic.LoadUint64(&tcpNatSessionCount)-1)
				} else {
					atomic.AddUint64(&deletedOtherNatSessionCount, 1)
					atomic.StoreUint64(&otherNatSessionCount, atomic.LoadUint64(&otherNatSessionCount)-1)
				}
			}
		}
	}
}

func tcpNatSessionsGauge() float64 {
	return float64(atomic.LoadUint64(&tcpNatSessionCount))
}

func otherNatSessionsGauge() float64 {
	return float64(atomic.LoadUint64(&otherNatSessionCount))
}

func deletedTCPNatSessionsGauge() float64 {
	return float64(atomic.LoadUint64(&deletedTCPNatSessionCount))
}

func deletedOtherNatSessionsGauge() float64 {
	return float64(atomic.LoadUint64(&deletedOtherNatSessionCount))
}

func natSessionDeleteErrorsGauge() float64 {
	return float64(atomic.LoadUint64(&natSessionDeleteErrorCount))
}
