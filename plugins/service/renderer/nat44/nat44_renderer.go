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
	"net"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/nat"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/service/renderer"

	govpp "git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/statscollector"
	nat_api "github.com/ligato/vpp-agent/plugins/vpp/binapi/nat"
	"sync/atomic"
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
	natGlobalCfg *nat.Nat44Global
	nodeIPs      *renderer.IPAddresses

	/* dynamic SNAT */
	defaultIfName string
	defaultIfIP   net.IP
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log           logging.Logger
	Contiv        contiv.API /* for GetNatLoopbackIP, GetServiceLocalEndpointWeight */
	NATTxnFactory func() (dsl linuxclient.DataChangeDSL)
	LatestRevs    *syncbase.PrevRevisions
	GoVPPChan     govpp.Channel      /* used for direct NAT binary API calls */
	Stats         statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
// Set <snatOnly> to true if the renderer should only configure SNAT and leave
// services to another renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	rndr.snatOnly = snatOnly
	rndr.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
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
	rndr.Log.WithFields(logging.Fields{
		"service": service,
		"DNAT":    dnat,
	}).Debug("Nat44Renderer - AddService()")

	// Configure DNAT via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.DNAT44(dnat)

	return dsl.Send().ReceiveReply()
}

// UpdateService updates destination-NAT rules for a changed service.
func (rndr *Renderer) UpdateService(oldService, newService *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}
	newDNAT := rndr.contivServiceToDNat(newService)
	rndr.Log.WithFields(logging.Fields{
		"oldService": oldService,
		"newService": newService,
		"newDNAT":    newDNAT,
	}).Debug("Nat44Renderer - UpdateService()")

	// Update DNAT via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.DNAT44(newDNAT)

	return dsl.Send().ReceiveReply()
}

// DeleteService removes destination-NAT configuration associated with a freshly
// un-deployed service.
func (rndr *Renderer) DeleteService(service *renderer.ContivService) error {
	if rndr.snatOnly {
		return nil
	}
	rndr.Log.WithFields(logging.Fields{
		"service": service,
	}).Debug("Nat44Renderer - DeleteService()")

	// Delete DNAT via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	deleteDsl := dsl.Delete()
	deleteDsl.DNAT44(service.ID.String())

	return dsl.Send().ReceiveReply()
}

// UpdateNodePortServices updates configuration of nodeport services to reflect
// the changed list of all node IPs in the cluster.
func (rndr *Renderer) UpdateNodePortServices(nodeIPs *renderer.IPAddresses,
	npServices []*renderer.ContivService) error {

	if rndr.snatOnly {
		return nil
	}
	rndr.Log.WithFields(logging.Fields{
		"nodeIPs":    nodeIPs,
		"npServices": npServices,
	}).Debug("Nat44Renderer - UpdateNodePortServices()")

	// Update cached internal node IPs.
	rndr.nodeIPs = nodeIPs

	// Update DNAT of all node-port services via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()

	for _, npService := range npServices {
		newDNAT := rndr.contivServiceToDNat(npService)
		putDsl.DNAT44(newDNAT)
	}

	err := dsl.Send().ReceiveReply()
	if err != nil {
		rndr.Log.Error(err)
		return err
	}

	return nil
}

// UpdateLocalFrontendIfs enables out2in VPP/NAT feature for interfaces connecting
// clients with VPP.
func (rndr *Renderer) UpdateLocalFrontendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}
	rndr.Log.WithFields(logging.Fields{
		"oldIfNames": oldIfNames,
		"newIfNames": newIfNames,
	}).Debug("Nat44Renderer - UpdateLocalFrontendIfs()")

	// Re-build the list of interfaces with enabled NAT features.
	rndr.natGlobalCfg = proto.Clone(rndr.natGlobalCfg).(*nat.Nat44Global)
	// - keep non-frontends unchanged
	newNatIfs := []*nat.Nat44Global_Interface{}
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
			&nat.Nat44Global_Interface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	rndr.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44Global(rndr.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// UpdateLocalBackendIfs enables in2out VPP/NAT feature for interfaces connecting
// service backends with VPP.
func (rndr *Renderer) UpdateLocalBackendIfs(oldIfNames, newIfNames renderer.Interfaces) error {
	if rndr.snatOnly {
		return nil
	}
	rndr.Log.WithFields(logging.Fields{
		"oldIfNames": oldIfNames,
		"newIfNames": newIfNames,
	}).Debug("Nat44Renderer - UpdateLocalBackendIfs()")

	// Re-build the list of interfaces with enabled NAT features.
	rndr.natGlobalCfg = proto.Clone(rndr.natGlobalCfg).(*nat.Nat44Global)
	// - keep non-backends unchanged
	newNatIfs := []*nat.Nat44Global_Interface{}
	for _, natIf := range rndr.natGlobalCfg.NatInterfaces {
		if !natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of backends
	for backendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&nat.Nat44Global_Interface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	rndr.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44Global(rndr.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// Resync completely replaces the current NAT configuration with the provided
// full state of K8s services.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	rndr.Log.WithFields(logging.Fields{
		"resyncEv": resyncEv,
	}).Debug("Nat44Renderer - Resync()")

	dsl := rndr.NATTxnFactory()
	putDsl := dsl.Put()

	// In case the renderer is supposed to configure only the dynamic source-NAT,
	// just pretend there are no services, frontends and backends to be configured.
	if rndr.snatOnly {
		resyncEv = renderer.NewResyncEventData()
	}

	// Configure SNAT only if it is explicitly enabled in the Contiv configuration.
	rndr.defaultIfName = ""
	rndr.defaultIfIP = nil
	if rndr.Contiv.NatExternalTraffic() {
		// Get interface used by default for cluster-outbound traffic.
		rndr.defaultIfName, rndr.defaultIfIP = rndr.Contiv.GetDefaultInterface()

		// If intra-cluster traffic flows without encapsulation through the same
		// interface as the cluster-outbound traffic, then we have to disable
		// the dynamic SNAT.
		// Policies require that intra-cluster traffic is not SNATed, but in
		// the pure L2 mode without VXLANs this cannot be achieved with the VPP/NAT
		// plugin. On the other hand, with VXLANs we can define identity NAT to
		// exclude VXLAN-encapsulated traffic from being SNATed.
		if rndr.Contiv.GetVxlanBVIIfName() == "" &&
			rndr.defaultIfName == rndr.Contiv.GetMainPhysicalIfName() {
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
		putDsl.DNAT44(dnat)
	}
	putDsl.DNAT44(rndr.exportIdentityMappings())

	// Re-build the global NAT config.
	rndr.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
	}
	if rndr.Contiv.DisableNATVirtualReassembly() {
		rndr.natGlobalCfg.VirtualReassembly = &nat.VirtualReassembly{
			DropFragments: true, // drop fragmented packets
		}
	}
	// - address pool
	if rndr.defaultIfIP != nil {
		// Address for SNAT:
		rndr.natGlobalCfg.AddressPool = append(rndr.natGlobalCfg.AddressPool,
			&nat.Nat44Global_Address{
				Address: rndr.defaultIfIP.String(),
				VrfId:   ^uint32(0),
			})
	}
	// Address for self-TwiceNAT:
	if !rndr.snatOnly {
		rndr.natGlobalCfg.AddressPool = append(rndr.natGlobalCfg.AddressPool,
			&nat.Nat44Global_Address{
				Address:  rndr.Contiv.GetNatLoopbackIP().String(),
				VrfId:    ^uint32(0),
				TwiceNat: true,
			})
	}
	// - frontends
	for frontendIf := range resyncEv.FrontendIfs {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_Interface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - backends
	for backendIf := range resyncEv.BackendIfs {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_Interface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	//  - post-routing
	if rndr.defaultIfName != "" {
		rndr.natGlobalCfg.NatInterfaces = append(rndr.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_Interface{
				Name:          rndr.defaultIfName,
				IsInside:      false,
				OutputFeature: true,
			})
	}
	// - add to the transaction
	putDsl.NAT44Global(rndr.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// contivServiceToDNat returns DNAT configuration corresponding to a given service.
func (rndr *Renderer) contivServiceToDNat(service *renderer.ContivService) *nat.DNat44 {
	dnat := &nat.DNat44{}
	dnat.Label = service.ID.String()
	dnat.StMappings = rndr.exportDNATMappings(service)
	return dnat
}

// exportDNATMappings exports the corresponding list of D-NAT mappings from a Contiv service.
func (rndr *Renderer) exportDNATMappings(service *renderer.ContivService) []*nat.DNat44_StaticMapping {
	mappings := []*nat.DNat44_StaticMapping{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		for _, nodeIP := range rndr.nodeIPs.List() {
			var externalIPFromPool bool
			if nodeIP.To4() != nil {
				nodeIP = nodeIP.To4()
			}
			if rndr.defaultIfIP != nil && rndr.defaultIfIP.Equal(nodeIP) {
				externalIPFromPool = true
			}
			// Add one mapping for each port.
			for portName, port := range service.Ports {
				if port.NodePort == 0 {
					continue
				}
				mapping := &nat.DNat44_StaticMapping{}
				mapping.TwiceNat = nat.DNat44_StaticMapping_SELF
				mapping.ExternalIp = nodeIP.String()
				mapping.ExternalIpFromPool = externalIPFromPool
				mapping.ExternalPort = uint32(port.NodePort)
				switch port.Protocol {
				case renderer.TCP:
					mapping.Protocol = nat.DNat44_TCP
				case renderer.UDP:
					mapping.Protocol = nat.DNat44_UDP
				}
				for _, backend := range service.Backends[portName] {
					if service.TrafficPolicy != renderer.ClusterWide && !backend.Local {
						// Do not NAT+LB remote backends.
						continue
					}
					local := &nat.DNat44_StaticMapping_LocalIP{
						LocalIp:   backend.IP.String(),
						LocalPort: uint32(backend.Port),
					}
					if backend.Local {
						local.Probability = uint32(rndr.Contiv.GetServiceLocalEndpointWeight())
					} else {
						local.Probability = 1
					}
					if rndr.isNodeLocalIP(backend.IP) {
						local.VrfId = rndr.Contiv.GetMainVrfID()
					} else {
						local.VrfId = rndr.Contiv.GetPodVrfID()
					}
					mapping.LocalIps = append(mapping.LocalIps, local)
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
	}

	// Export NAT mappings for external IPs.
	for _, externalIP := range service.ExternalIPs.List() {
		// Add one mapping for each port.
		for portName, port := range service.Ports {
			if port.Port == 0 {
				continue
			}
			mapping := &nat.DNat44_StaticMapping{}
			mapping.TwiceNat = nat.DNat44_StaticMapping_SELF
			mapping.ExternalIp = externalIP.String()
			mapping.ExternalPort = uint32(port.Port)
			switch port.Protocol {
			case renderer.TCP:
				mapping.Protocol = nat.DNat44_TCP
			case renderer.UDP:
				mapping.Protocol = nat.DNat44_UDP
			}
			for _, backend := range service.Backends[portName] {
				if service.TrafficPolicy != renderer.ClusterWide && !backend.Local {
					// Do not NAT+LB remote backends.
					continue
				}
				local := &nat.DNat44_StaticMapping_LocalIP{
					LocalIp:   backend.IP.String(),
					LocalPort: uint32(backend.Port),
				}
				if backend.Local {
					local.Probability = uint32(rndr.Contiv.GetServiceLocalEndpointWeight())
				} else {
					local.Probability = 1
				}
				if rndr.isNodeLocalIP(backend.IP) {
					local.VrfId = rndr.Contiv.GetMainVrfID()
				} else {
					local.VrfId = rndr.Contiv.GetPodVrfID()
				}
				mapping.LocalIps = append(mapping.LocalIps, local)
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

// isNodeLocalIP returns true if the given IP is local to the current node, false otherwise.
func (rndr *Renderer) isNodeLocalIP(ip net.IP) bool {
	nodeIP, _ := rndr.Contiv.GetNodeIP()
	if ip.Equal(nodeIP) {
		return true
	}

	for _, hostIP := range rndr.Contiv.GetHostIPs() {
		if hostIP.Equal(ip) {
			return true
		}
	}

	return false
}

// exportIdentityMappings returns DNAT configuration with identities to exclude
// VXLAN port and main interface IP (with the exception of node-ports)
// from dynamic mappings.
func (rndr *Renderer) exportIdentityMappings() *nat.DNat44 {
	idNat := &nat.DNat44{
		Label: identityDNATLabel,
	}

	if rndr.defaultIfIP != nil {
		/* identity NAT for the VXLAN tunnel - incoming packets */
		vxlanID := &nat.DNat44_IdentityMapping{
			IpAddress:         rndr.defaultIfIP.String(),
			IpAddressFromPool: true,
			Protocol:          nat.DNat44_UDP,
			Port:              vxlanPort,
			VrfId:             rndr.Contiv.GetMainVrfID(),
		}
		/* identity NAT for the VXLAN tunnel - outgoing packets */
		mainIfID1 := &nat.DNat44_IdentityMapping{
			IpAddress:         rndr.defaultIfIP.String(),
			IpAddressFromPool: true,
			Protocol:          nat.DNat44_UDP, /* Address-only mappings are dumped with UDP as protocol */
			VrfId:             rndr.Contiv.GetPodVrfID(),
		}
		/* identity NAT for the STN (host-facing) traffic */
		mainIfID2 := &nat.DNat44_IdentityMapping{
			IpAddress:         rndr.defaultIfIP.String(),
			IpAddressFromPool: true,
			Protocol:          nat.DNat44_UDP, /* Address-only mappings are dumped with UDP as protocol */
			VrfId:             rndr.Contiv.GetMainVrfID(),
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
	if !rndr.Contiv.CleanupIdleNATSessions() {
		return
	}

	tcpTimeout := time.Duration(rndr.Contiv.GetTCPNATSessionTimeout()) * time.Minute
	otherTimeout := time.Duration(rndr.Contiv.GetOtherNATSessionTimeout()) * time.Minute
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
