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

package configurator

import (
	"strings"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"

	"github.com/contiv/vpp/plugins/contiv"

	govpp "git.fd.io/govpp.git/api"
	"github.com/contiv/vpp/plugins/statscollector"
	nat_api "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/nat"
	"sync/atomic"
)

// LocalVsRemoteProbRatio tells how much more likely a local backend is to receive
// traffic as opposed to a remote backend.
const LocalVsRemoteProbRatio uint32 = 2

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

// ServiceConfigurator implements ServiceConfiguratorAPI.
type ServiceConfigurator struct {
	Deps

	externalSNAT ExternalSNATConfig
	natGlobalCfg *nat.Nat44Global
	nodeIPs      *IPAddresses
}

// Deps lists dependencies of ServiceConfigurator.
type Deps struct {
	Log           logging.Logger
	VPP           defaultplugins.API /* for DumpNat44Global & DumpNat44DNat */
	Contiv        contiv.API         /* for GetNatLoopbackIP, InSTNMode */
	NATTxnFactory func() (dsl linux.DataChangeDSL)
	LatestRevs    *syncbase.PrevRevisions
	GoVPPChan     *govpp.Channel     /* used for direct NAT binary API calls */
	Stats         statscollector.API /* used for exporting the statistics */
}

// Init initializes service configurator.
func (sc *ServiceConfigurator) Init() error {
	sc.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
	}
	return nil
}

// AfterInit is called by the plugin infra after init of all plugins is completed.
func (sc *ServiceConfigurator) AfterInit() error {
	// run async NAT session cleanup routine
	go sc.idleNATSessionCleanup()
	return nil
}

// AddService installs NAT rules for a newly added service.
func (sc *ServiceConfigurator) AddService(service *ContivService) error {
	dnat := sc.contivServiceToDNat(service)
	sc.Log.WithFields(logging.Fields{
		"service": service,
		"DNAT":    dnat,
	}).Debug("ServiceConfigurator - AddService()")

	// Configure DNAT via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44DNat(dnat)

	return dsl.Send().ReceiveReply()
}

// UpdateService reflects a change in the configuration of a service with
// the smallest number of VPP/NAT binary API calls necessary.
func (sc *ServiceConfigurator) UpdateService(oldService, newService *ContivService) error {
	newDNAT := sc.contivServiceToDNat(newService)
	sc.Log.WithFields(logging.Fields{
		"oldService": oldService,
		"newService": newService,
		"newDNAT":    newDNAT,
	}).Debug("ServiceConfigurator - UpdateService()")

	// Update DNAT via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44DNat(newDNAT)

	return dsl.Send().ReceiveReply()
}

// DeleteService removes NAT configuration associated with a newly undeployed
// service.
func (sc *ServiceConfigurator) DeleteService(service *ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"service": service,
	}).Debug("ServiceConfigurator - DeleteService()")

	// Delete DNAT via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	deleteDsl := dsl.Delete()
	deleteDsl.NAT44DNat(service.ID.String())

	return dsl.Send().ReceiveReply()
}

// UpdateNodePortServices updates configuration of nodeport services to reflect
// changed list of all node IPs in the cluster.
func (sc *ServiceConfigurator) UpdateNodePortServices(nodeIPs *IPAddresses, npServices []*ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"nodeIPs":    nodeIPs,
		"npServices": npServices,
	}).Debug("ServiceConfigurator - UpdateNodePortServices()")

	// Update cached internal node IPs.
	sc.nodeIPs = nodeIPs

	// Update DNAT of all node-port services via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()

	for _, npService := range npServices {
		newDNAT := sc.contivServiceToDNat(npService)
		putDsl.NAT44DNat(newDNAT)
	}

	err := dsl.Send().ReceiveReply()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	return nil
}

// UpdateLocalFrontendIfs updates the list of interfaces connecting clients
// with VPP (enabled out2in VPP/NAT feature).
func (sc *ServiceConfigurator) UpdateLocalFrontendIfs(oldIfNames, newIfNames Interfaces) error {
	sc.Log.WithFields(logging.Fields{
		"oldIfNames": oldIfNames,
		"newIfNames": newIfNames,
	}).Debug("ServiceConfigurator - UpdateLocalFrontendIfs()")

	// Re-build the list of interfaces with enabled NAT features.
	sc.natGlobalCfg = proto.Clone(sc.natGlobalCfg).(*nat.Nat44Global)
	// - keep non-frontends unchanged
	newNatIfs := []*nat.Nat44Global_NatInterface{}
	for _, natIf := range sc.natGlobalCfg.NatInterfaces {
		if natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of frontends
	for frontendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&nat.Nat44Global_NatInterface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	sc.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44Global(sc.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// UpdateLocalBackendIfs updates the list of interfaces connecting service
// backends with VPP (enabled in2out VPP/NAT feature).
func (sc *ServiceConfigurator) UpdateLocalBackendIfs(oldIfNames, newIfNames Interfaces) error {
	sc.Log.WithFields(logging.Fields{
		"oldIfNames": oldIfNames,
		"newIfNames": newIfNames,
	}).Debug("ServiceConfigurator - UpdateLocalBackendIfs()")

	// Re-build the list of interfaces with enabled NAT features.
	sc.natGlobalCfg = proto.Clone(sc.natGlobalCfg).(*nat.Nat44Global)
	// - keep non-backends unchanged
	newNatIfs := []*nat.Nat44Global_NatInterface{}
	for _, natIf := range sc.natGlobalCfg.NatInterfaces {
		if !natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of backends
	for backendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&nat.Nat44Global_NatInterface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	// - re-write the cached list
	sc.natGlobalCfg.NatInterfaces = newNatIfs

	// Update global NAT config via ligato/vpp-agent.
	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()
	putDsl.NAT44Global(sc.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// Resync completely replaces the current NAT configuration with the provided
// full state of K8s services.
func (sc *ServiceConfigurator) Resync(resyncEv *ResyncEventData) error {
	var err error
	sc.Log.WithFields(logging.Fields{
		"resyncEv": resyncEv,
	}).Debug("ServiceConfigurator - Resync()")

	dsl := sc.NATTxnFactory()
	putDsl := dsl.Put()
	deleteDsl := dsl.Delete()

	// Updated cached internal node IP.
	sc.nodeIPs = resyncEv.NodeIPs

	// Update cached SNAT config.
	sc.externalSNAT = resyncEv.ExternalSNAT

	// Dump currently configured services.
	dnatDump, err := sc.VPP.DumpNat44DNat()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Get the latest revisions of DNATs in-sync with VPP.
	keyList := sc.LatestRevs.ListKeys()
	keys := map[string]struct{}{}
	for _, key := range keyList {
		if strings.HasPrefix(key, nat.DNatPrefix()) {
			keys[key] = struct{}{}
		}
	}
	for _, dnat := range dnatDump.DnatConfigs {
		key := nat.DNatKey(dnat.Label)
		value := syncbase.NewChange(key, dnat, 0, datasync.Put)
		sc.LatestRevs.PutWithRevision(key, value)
		delete(keys, key)
	}
	for key := range keys {
		sc.LatestRevs.Del(key)
	}

	// Resync DNAT configuration.
	// - remove obsolete DNATs
	for _, dnatConfig := range dnatDump.DnatConfigs {
		if dnatConfig.Label == identityDNATLabel {
			continue
		}
		removed := true
		for _, service := range resyncEv.Services {
			if service.ID.String() == dnatConfig.Label {
				removed = false
				break
			}
		}
		if removed {
			deleteDsl.NAT44DNat(dnatConfig.Label)
		}
	}
	// - update all DNATs
	for _, service := range resyncEv.Services {
		dnat := sc.contivServiceToDNat(service)
		putDsl.NAT44DNat(dnat)
	}
	// - identity mappings
	putDsl.NAT44DNat(sc.exportIdentityMappings())

	// Re-sync global config's last revision with VPP.
	globalNatDump, err := sc.VPP.DumpNat44Global()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	if globalNatDump.Forwarding {
		// Global NAT was configured by the agent.
		key := nat.GlobalConfigKey()
		value := syncbase.NewChange(nat.GlobalConfigKey(), globalNatDump, 0, datasync.Put)
		sc.LatestRevs.PutWithRevision(key, value)
	} else {
		// Not configured by the agent.
		sc.LatestRevs.Del(nat.GlobalConfigKey())
	}

	// Re-build the global NAT config.
	sc.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
	}
	// - address pool
	if resyncEv.ExternalSNAT.ExternalIP != nil {
		// Address for SNAT:
		sc.natGlobalCfg.AddressPools = append(sc.natGlobalCfg.AddressPools,
			&nat.Nat44Global_AddressPool{
				FirstSrcAddress: resyncEv.ExternalSNAT.ExternalIP.String(),
				VrfId:           ^uint32(0),
			})
	}
	// Address for self-TwiceNAT:
	sc.natGlobalCfg.AddressPools = append(sc.natGlobalCfg.AddressPools,
		&nat.Nat44Global_AddressPool{
			FirstSrcAddress: sc.Contiv.GetNatLoopbackIP().String(),
			VrfId:           ^uint32(0),
			TwiceNat:        true,
		})
	// - frontends
	for frontendIf := range resyncEv.FrontendIfs {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterface{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - backends
	for backendIf := range resyncEv.BackendIfs {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterface{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	//  - post-routing
	if resyncEv.ExternalSNAT.ExternalIfName != "" {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterface{
				Name:          resyncEv.ExternalSNAT.ExternalIfName,
				IsInside:      false,
				OutputFeature: true,
			})
	}
	// - add to the transaction
	putDsl.NAT44Global(sc.natGlobalCfg)

	return dsl.Send().ReceiveReply()
}

// contivServiceToDNat returns DNAT configuration corresponding to a given service.
func (sc *ServiceConfigurator) contivServiceToDNat(service *ContivService) *nat.Nat44DNat_DNatConfig {
	dnat := &nat.Nat44DNat_DNatConfig{}
	dnat.Label = service.ID.String()
	dnat.StMappings = sc.exportDNATMappings(service)
	return dnat
}

// exportDNATMappings exports the corresponding list of D-NAT mappings from a Contiv service.
func (sc *ServiceConfigurator) exportDNATMappings(service *ContivService) []*nat.Nat44DNat_DNatConfig_StaticMapping {
	mappings := []*nat.Nat44DNat_DNatConfig_StaticMapping{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		for _, nodeIP := range sc.nodeIPs.list {
			if nodeIP.To4() != nil {
				nodeIP = nodeIP.To4()
			}
			// Add one mapping for each port.
			for portName, port := range service.Ports {
				if port.NodePort == 0 {
					continue
				}
				mapping := &nat.Nat44DNat_DNatConfig_StaticMapping{}
				mapping.TwiceNat = nat.TwiceNatMode_SELF
				mapping.ExternalIp = nodeIP.String()
				mapping.ExternalPort = uint32(port.NodePort)
				switch port.Protocol {
				case TCP:
					mapping.Protocol = nat.Protocol_TCP
				case UDP:
					mapping.Protocol = nat.Protocol_UDP
				}
				for _, backend := range service.Backends[portName] {
					if service.TrafficPolicy != ClusterWide && !backend.Local {
						// Do not NAT+LB remote backends.
						continue
					}
					local := &nat.Nat44DNat_DNatConfig_StaticMapping_LocalIP{
						LocalIp:   backend.IP.String(),
						LocalPort: uint32(backend.Port),
					}
					if backend.Local {
						local.Probability = LocalVsRemoteProbRatio
					} else {
						local.Probability = 1
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
			mapping := &nat.Nat44DNat_DNatConfig_StaticMapping{}
			mapping.TwiceNat = nat.TwiceNatMode_SELF
			mapping.ExternalIp = externalIP.String()
			mapping.ExternalPort = uint32(port.Port)
			switch port.Protocol {
			case TCP:
				mapping.Protocol = nat.Protocol_TCP
			case UDP:
				mapping.Protocol = nat.Protocol_UDP
			}
			for _, backend := range service.Backends[portName] {
				if service.TrafficPolicy != ClusterWide && !backend.Local {
					// Do not NAT+LB remote backends.
					continue
				}
				local := &nat.Nat44DNat_DNatConfig_StaticMapping_LocalIP{
					LocalIp:   backend.IP.String(),
					LocalPort: uint32(backend.Port),
				}
				if backend.Local {
					local.Probability = LocalVsRemoteProbRatio
				} else {
					local.Probability = 1
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

// exportIdentityMappings returns DNAT configuration with identities to exclude
// VXLAN port and main interface IP (with the exception of node-ports)
// from dynamic mappings.
func (sc *ServiceConfigurator) exportIdentityMappings() *nat.Nat44DNat_DNatConfig {
	idNat := &nat.Nat44DNat_DNatConfig{
		Label: identityDNATLabel,
	}

	if sc.externalSNAT.ExternalIP != nil {
		vxlanID := &nat.Nat44DNat_DNatConfig_IdentityMapping{
			IpAddress: sc.externalSNAT.ExternalIP.String(),
			Protocol:  nat.Protocol_UDP,
			Port:      vxlanPort,
		}
		mainIfID := &nat.Nat44DNat_DNatConfig_IdentityMapping{
			IpAddress: sc.externalSNAT.ExternalIP.String(),
			Protocol:  nat.Protocol_UDP, /* Address-only mappings are dumped with UDP as protocol */
		}
		idNat.IdMappings = append(idNat.IdMappings, vxlanID)
		idNat.IdMappings = append(idNat.IdMappings, mainIfID)
	}

	return idNat
}

// Close deallocates resources held by the configurator.
func (sc *ServiceConfigurator) Close() error {
	return nil
}

// idleNATSessionCleanup performs periodic cleanup of inactive NAT sessions.
// This should be removed once VPP supports timing out of the NAT sessions.
func (sc *ServiceConfigurator) idleNATSessionCleanup() {
	// run only if requested
	if !sc.Contiv.CleanupIdleNATSessions() {
		return
	}

	tcpTimeout := time.Duration(sc.Contiv.GetTCPNATSessionTimeout()) * time.Minute
	otherTimeout := time.Duration(sc.Contiv.GetOtherNATSessionTimeout()) * time.Minute
	if tcpTimeout == 0 {
		tcpTimeout = defaultIdleTCPTimeout
	}
	if otherTimeout == 0 {
		otherTimeout = defaultIdleOtherTimeout
	}

	sc.Log.Infof("NAT session cleanup enabled, TCP timeout=%v, other timeout=%v.", tcpTimeout, otherTimeout)

	// register gauges
	sc.Stats.RegisterGaugeFunc("tcpNatSessions", "Total count of TCP NAT sessions", tcpNatSessionsGauge)
	sc.Stats.RegisterGaugeFunc("otherNatSessions", "Total count of non-TCP NAT sessions", otherNatSessionsGauge)
	sc.Stats.RegisterGaugeFunc("deletedTCPNatSessions", "Total count of deleted TCP NAT sessions", deletedTCPNatSessionsGauge)
	sc.Stats.RegisterGaugeFunc("deletedOtherNatSessions", "Total count of deleted non-TCP NAT sessions", deletedOtherNatSessionsGauge)
	sc.Stats.RegisterGaugeFunc("natSessionDeleteErrors", "Count of errors by NAT session delete", natSessionDeleteErrorsGauge)

	// VPP counts the time from 0 since its start. Let's assume it is now
	// (it shouldn't be more than few seconds since its start).
	zeroTime := time.Now()

	for {
		<-time.After(otherTimeout)

		sc.Log.Debugf("NAT session cleanup started.")

		natUsers := make([][]byte, 0)
		delRules := make([]*nat_api.Nat44DelSession, 0)
		var tcpCount uint64
		var otherCount uint64

		// dump NAT users
		req1 := &nat_api.Nat44UserDump{}
		reqCtx1 := sc.GoVPPChan.SendMultiRequest(req1)
		for {
			msg := &nat_api.Nat44UserDetails{}
			stop, err := reqCtx1.ReceiveReply(msg)
			if stop {
				break // break out of the loop
			}
			if err != nil {
				sc.Log.Errorf("Error by dumping NAT users: %v", err)
			}
			natUsers = append(natUsers, msg.IPAddress)
		}

		// dump NAT sessions per user
		for _, natUser := range natUsers {
			req2 := &nat_api.Nat44UserSessionDump{
				IPAddress: natUser,
			}
			reqCtx2 := sc.GoVPPChan.SendMultiRequest(req2)

			for {
				msg := &nat_api.Nat44UserSessionDetails{}
				stop, err := reqCtx2.ReceiveReply(msg)
				if stop {
					break // break out of the loop
				}
				if err != nil {
					sc.Log.Errorf("Error by dumping NAT sessions: %v", err)
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
						sc.Log.Debugf("Deleting inactive NAT session (proto %d), last heard %v ago: %v", msg.Protocol, time.Since(lastHeard), msg)

						delRule := &nat_api.Nat44DelSession{
							IsIn:     1,
							Address:  msg.InsideIPAddress,
							Port:     msg.InsidePort,
							Protocol: uint8(msg.Protocol),
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

		sc.Log.Debugf("There are %d TCP / %d other NAT sessions, %d will be deleted", tcpCount, otherCount, len(delRules))
		atomic.StoreUint64(&tcpNatSessionCount, tcpCount)
		atomic.StoreUint64(&otherNatSessionCount, otherCount)

		// delete the old sessions
		for _, r := range delRules {
			msg := &nat_api.Nat44DelSessionReply{}
			err := sc.GoVPPChan.SendRequest(r).ReceiveReply(msg)
			if err != nil || msg.Retval != 0 {
				sc.Log.Errorf("Error by deleting NAT session: %v, retval=%d, req: %v", err, msg.Retval, r)
				atomic.AddUint64(&natSessionDeleteErrorCount, 1)
			} else {
				if r.Protocol == 6 {
					atomic.AddUint64(&deletedTCPNatSessionCount, 1)
				} else {
					atomic.AddUint64(&deletedOtherNatSessionCount, 1)
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
