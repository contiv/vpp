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
	"net"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"
)

// LocalVsRemoteProbRatio tells how much more likely a local backend is to receive
// traffic as opposed to a remote backend.
const LocalVsRemoteProbRatio uint32 = 2

// ServiceConfigurator implements ServiceConfiguratorAPI.
type ServiceConfigurator struct {
	Deps

	natGlobalCfg *nat.Nat44Global
	nodeIPs      []net.IP
}

// Deps lists dependencies of ServiceConfigurator.
type Deps struct {
	Log           logging.Logger
	Contiv        contiv.API         /* to get the Node IP */
	VPP           defaultplugins.API /* for DumpNat44Global & DumpNat44DNat */
	NATTxnFactory func() (dsl linux.DataChangeDSL)
}

// Init initializes service configurator.
func (sc *ServiceConfigurator) Init() error {
	sc.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
	}
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
func (sc *ServiceConfigurator) UpdateNodePortServices(nodeIPs []net.IP, npServices []*ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"nodeIPs":    nodeIPs,
		"npServices": npServices,
	}).Debug("ServiceConfigurator - UpdateNodePortServices()")

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

	// Update cached internal node IPs.
	sc.nodeIPs = nodeIPs
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
	// - keep non-frontends unchanged
	newNatIfs := []*nat.Nat44Global_NatInterfaces{}
	for _, natIf := range sc.natGlobalCfg.NatInterfaces {
		if natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of frontends
	for frontendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&nat.Nat44Global_NatInterfaces{
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
	// - keep non-backends unchanged
	newNatIfs := []*nat.Nat44Global_NatInterfaces{}
	for _, natIf := range sc.natGlobalCfg.NatInterfaces {
		if !natIf.IsInside || natIf.OutputFeature {
			newNatIfs = append(newNatIfs, natIf)
		}
	}
	// - re-create the list of backends
	for backendIf := range newIfNames {
		newNatIfs = append(newNatIfs,
			&nat.Nat44Global_NatInterfaces{
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

	// Re-build the global NAT config.
	sc.natGlobalCfg = &nat.Nat44Global{
		Forwarding: true,
	}
	// - address pool
	if resyncEv.ExternalSNAT.ExternalIP != nil {
		sc.natGlobalCfg.AddressPools = append(sc.natGlobalCfg.AddressPools,
			&nat.Nat44Global_AddressPools{
				FirstSrcAddress: resyncEv.ExternalSNAT.ExternalIP.String(),
				LastSrcAddress:  resyncEv.ExternalSNAT.ExternalIP.String(),
				VrfId:           ^uint32(0),
			})
	}
	// - frontends
	for frontendIf := range resyncEv.FrontendIfs {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterfaces{
				Name:          frontendIf,
				IsInside:      false,
				OutputFeature: false,
			})
	}
	// - backends
	for backendIf := range resyncEv.BackendIfs {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterfaces{
				Name:          backendIf,
				IsInside:      true,
				OutputFeature: false,
			})
	}
	//  - post-routing
	if resyncEv.ExternalSNAT.ExternalIfName != "" {
		sc.natGlobalCfg.NatInterfaces = append(sc.natGlobalCfg.NatInterfaces,
			&nat.Nat44Global_NatInterfaces{
				Name:          resyncEv.ExternalSNAT.ExternalIfName,
				IsInside:      false,
				OutputFeature: true,
			})
	}
	// - add to the transaction
	putDsl.NAT44Global(sc.natGlobalCfg)

	// Dump currently configured services.
	dnatDump, err := sc.VPP.DumpNat44DNat()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Resync DNAT configuration.
	// - remove obsolete DNATs
	for _, dnatConfig := range dnatDump.DnatConfig {
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
func (sc *ServiceConfigurator) exportDNATMappings(service *ContivService) []*nat.Nat44DNat_DNatConfig_StaticMappings {
	mappings := []*nat.Nat44DNat_DNatConfig_StaticMappings{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		for _, nodeIP := range sc.nodeIPs {
			if nodeIP.To4() != nil {
				nodeIP = nodeIP.To4()
			}
			// Add one mapping for each port.
			for portName, port := range service.Ports {
				if port.NodePort == 0 {
					continue
				}
				mapping := &nat.Nat44DNat_DNatConfig_StaticMappings{}
				mapping.ExternalIP = nodeIP.String()
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
					local := &nat.Nat44DNat_DNatConfig_StaticMappings_LocalIPs{
						LocalIP:   backend.IP.String(),
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
					// For single backend we use "1" to represent the probability
					// (not really configured).
					mapping.LocalIps[0].Probability = 1
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
			mapping := &nat.Nat44DNat_DNatConfig_StaticMappings{}
			mapping.ExternalIP = externalIP.String()
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
				local := &nat.Nat44DNat_DNatConfig_StaticMappings_LocalIPs{
					LocalIP:   backend.IP.String(),
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
				// For single backend we use "1" to represent the probability
				// (not really configured).
				mapping.LocalIps[0].Probability = 1
			}
			mappings = append(mappings, mapping)
		}
	}

	return mappings
}

// Close deallocates resources held by the configurator.
func (sc *ServiceConfigurator) Close() error {
	return nil
}
