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

	govpp "git.fd.io/govpp.git/api"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
)

// LocalVsRemoteProbRatio tells how much more likely a local backend is to receive
// traffic as opposed to a remote backend.
const LocalVsRemoteProbRatio uint8 = 2

// ServiceConfigurator implements ServiceConfiguratorAPI.
type ServiceConfigurator struct {
	Deps

	nodeIPs []net.IP
}

// Deps lists dependencies of ServiceConfigurator.
type Deps struct {
	Log              logging.Logger
	Contiv           contiv.API         /* to get the Node IP */
	VPP              defaultplugins.API /* interface indexes */
	GoVPPChan        *govpp.Channel     /* until supported in vpp-agent, we call NAT binary APIs directly */
	GoVPPChanBufSize int
}

// Init initializes service configurator.
func (sc *ServiceConfigurator) Init() error {
	return nil
}

// AddService installs NAT rules for a newly added service.
func (sc *ServiceConfigurator) AddService(service *ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"service": service,
	}).Debug("ServiceConfigurator - AddService()")

	natMaps, err := sc.exportNATMappings(sc.nodeIPs, service)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	err = sc.syncNATMappings([]*NATMapping{}, natMaps)
	if err != nil {
		sc.Log.Error(err)
		return err
	}
	return nil
}

// UpdateService reflects a change in the configuration of a service with
// the smallest number of VPP/NAT binary API calls necessary.
func (sc *ServiceConfigurator) UpdateService(oldService, newService *ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"oldService": oldService,
		"newService": newService,
	}).Debug("ServiceConfigurator - UpdateService()")

	oldNatMaps, err := sc.exportNATMappings(sc.nodeIPs, oldService)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	newNatMaps, err := sc.exportNATMappings(sc.nodeIPs, newService)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	err = sc.syncNATMappings(oldNatMaps, newNatMaps)
	if err != nil {
		sc.Log.Error(err)
		return err
	}
	return nil
}

// DeleteService removes NAT configuration associated with a newly undeployed
// service.
func (sc *ServiceConfigurator) DeleteService(service *ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"service": service,
	}).Debug("ServiceConfigurator - DeleteService()")

	natMaps, err := sc.exportNATMappings(sc.nodeIPs, service)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	err = sc.syncNATMappings(natMaps, []*NATMapping{})
	if err != nil {
		sc.Log.Error(err)
		return err
	}
	return nil
}

// UpdateNodePortServices updates configuration of nodeport services to reflect
// changed list of all node IPs in the cluster.
func (sc *ServiceConfigurator) UpdateNodePortServices(nodeIPs []net.IP, npServices []*ContivService) error {
	sc.Log.WithFields(logging.Fields{
		"nodeIPs":    nodeIPs,
		"npServices": npServices,
	}).Debug("ServiceConfigurator - UpdateNodePortServices()")

	// Export current NAT Mappings for nodePort services.
	currentNatMaps := []*NATMapping{}
	for _, svc := range npServices {
		exportedMaps, err := sc.exportNATMappings(sc.nodeIPs, svc)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
		currentNatMaps = append(currentNatMaps, exportedMaps...)
	}

	// Export NAT mapping using the new internal node IP.
	newNatMaps := []*NATMapping{}
	for _, svc := range npServices {
		exportedMaps, err := sc.exportNATMappings(nodeIPs, svc)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
		newNatMaps = append(newNatMaps, exportedMaps...)
	}

	// Update outdated NAT mappings.
	err := sc.syncNATMappings(currentNatMaps, newNatMaps)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Update cached internal node IP.
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

	// Configure new frontend interfaces.
	for newIf := range newIfNames {
		new := true
		for oldIf := range oldIfNames {
			if oldIf == newIf {
				new = false
				break
			}
		}
		if new {
			err := sc.setInterfaceNATFeature(newIf, false, false, true)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Unconfigure interfaces which are no longer frontends (to be removed from VPP).
	for oldIf := range oldIfNames {
		removed := true
		for newIf := range newIfNames {
			if oldIf == newIf {
				removed = false
				break
			}
		}
		if removed {
			err := sc.setInterfaceNATFeature(oldIf, false, false, false)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}
	return nil
}

// UpdateLocalBackendIfs updates the list of interfaces connecting service
// backends with VPP (enabled in2out VPP/NAT feature).
func (sc *ServiceConfigurator) UpdateLocalBackendIfs(oldIfNames, newIfNames Interfaces) error {
	sc.Log.WithFields(logging.Fields{
		"oldIfNames": oldIfNames,
		"newIfNames": newIfNames,
	}).Debug("ServiceConfigurator - UpdateLocalBackendIfs()")

	// Configure new backend interfaces.
	for newIf := range newIfNames {
		new := true
		for oldIf := range oldIfNames {
			if oldIf == newIf {
				new = false
				break
			}
		}
		if new {
			err := sc.setInterfaceNATFeature(newIf, false, true, true)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Unconfigure interfaces that no longer connect service backends.
	for oldIf := range oldIfNames {
		removed := true
		for newIf := range newIfNames {
			if oldIf == newIf {
				removed = false
				break
			}
		}
		if removed {
			err := sc.setInterfaceNATFeature(oldIf, false, true, false)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}
	return nil
}

// Resync completely replaces the current NAT configuration with the provided
// full state of K8s services.
func (sc *ServiceConfigurator) Resync(resyncEv *ResyncEventData) error {
	var err error
	sc.Log.WithFields(logging.Fields{
		"resyncEv": resyncEv,
	}).Debug("ServiceConfigurator - Resync()")

	// Updated cached internal node IP.
	sc.nodeIPs = resyncEv.NodeIPs

	// Dump NAT address pool.
	natPoolDump, err := sc.dumpAddressPool()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Dump currently installed NAT mappings.
	natMapDump, err := sc.dumpNATMappings()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Dump currently configured local frontend and backend interfaces.
	frontendIfsDump, backendIfsDump, err := sc.dumpNATInterfaces(false)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Dump currently configured local frontend and backend interfaces for *post*-routing.
	postFrontendIfsDump, postBackendIfsDump, err := sc.dumpNATInterfaces(true)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Enable NAT44 forwarding.
	err = sc.enableNat44Forwarding()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Insert address used for SNAT into the NAT address pool if it is not already there.
	if resyncEv.ExternalSNAT.ExternalIP != nil {
		extAddrInstalled := false
		for _, addr := range natPoolDump.List() {
			if addr.Equal(resyncEv.ExternalSNAT.ExternalIP) {
				extAddrInstalled = true
				break
			}
		}
		if !extAddrInstalled {
			err = sc.setNATAddress(resyncEv.ExternalSNAT.ExternalIP, true)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Export and update NAT Mappings.
	natMaps := []*NATMapping{}
	for _, svc := range resyncEv.Services {
		exportedMaps, err := sc.exportNATMappings(sc.nodeIPs, svc)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
		natMaps = append(natMaps, exportedMaps...)
	}
	err = sc.syncNATMappings(natMapDump, natMaps)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Remove obsolete addresses from the NAT pool.
	for _, addr := range natPoolDump.List() {
		if resyncEv.ExternalSNAT.ExternalIP == nil || !addr.Equal(resyncEv.ExternalSNAT.ExternalIP) {
			err = sc.setNATAddress(addr, false)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Update local backend interfaces.
	err = sc.UpdateLocalBackendIfs(backendIfsDump, resyncEv.BackendIfs)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Update local frontend interfaces.
	err = sc.UpdateLocalFrontendIfs(frontendIfsDump, resyncEv.FrontendIfs)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Update frontend and backend interfaces for *post*-routing.
	// -> no backend should be in the postrouting mode
	for ifName := range postBackendIfsDump {
		err := sc.setInterfaceNATFeature(ifName, true, true, false)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
	}
	// -> make sure the SNATed interface is the only one in the postrouting mode
	snatEnabled := false
	for ifName := range postFrontendIfsDump {
		if ifName == resyncEv.ExternalSNAT.ExternalIfName {
			snatEnabled = true
		} else {
			err := sc.setInterfaceNATFeature(ifName, true, false, false)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}
	if resyncEv.ExternalSNAT.ExternalIfName != "" && !snatEnabled {
		err := sc.setInterfaceNATFeature(resyncEv.ExternalSNAT.ExternalIfName, true, false, true)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
	}

	return nil
}

// exportNATMappings exports the corresponding list of NAT mappings from a Contiv service.
func (sc *ServiceConfigurator) exportNATMappings(nodeIPs []net.IP, service *ContivService) ([]*NATMapping, error) {
	mappings := []*NATMapping{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		for _, nodeIP := range nodeIPs {
			if nodeIP.To4() != nil {
				nodeIP = nodeIP.To4()
			}
			// Add one mapping for each port.
			for portName, port := range service.Ports {
				if port.NodePort == 0 {
					continue
				}
				mapping := NewNATMapping()
				mapping.ExternalIP = nodeIP
				mapping.ExternalPort = port.NodePort
				mapping.Protocol = port.Protocol
				for _, backend := range service.Backends[portName] {
					if service.TrafficPolicy != ClusterWide && !backend.Local {
						// Do not NAT+LB remote backends.
						continue
					}
					local := &NATMappingLocal{
						Address: backend.IP,
						Port:    backend.Port,
					}
					if backend.Local {
						local.Probability = LocalVsRemoteProbRatio
					} else {
						local.Probability = 1
					}
					mapping.Locals = append(mapping.Locals, local)
				}
				if len(mapping.Locals) == 0 {
					continue
				}
				if len(mapping.Locals) == 1 {
					// For single backend we use "1" to represent the probability
					// (not really configured).
					mapping.Locals[0].Probability = 1
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
			mapping := NewNATMapping()
			mapping.ExternalIP = externalIP
			mapping.ExternalPort = port.Port
			mapping.Protocol = port.Protocol
			for _, backend := range service.Backends[portName] {
				if service.TrafficPolicy != ClusterWide && !backend.Local {
					// Do not NAT+LB remote backends.
					continue
				}
				local := &NATMappingLocal{
					Address: backend.IP,
					Port:    backend.Port,
				}
				if backend.Local {
					local.Probability = LocalVsRemoteProbRatio
				} else {
					local.Probability = 1
				}
				mapping.Locals = append(mapping.Locals, local)
			}
			if len(mapping.Locals) == 0 {
				continue
			}
			if len(mapping.Locals) == 1 {
				// For single backend we use "1" to represent the probability
				// (not really configured).
				mapping.Locals[0].Probability = 1
			}
			mappings = append(mappings, mapping)
		}
	}

	return mappings, nil
}

// Close deallocates resources held by the configurator.
func (sc *ServiceConfigurator) Close() error {
	return nil
}
