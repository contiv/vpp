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
	"errors"
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

	natMaps, err := sc.exportNATMappings(service)
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

	oldNatMaps, err := sc.exportNATMappings(oldService)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	newNatMaps, err := sc.exportNATMappings(newService)
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

	natMaps, err := sc.exportNATMappings(service)
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

// UpdateFrontendAddrs updates the list of addresses on which services are exposed.
func (sc *ServiceConfigurator) UpdateFrontendAddrs(oldAddrs, newAddrs *IPAddresses) error {
	sc.Log.WithFields(logging.Fields{
		"oldAddrs": oldAddrs,
		"newAddrs": newAddrs,
	}).Debug("ServiceConfigurator - UpdateFrontendAddrs()")

	// Configure new NAT external addresses.
	for _, newAddr := range newAddrs.List() {
		new := true
		for _, oldAddr := range oldAddrs.List() {
			if oldAddr.Equal(newAddr) {
				new = false
				break
			}
		}
		if new {
			err := sc.setNATAddress(newAddr, false, true)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Unconfigure obsolete NAT external addresses.
	for _, oldAddr := range oldAddrs.List() {
		removed := true
		for _, newAddr := range newAddrs.List() {
			if oldAddr.Equal(newAddr) {
				removed = false
				break
			}
		}
		if removed {
			err := sc.setNATAddress(oldAddr, false, false)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
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
			err := sc.setInterfaceNATFeature(newIf, false, true)
			if err != nil {
				sc.Log.Error(err)
				return err
			}
		}
	}

	// Interfaces which are no longer frontends were removed from VPP
	//  => nothing to be done here.
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
			err := sc.setInterfaceNATFeature(newIf, true, true)
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
			err := sc.setInterfaceNATFeature(oldIf, true, false)
			if err != nil {
				// Interface may have already been removed thus the error is ignored.
				sc.Log.WithFields(logging.Fields{
					"ifName": oldIf,
					"err":    err,
				}).Debug("Failed to unconfigure NAT in2out feature from interface")
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

	// Try to get Node IP.
	nodeIP, err := sc.getNodeIP()
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

	// Dump NAT address pools.
	snatPoolDump, dnatPoolDump, err := sc.dumpAddressPools()
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Dump currently configured local frontend and backend interfaces.
	frontendIfsDump, backendIfsDump, err := sc.dumpNATInterfaces()
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

	// Add Node IP to the pool for SNAT.
	if !snatPoolDump.Has(nodeIP) {
		err = sc.setNATAddress(nodeIP, true, true)
		if err != nil {
			sc.Log.Error(err)
			return err
		}
	}

	// Update frontend addresses.
	err = sc.UpdateFrontendAddrs(dnatPoolDump, resyncEv.FrontendAddrs)
	if err != nil {
		sc.Log.Error(err)
		return err
	}

	// Export and update NAT Mappings.
	natMaps := []*NATMapping{}
	for _, svc := range resyncEv.Services {
		exportedMaps, err := sc.exportNATMappings(svc)
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

	return nil
}

// exportNATMappings exports the corresponding list of NAT mappings from a Contiv service.
func (sc *ServiceConfigurator) exportNATMappings(service *ContivService) ([]*NATMapping, error) {
	mappings := []*NATMapping{}

	// Export NAT mappings for NodePort services.
	if service.HasNodePort() {
		// Try to get Node IP.
		nodeIP, err := sc.getNodeIP()
		if err != nil {
			sc.Log.Error(err)
			return nil, err
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
			mapping.TwiceNat = service.SNAT
			for _, backend := range service.Backends[portName] {
				if !service.SNAT && !backend.Local {
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
			mapping.TwiceNat = service.SNAT
			for _, backend := range service.Backends[portName] {
				if !service.SNAT && !backend.Local {
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

/**** Helper methods ****/

func (sc *ServiceConfigurator) getNodeIP() (net.IP, error) {
	nodeIPNet := sc.Contiv.GetHostIPNetwork()
	if nodeIPNet == nil {
		return nil, errors.New("failed to get Node IP")
	}
	nodeIP := nodeIPNet.IP.To4()
	if nodeIP == nil {
		// TODO: IPv6 support
		return nil, errors.New("node IP is not IPv4 address")
	}
	return nodeIP, nil
}
