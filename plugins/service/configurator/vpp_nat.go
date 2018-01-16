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

//go:generate binapi-generator --input-file=/usr/share/vpp/api/nat.api.json --output-dir=bin_api

package configurator

import (
	"errors"
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/service/configurator/bin_api/nat"
)

// NATMapping represents a single VPP NAT mapping (with single local backend
// or multiple load-balanced ones).
type NATMapping struct {
	ExternalIP   net.IP
	ExternalPort uint16
	Protocol     ProtocolType
	VrfID        uint32
	TwiceNat     uint8
	Locals       []NATMappingLocal
}

// NATMappingLocal represents a single backend for VPP NAT mapping.
type NATMappingLocal struct {
	Address     net.IP
	Port        uint16
	Probability uint8
}

// isNat44ForwardingEnabled checks with VPP if NAT44 forwarding is enabled.
func (sc *ServiceConfigurator) isNat44ForwardingEnabled() (bool, error) {
	req := &nat.Nat44ForwardingIsEnabled{}
	reply := &nat.Nat44ForwardingIsEnabledReply{}
	err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Enabled > 0 {
		return true, err
	}
	return false, err
}

// enableNat44Forwarding enables NAT44 forwarding, meaning that traffic not matching
// any NAT rules will be just forwarded and not dropped.
func (sc *ServiceConfigurator) enableNat44Forwarding() error {
	alreadyEnabled, err := sc.isNat44ForwardingEnabled()
	if err != nil || alreadyEnabled {
		return err
	}
	req := &nat.Nat44ForwardingEnableDisable{
		Enable: 1,
	}
	reply := &nat.Nat44ForwardingEnableDisableReply{}
	err = sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("attempt to enable NAT44 forwarding returned non zero error code (%v)",
			reply.Retval)
	}
	if err != nil {
		return err
	}

	sc.Log.Debug("NAT44 forwarding was enabled")
	return nil
}

// setNodeIPForSNAT adds Node IP into the SNAT address pool if it is not already there.
func (sc *ServiceConfigurator) setNodeIPForSNAT() error {
	nodeIPNet := sc.Contiv.GetHostIPNetwork()
	if nodeIPNet == nil {
		return errors.New("failed to get Node IP")
	}
	nodeIP := nodeIPNet.IP.To4()
	if nodeIP == nil {
		// TODO: IPv6 support
		return errors.New("node IP is not IPv4 address")
	}

	// Check if the address is already in the pool.
	snatAddrPool, err := sc.dumpSNATAddressPool()
	if err != nil {
		return err
	}
	for _, addr := range snatAddrPool {
		if addr.Equal(nodeIP) {
			/* already installed */
			return nil
		}
	}

	// Add node IP into the "twice-NAT" pool for SNAT.
	req := &nat.Nat44AddDelAddressRange{
		VrfID:    ^uint32(0),
		TwiceNat: 1,
		IsAdd:    1,
	}
	copy(req.FirstIPAddress, nodeIP)
	copy(req.LastIPAddress, nodeIP)
	reply := &nat.Nat44AddDelAddressRangeReply{}
	err = sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("attempt to add Node IP into the SNAT address pool returned non zero error code (%v)",
			reply.Retval)
	}
	if err != nil {
		return err
	}

	sc.Log.Debug("Node IP was added into the SNAT address pool")
	return nil
}

// setInterfaceNATFeature enables(isAdd=true)/disables NATing for ingress or egress(isInside=true)
// traffic going through a given interface(ifName).
func (sc *ServiceConfigurator) setInterfaceNATFeature(ifName string, isInside bool, isAdd bool) error {
	// TODO
	return nil
}

// setExternalNATAddress adds or removes given address from the pool of NATed
// external addresses.
func (sc *ServiceConfigurator) setExternalNATAddress(address net.IP, isAdd bool) error {
	// TODO
	return nil
}

// syncNATMappings updates VPP NAT mappings so that <have> becomes <want>.
func (sc *ServiceConfigurator) syncNATMappings(have []*NATMapping, want []*NATMapping) error {
	// TODO
	return nil
}

/***** Dumps *****/

// dumpAddressPool returns all addresses currently installed in the NAT plugin's
// SNAT or DNAT address pool.
func (sc *ServiceConfigurator) dumpAddressPool(snat bool) ([]net.IP, error) {
	addresses := []net.IP{}
	req := &nat.Nat44AddressDump{}
	reqContext := sc.GoVPPChan.SendMultiRequest(req)

	for {
		msg := &nat.Nat44AddressDetails{}
		stop, err := reqContext.ReceiveReply(msg)
		if err != nil {
			sc.Log.WithField("err", err).Error("Failed to get NAT44 address details")
			return addresses, err
		}
		if stop {
			break
		}
		if (snat && msg.TwiceNat == 0) || (!snat && msg.TwiceNat > 0) {
			continue
		}
		addr := make(net.IP, net.IPv4len)
		copy(addr, msg.IPAddress[:])
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

// dumpSNATAddressPool returns all addresses currently installed in the NAT plugin's
// SNAT address pool.
func (sc *ServiceConfigurator) dumpSNATAddressPool() ([]net.IP, error) {
	return sc.dumpAddressPool(true)
}

// dumpSNATAddressPool returns all addresses currently installed in the NAT plugin's
// DNAT address pool.
func (sc *ServiceConfigurator) dumpDNATAddressPool() ([]net.IP, error) {
	return sc.dumpAddressPool(false)
}

// dumpServices returns a list of currently configured NAT mappings.
func (sc *ServiceConfigurator) dumpNATMappings() ([]*NATMapping, error) {
	mappings := []*NATMapping{}
	// TODO
	return mappings, nil
}

// dumpFrontendAddrs returns a list of currently configured frontend addresses.
func (sc *ServiceConfigurator) dumpFrontendAddrs() (IPAddresses, error) {
	// TODO
	return NewIPAddresses(), nil
}

// dumpLocalBackendIfs returns a list of currently configured backend interfaces.
func (sc *ServiceConfigurator) dumpLocalBackendIfs() (Interfaces, error) {
	// TODO
	return NewInterfaces(), nil
}

// dumpLocalFrontendIfs returns a list of currently configured frontend interfaces.
func (sc *ServiceConfigurator) dumpLocalFrontendIfs() (Interfaces, error) {
	// TODO
	return NewInterfaces(), nil
}
