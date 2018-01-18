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
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/service/configurator/bin_api/nat"
	"github.com/ligato/cn-infra/logging"
)

// NATMapping represents a single VPP NAT mapping (with single local backend
// or multiple load-balanced ones).
type NATMapping struct {
	ExternalIP   net.IP
	ExternalPort uint16
	Protocol     ProtocolType
	TwiceNat     bool
	Locals       []*NATMappingLocal
}

// NewNATMapping is a constructor for NATMapping.
func NewNATMapping() *NATMapping {
	return &NATMapping{
		Locals: []*NATMappingLocal{},
	}
}

// String converts a NAT mapping into a human-readable string.
func (nm NATMapping) String() string {
	locals := ""
	for idx, local := range nm.Locals {
		locals += local.String()
		if idx < len(nm.Locals)-1 {
			locals += ", "
		}
	}
	return fmt.Sprintf("NAT-Mapping <ExternalIP:%s ExternalPort:%d Protocol:%s TwiceNat:%t Locals:[%s]>",
		nm.ExternalIP.String(), nm.ExternalPort, nm.Protocol.String(), nm.TwiceNat,
		locals)
}

// NATMappingLocal represents a single backend for VPP NAT mapping.
type NATMappingLocal struct {
	Address     net.IP
	Port        uint16
	Probability uint8
}

// String converts a NAT mapping local endpoint into a human-readable string.
func (nml NATMappingLocal) String() string {
	return fmt.Sprintf("Local <Address:%s Port:%d Probability:%d>",
		nml.Address.String(), nml.Port, nml.Probability)
}

// Equal compares this mapping with another for equality.
func (nm *NATMapping) Equal(nm2 *NATMapping) bool {
	// Compare locals.
	if len(nm.Locals) != len(nm2.Locals) {
		return false
	}
	// -> test nm.Locals is a subset of nm2.Locals
	for _, local := range nm.Locals {
		found := false
		for _, local2 := range nm2.Locals {
			if local.Equal(local2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// -> test nm2.Locals is a subset of nm.Locals
	for _, local2 := range nm2.Locals {
		found := false
		for _, local := range nm.Locals {
			if local.Equal(local2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Compare the rest of the attributes.
	return nm.ExternalIP.Equal(nm2.ExternalIP) &&
		nm.ExternalPort == nm2.ExternalPort &&
		nm.Protocol == nm2.Protocol &&
		nm.TwiceNat == nm.TwiceNat
}

// Equal compares this local with another for equality.
func (nml *NATMappingLocal) Equal(nml2 *NATMappingLocal) bool {
	return nml.Address.Equal(nml2.Address) &&
		nml.Port == nml2.Port &&
		nml.Probability == nml2.Probability
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

// setInterfaceNATFeature enables(isAdd=true)/disables NATing for ingress or egress(isInside=true)
// traffic going through a given interface(ifName).
func (sc *ServiceConfigurator) setInterfaceNATFeature(ifName string, isInside bool, isAdd bool) error {
	var op string
	var feature string

	ifIndex, _, exists := sc.VPP.GetSwIfIndexes().LookupIdx(ifName)
	if !exists {
		return fmt.Errorf("failed to get interface index corresponding to interface name: %s", ifName)
	}

	req := &nat.Nat44InterfaceAddDelFeature{
		SwIfIndex: ifIndex,
	}
	if isAdd {
		req.IsAdd = 1
		op = "enable"
	} else {
		op = "disable"
	}
	if isInside {
		req.IsInside = 1
		feature = "in2out"
	} else {
		feature = "out2in"
	}
	reply := &nat.Nat44InterfaceAddDelFeatureReply{}
	err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("attempt to %s NAT44 feature '%s' for interface '%s' returned non zero error code (%v)",
			op, feature, ifName, reply.Retval)
	}
	if err != nil {
		return err
	}

	sc.Log.Debugf("Feature '%s' was %sd for interface '%s'", feature, op, ifName)
	return nil
}

// setNATAddress adds or removes given IP to/from the pool of addresses for SNAT or DNAT.
func (sc *ServiceConfigurator) setNATAddress(address net.IP, snat, isAdd bool) error {
	var pool string

	if address.To4() == nil {
		// TODO: IPv6 support
		return fmt.Errorf("'%s' is not IPv4 address", address.String())
	}

	req := &nat.Nat44AddDelAddressRange{
		VrfID: ^uint32(0),
	}
	if snat {
		req.TwiceNat = 1
		pool = "SNAT"
	} else {
		pool = "DNAT"
	}
	if isAdd {
		req.IsAdd = 1
	}
	req.FirstIPAddress = make([]byte, net.IPv4len)
	copy(req.FirstIPAddress, address.To4())
	req.LastIPAddress = make([]byte, net.IPv4len)
	copy(req.LastIPAddress, address.To4())
	reply := &nat.Nat44AddDelAddressRangeReply{}

	err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		if isAdd {
			return fmt.Errorf("attempt to add '%s' into the %s address pool returned non zero error code (%v)",
				address.String(), pool, reply.Retval)
		}
		return fmt.Errorf("attempt to remove '%s' from the %s address pool returned non zero error code (%v)",
			address.String(), pool, reply.Retval)
	}
	if err != nil {
		return err
	}

	if isAdd {
		sc.Log.Debugf("IP address '%s' was added into the %s address pool", address.String(), pool)
	} else {
		sc.Log.Debugf("IP address '%s' was removed from the %s address pool", address.String(), pool)
	}
	return nil
}

// setNATMapping adds or removes a given NAT mapping.
func (sc *ServiceConfigurator) setNATMapping(mapping *NATMapping, isAdd bool) error {
	var op string
	if isAdd {
		op = "add"
	} else {
		op = "remove"
	}

	if mapping.ExternalIP.To4() == nil {
		// TODO: IPv6 support
		return fmt.Errorf("'%s' is not IPv4 address", mapping.ExternalIP.String())
	}

	if len(mapping.Locals) == 1 {
		if mapping.Locals[0].Address.To4() == nil {
			// TODO: IPv6 support
			return fmt.Errorf("'%s' is not IPv4 address", mapping.Locals[0].Address.String())
		}
		// Single-backend NAT mapping.
		req := &nat.Nat44AddDelStaticMapping{
			VrfID: ^uint32(0),
			/* Out2inOnly: 1, */
			AddrOnly:          0,
			Protocol:          uint8(mapping.Protocol),
			ExternalPort:      mapping.ExternalPort,
			ExternalSwIfIndex: ^uint32(0),
			LocalPort:         mapping.Locals[0].Port,
		}
		req.ExternalIPAddress = make([]byte, net.IPv4len)
		copy(req.ExternalIPAddress, mapping.ExternalIP.To4())
		req.LocalIPAddress = make([]byte, net.IPv4len)
		copy(req.LocalIPAddress, mapping.Locals[0].Address.To4())
		if mapping.TwiceNat {
			req.TwiceNat = 1
		}
		if isAdd {
			req.IsAdd = 1
		}

		reply := &nat.Nat44AddDelStaticMappingReply{}

		err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
		if reply.Retval != 0 {
			return fmt.Errorf("attempt to %s NAT mapping returned non zero error code (%v)",
				op, reply.Retval)
		}
		return err
	}

	// Multiple-backends NAT mapping.
	req := &nat.Nat44AddDelLbStaticMapping{
		VrfID:        ^uint32(0),
		Out2inOnly:   1,
		Protocol:     uint8(mapping.Protocol),
		ExternalPort: mapping.ExternalPort,
		LocalNum:     uint8(len(mapping.Locals)),
		Locals:       []nat.Nat44LbAddrPort{},
	}
	req.ExternalAddr = make([]byte, net.IPv4len)
	copy(req.ExternalAddr, mapping.ExternalIP.To4())
	if mapping.TwiceNat {
		req.TwiceNat = 1
	}
	if isAdd {
		req.IsAdd = 1
	}
	for _, local := range mapping.Locals {
		if local.Address.To4() == nil {
			// TODO: IPv6 support
			fmt.Errorf("'%s' is not IPv4 address", local.Address.String())
		}
		reqLocal := nat.Nat44LbAddrPort{
			Port:        local.Port,
			Probability: local.Probability,
		}
		reqLocal.Addr = make([]byte, net.IPv4len)
		copy(reqLocal.Addr, local.Address.To4())
		req.Locals = append(req.Locals, reqLocal)
	}

	reply := &nat.Nat44AddDelLbStaticMappingReply{}

	err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("attempt to %s NAT mapping returned non zero error code (%v)",
			op, reply.Retval)
	}
	return err
}

// syncNATMappings updates VPP NAT mappings so that <have> becomes <want>.
func (sc *ServiceConfigurator) syncNATMappings(have []*NATMapping, want []*NATMapping) error {
	// Remove obsolete NAT mappings.
	for _, haveMapping := range have {
		removed := true
		for _, wantMapping := range want {
			if wantMapping.Equal(haveMapping) {
				removed = false
				break
			}
		}
		if removed {
			err := sc.setNATMapping(haveMapping, false)
			if err == nil {
				sc.Log.WithFields(logging.Fields{
					"mapping": haveMapping.String(),
				}).Debug("NAT mapping was removed")
			} else {
				sc.Log.WithFields(logging.Fields{
					"err":     err,
					"mapping": haveMapping.String(),
				}).Error("Failed to remove NAT mapping")
				return err
			}
		}
	}

	// Add new NAT mappings.
	for _, wantMapping := range want {
		new := true
		for _, haveMapping := range have {
			if wantMapping.Equal(haveMapping) {
				new = false
				break
			}
		}
		if new {
			err := sc.setNATMapping(wantMapping, true)
			if err == nil {
				sc.Log.WithFields(logging.Fields{
					"mapping": wantMapping.String(),
				}).Debug("NAT mapping was added")
			} else {
				sc.Log.WithFields(logging.Fields{
					"err":     err,
					"mapping": wantMapping.String(),
				}).Error("Failed to add NAT mapping")
				return err
			}
		}
	}
	return nil
}

/***** Dumps *****/

// dumpAddressPool returns all addresses currently installed in the NAT plugin's
// SNAT or DNAT address pool.
func (sc *ServiceConfigurator) dumpAddressPools() (snat, dnat *IPAddresses, err error) {
	snat = NewIPAddresses()
	dnat = NewIPAddresses()
	req := &nat.Nat44AddressDump{}
	reqContext := sc.GoVPPChan.SendMultiRequest(req)

	for {
		msg := &nat.Nat44AddressDetails{}
		stop, err := reqContext.ReceiveReply(msg)
		if err != nil {
			sc.Log.WithField("err", err).Error("Failed to get NAT44 address details")
			return snat, dnat, err
		}
		if stop {
			break
		}
		addr := make(net.IP, net.IPv4len)
		copy(addr, msg.IPAddress[:])
		if msg.TwiceNat == 0 {
			dnat.Add(addr)
		} else {
			snat.Add(addr)
		}
	}
	return snat, dnat, nil
}

// dumpServices returns a list of currently configured NAT mappings.
func (sc *ServiceConfigurator) dumpNATMappings() ([]*NATMapping, error) {
	mappings := []*NATMapping{}

	// Dump mappings with load balancing.
	req1 := &nat.Nat44LbStaticMappingDump{}
	reqContext1 := sc.GoVPPChan.SendMultiRequest(req1)
	for {
		msg := &nat.Nat44LbStaticMappingDetails{}
		stop, err := reqContext1.ReceiveReply(msg)
		if err != nil {
			sc.Log.WithField("err", err).Error("Failed to get NAT44 mapping details")
			return mappings, err
		}
		if stop {
			break
		}
		if msg.Out2inOnly == 0 || (msg.Protocol != uint8(TCP) && msg.Protocol != uint8(UDP)) {
			// Mapping not installed by this plugin.
			continue
		}

		mapping := &NATMapping{}
		mapping.ExternalIP = make([]byte, net.IPv4len)
		copy(mapping.ExternalIP, msg.ExternalAddr)
		mapping.ExternalPort = msg.ExternalPort
		mapping.Protocol = ProtocolType(msg.Protocol)
		if msg.TwiceNat == 1 {
			mapping.TwiceNat = true
		}

		// Construct the list of locals
		for _, msgLocal := range msg.Locals {
			local := &NATMappingLocal{
				Port:        msgLocal.Port,
				Probability: msgLocal.Probability,
			}
			local.Address = make([]byte, net.IPv4len)
			copy(local.Address, msgLocal.Addr)
			mapping.Locals = append(mapping.Locals, local)
		}
		mappings = append(mappings, mapping)
	}

	// Dump mappings with single backend.
	req2 := &nat.Nat44StaticMappingDump{}
	reqContext2 := sc.GoVPPChan.SendMultiRequest(req2)
	for {
		msg := &nat.Nat44StaticMappingDetails{}
		stop, err := reqContext2.ReceiveReply(msg)
		if err != nil {
			sc.Log.WithField("err", err).Error("Failed to get NAT44 mapping details")
			return mappings, err
		}
		if stop {
			break
		}
		if /*msg.Out2inOnly == 0 || */ msg.AddrOnly == 1 || msg.ExternalSwIfIndex != ^uint32(0) ||
			(msg.Protocol != uint8(TCP) && msg.Protocol != uint8(UDP)) {
			// Mapping not installed by this plugin.
			continue
		}

		mapping := &NATMapping{}
		mapping.ExternalIP = make([]byte, net.IPv4len)
		copy(mapping.ExternalIP, msg.ExternalIPAddress)
		mapping.ExternalPort = msg.ExternalPort
		mapping.Protocol = ProtocolType(msg.Protocol)
		if msg.TwiceNat == 1 {
			mapping.TwiceNat = true
		}

		// Construct the single local.
		local := &NATMappingLocal{
			Port:        msg.LocalPort,
			Probability: 1,
		}
		local.Address = make([]byte, net.IPv4len)
		copy(local.Address, msg.LocalIPAddress)
		mapping.Locals = append(mapping.Locals, local)
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

// dumpNATInterfaces returns sets of currently configured NAT frontend
// and backend interfaces.
func (sc *ServiceConfigurator) dumpNATInterfaces() (frontend, backend Interfaces, err error) {
	frontend = NewInterfaces()
	backend = NewInterfaces()

	req := &nat.Nat44InterfaceDump{}
	reqContext := sc.GoVPPChan.SendMultiRequest(req)

	for {
		msg := &nat.Nat44InterfaceDetails{}
		stop, err := reqContext.ReceiveReply(msg)
		if err != nil {
			sc.Log.WithField("err", err).Error("Failed to get NAT44 interface details")
			return frontend, backend, err
		}
		if stop {
			break
		}
		// Get interface name.
		ifName, _, exists := sc.VPP.GetSwIfIndexes().LookupName(msg.SwIfIndex)
		if !exists {
			sc.Log.WithFields(logging.Fields{
				"swIfIndex": msg.SwIfIndex,
			}).Warn("Failed to get interface name")
		}
		// Add interface into the corresponding set.
		if msg.IsInside == 1 {
			backend.Add(ifName)
		} else {
			frontend.Add(ifName)
		}
	}

	return frontend, backend, nil
}
