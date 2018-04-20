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

package natplugin

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/service/configurator"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/nat"
)

// MockNatPlugin simulates the VPP/NAT plugin.
type MockNatPlugin struct {
	sync.Mutex

	Log logging.Logger

	/* NAT44 global */
	nat44Global  *nat.Nat44Global
	forwarding   bool
	addressPool  []net.IP
	twiceNatPool []net.IP
	interfaces   map[string]NatFeatures // ifname -> NAT features

	/* NAT44 DNAT */
	nat44Dnat        map[string]*nat.Nat44DNat_DNatConfig // label -> DNAT config
	staticMappings   *StaticMappings
	identityMappings *IdentityMappings
}

// NewMockNatPlugin is a constructor for MockNatPlugin.
func NewMockNatPlugin(log logging.Logger) *MockNatPlugin {
	np := &MockNatPlugin{Log: log}
	np.resetNat44Global()
	np.resetNat44Dnat()
	return np
}

func (mnt *MockNatPlugin) resetNat44Global() {
	mnt.nat44Global = &nat.Nat44Global{}
	mnt.forwarding = false
	mnt.addressPool = []net.IP{}
	mnt.twiceNatPool = []net.IP{}
	mnt.interfaces = make(map[string]NatFeatures)
}

func (mnt *MockNatPlugin) resetNat44Dnat() {
	mnt.nat44Dnat = make(map[string]*nat.Nat44DNat_DNatConfig)
	mnt.staticMappings = &StaticMappings{}
	mnt.identityMappings = &IdentityMappings{}
}

// ApplyTxn applies transaction created by the service configurator.
func (mnt *MockNatPlugin) ApplyTxn(txn *localclient.Txn) error {
	mnt.Lock()
	defer mnt.Unlock()
	mnt.Log.Debug("Applying localclient transaction")

	if txn == nil {
		return errors.New("txn is nil")
	}

	if txn.DefaultPluginsDataChangeTxn != nil || txn.DefaultPluginsDataResyncTxn != nil {
		return errors.New("defaultplugins txn is not supported")
	}

	if txn.LinuxDataResyncTxn != nil {
		return errors.New("linux resync txn is not supported")
	}

	if txn.LinuxDataChangeTxn == nil {
		return errors.New("linux data change txn is nil")
	}

	dataChange := txn.LinuxDataChangeTxn
	for _, op := range dataChange.Ops {
		if op.Key == nat.GlobalConfigPrefix() {
			mnt.resetNat44Global()
			if op.Value != nil {
				// put global NAT config
				natGlobal, isNatGlobal := op.Value.(*nat.Nat44Global)
				if !isNatGlobal {
					return errors.New("failed to cast NAT global value")
				}
				// update forwarding
				mnt.forwarding = natGlobal.Forwarding
				// update NAT interface features
				for _, natIf := range natGlobal.NatInterfaces {
					if natIf.Name == "" {
						return errors.New("empty interface name")
					}
					if _, hasIf := mnt.interfaces[natIf.Name]; !hasIf {
						mnt.interfaces[natIf.Name] = NewNatFeatures()
					}

					if natIf.OutputFeature {
						if natIf.IsInside {
							if !mnt.interfaces[natIf.Name].Add(OUTPUT_IN) {
								return fmt.Errorf("duplicate OUTPUT_IN feature for interface:%s", natIf.Name)
							}
						} else {
							if !mnt.interfaces[natIf.Name].Add(OUTPUT_OUT) {
								return fmt.Errorf("duplicate OUTPUT_OUT feature for interface:%s", natIf.Name)
							}
						}
					} else {
						if natIf.IsInside {
							if !mnt.interfaces[natIf.Name].Add(IN) {
								return fmt.Errorf("duplicate IN feature for interface:%s", natIf.Name)
							}
						} else {
							if !mnt.interfaces[natIf.Name].Add(OUT) {
								return fmt.Errorf("duplicate OUT feature for interface:%s", natIf.Name)
							}
						}
					}
				}
				// update address pools
				for _, addr := range natGlobal.AddressPools {
					if addr.VrfId != ^uint32(0) {
						return errors.New("nat address assigned to invalid vrf")
					}
					if addr.FirstSrcAddress == "" {
						return errors.New("empty nat address")
					}
					if addr.LastSrcAddress != "" {
						return errors.New("unexpected nat address range")
					}
					addrIP := net.ParseIP(addr.FirstSrcAddress)
					if addrIP == nil {
						return errors.New("failed to parse nat address")
					}
					if addr.TwiceNat {
						mnt.twiceNatPool = append(mnt.twiceNatPool, addrIP)
					} else {
						mnt.addressPool = append(mnt.addressPool, addrIP)
					}
				}
				// update copy of the configuration
				mnt.nat44Global = natGlobal
			}

		} else if strings.HasPrefix(op.Key, nat.DNatPrefix()) {
			if op.Value != nil {
				// put DNAT config
				dnatConfig, isDnatConfig := op.Value.(*nat.Nat44DNat_DNatConfig)
				if !isDnatConfig {
					return errors.New("failed to cast DNAT config value")
				}
				prevDnatConfig, modify := mnt.nat44Dnat[dnatConfig.Label]
				if modify {
					// remove old static mappings
					oldSms, err := mnt.dnatToStaticMappings(prevDnatConfig)
					if err != nil {
						return err
					}
					mnt.staticMappings.Subtract(oldSms)
					// remove old identity mappings
					oldIms, err := mnt.dnatToIdentityMappings(prevDnatConfig)
					if err != nil {
						return err
					}
					mnt.identityMappings.Subtract(oldIms)
				}
				// add new static mappings
				newSms, err := mnt.dnatToStaticMappings(dnatConfig)
				if err != nil {
					return err
				}
				if !mnt.staticMappings.Join(newSms) {
					return errors.New("duplicate static mapping")
				}
				// add new identity mappings
				newIms, err := mnt.dnatToIdentityMappings(dnatConfig)
				if err != nil {
					return err
				}
				if !mnt.identityMappings.Join(newIms) {
					return errors.New("duplicate identity mapping")
				}
				// update copy of the configuration
				mnt.nat44Dnat[dnatConfig.Label] = dnatConfig

			} else {
				// remove DNAT configuration
				label := strings.TrimPrefix(op.Key, nat.DNatPrefix())
				if prevDnatConfig, hasDnat := mnt.nat44Dnat[label]; hasDnat {
					oldSms, err := mnt.dnatToStaticMappings(prevDnatConfig)
					if err != nil {
						return err
					}
					mnt.staticMappings.Subtract(oldSms)
				} else {
					return errors.New("attempt to remove DNAT config which does not exist")
				}
			}

		} else {
			return errors.New("non-NAT changed in txn")
		}

	}

	return nil
}

func (mnt *MockNatPlugin) dnatToStaticMappings(dnat *nat.Nat44DNat_DNatConfig) (*StaticMappings, error) {
	sms := &StaticMappings{}
	for _, staticMapping := range dnat.StMappings {
		sm := &StaticMapping{}

		// fields set to a constant value
		if staticMapping.TwiceNat != nat.TwiceNatMode_SELF {
			return nil, errors.New("self-twice-NAT not enabled for static mapping")
		}
		if staticMapping.VrfId != 0 {
			return nil, errors.New("static mapping assigned to invalid vrf")
		}
		if staticMapping.ExternalInterface != "" {
			return nil, errors.New("static mapping with external interface is not expected")
		}

		// external IP
		externalIP := net.ParseIP(staticMapping.ExternalIp)
		if externalIP == nil {
			return nil, errors.New("failed to parse external IP")
		}
		sm.ExternalIP = externalIP

		// protocol
		switch staticMapping.Protocol {
		case nat.Protocol_TCP:
			sm.Protocol = configurator.TCP
		case nat.Protocol_UDP:
			sm.Protocol = configurator.UDP
		case nat.Protocol_ICMP:
			return nil, errors.New("unexpected static mapping for the ICMP protocol")
		}

		// port
		if staticMapping.ExternalPort > uint32(^uint16(0)) {
			return nil, errors.New("invalid external port number")
		}
		sm.ExternalPort = uint16(staticMapping.ExternalPort)

		// locals
		for _, local := range staticMapping.LocalIps {
			localIP := net.ParseIP(local.LocalIp)
			if localIP == nil {
				return nil, errors.New("failed to parse local IP")
			}
			if local.LocalPort > uint32(^uint16(0)) {
				return nil, errors.New("invalid local port number")
			}
			if local.Probability == 0 || local.Probability > uint32(^uint8(0)) {
				return nil, errors.New("invalid local probability")
			}
			sm.Locals = append(sm.Locals, &Local{
				IP:          localIP,
				Port:        uint16(local.LocalPort),
				Probability: uint8(local.Probability),
			})
		}

		// append static mapping
		if !sms.Add(sm) {
			return nil, errors.New("duplicate static mapping")
		}
	}
	return sms, nil
}

func (mnt *MockNatPlugin) dnatToIdentityMappings(dnat *nat.Nat44DNat_DNatConfig) (*IdentityMappings, error) {
	ims := &IdentityMappings{}
	for _, identityMapping := range dnat.IdMappings {
		im := &IdentityMapping{}

		// fields set to a constant value
		if identityMapping.VrfId != 0 {
			return nil, errors.New("identity mapping assigned to invalid vrf")
		}
		if identityMapping.AddressedInterface != "" {
			return nil, errors.New("identity mapping with interface is not expected")
		}

		// IP addr
		ip := net.ParseIP(identityMapping.IpAddress)
		if ip == nil {
			return nil, errors.New("failed to parse IP address associated with identity mappings")
		}
		im.IP = ip

		// protocol
		switch identityMapping.Protocol {
		case nat.Protocol_TCP:
			im.Protocol = configurator.TCP
		case nat.Protocol_UDP:
			im.Protocol = configurator.UDP
		case nat.Protocol_ICMP:
			return nil, errors.New("unexpected identity mapping for the ICMP protocol")
		}

		// port
		if identityMapping.Port > uint32(^uint16(0)) {
			return nil, errors.New("invalid port number")
		}
		im.Port = uint16(identityMapping.Port)

		// append static mapping
		if !ims.Add(im) {
			return nil, errors.New("duplicate identity mapping")
		}
	}
	return ims, nil
}

// DumpNat44Global returns the current NAT44 global config
func (mnt *MockNatPlugin) DumpNat44Global() *nat.Nat44Global {
	return mnt.nat44Global
}

// DumpNat44DNat returns the current NAT44 DNAT config
func (mnt *MockNatPlugin) DumpNat44DNat() *nat.Nat44DNat {
	dnat := &nat.Nat44DNat{}
	for _, dnatCfg := range mnt.nat44Dnat {
		dnat.DnatConfigs = append(dnat.DnatConfigs, dnatCfg)
	}
	return dnat
}

// IsForwardingEnabled returns true if the forwarding is enabled.
func (mnt *MockNatPlugin) IsForwardingEnabled() bool {
	return mnt.forwarding
}

// AddressPoolSize returns the number of addresses in the NAT address pool.
func (mnt *MockNatPlugin) AddressPoolSize() int {
	return len(mnt.addressPool)
}

// PoolContainsAddress checks if the given address is in the NAT address pool.
func (mnt *MockNatPlugin) PoolContainsAddress(addr string) bool {
	addrIP := net.ParseIP(addr)
	for _, address := range mnt.addressPool {
		if address.Equal(addrIP) {
			return true
		}
	}
	return false
}

// TwiceNatPoolSize returns the number of addresses in the twice-NAT address pool.
func (mnt *MockNatPlugin) TwiceNatPoolSize() int {
	return len(mnt.twiceNatPool)
}

// TwiceNatPoolContainsAddress checks if the given address is in the twice-NAT address pool.
func (mnt *MockNatPlugin) TwiceNatPoolContainsAddress(addr string) bool {
	addrIP := net.ParseIP(addr)
	for _, address := range mnt.twiceNatPool {
		if address.Equal(addrIP) {
			return true
		}
	}
	return false
}

// NumOfIfsWithFeatures returns the number of interfaces with some features enabled.
func (mnt *MockNatPlugin) NumOfIfsWithFeatures() int {
	count := 0
	for _, features := range mnt.interfaces {
		if len(features) > 0 {
			count++
		}
	}
	return count
}

// GetInterfaceFeatures returns features enabled for a given interface.
func (mnt *MockNatPlugin) GetInterfaceFeatures(ifname string) NatFeatures {
	features, has := mnt.interfaces[ifname]
	if has {
		return features
	}
	return NewNatFeatures()
}

// NumOfStaticMappings returns the number of static mappings installed.
func (mnt *MockNatPlugin) NumOfStaticMappings() int {
	return mnt.staticMappings.Count()
}

// HasStaticMapping tests for the presence of the given static mapping.
func (mnt *MockNatPlugin) HasStaticMapping(sm *StaticMapping) bool {
	return mnt.staticMappings.Has(sm)
}

// NumOfIdentityMappings returns the number of identity mappings installed.
func (mnt *MockNatPlugin) NumOfIdentityMappings() int {
	return mnt.identityMappings.Count()
}

// HasIdentityMapping tests for the presence of the given identity mapping.
func (mnt *MockNatPlugin) HasIdentityMapping(im *IdentityMapping) bool {
	return mnt.identityMappings.Has(im)
}
