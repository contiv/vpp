// Copyright (c) 2018 Cisco and/or its affiliates.
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

package descriptor

import (
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/logging"
	"github.com/pkg/errors"

	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/descriptor/adapter"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/cn-infra/utils/addrs"
)

const (
	// UnnumberedIfDescriptorName is the name of the descriptor for the unnumbered
	// config-subsection of VPP interfaces.
	UnnumberedIfDescriptorName = "vpp-unnumbered-interface"

	// dependency labels
	unnumberedInterfaceHasIPDep = "unnumbered-interface-has-IP"
)

// UnnumberedIfDescriptor sets/unsets VPP interfaces as unnumbered.
// Values = Interface_Unnumbered{} derived from interfaces where IsUnnumbered==true
type UnnumberedIfDescriptor struct {
	log       logging.Logger
	ifHandler vppcalls.IfVppAPI
	ifIndex   ifaceidx.IfaceMetadataIndex
}

// NewUnnumberedIfDescriptor creates a new instance of UnnumberedIfDescriptor.
func NewUnnumberedIfDescriptor(ifHandler vppcalls.IfVppAPI, log logging.PluginLogger) *UnnumberedIfDescriptor {
	return &UnnumberedIfDescriptor{
		ifHandler: ifHandler,
		log:       log.NewLogger("unif-descriptor"),
	}
}

// GetDescriptor returns descriptor suitable for registration (via adapter)
// with the KVScheduler.
func (d *UnnumberedIfDescriptor) GetDescriptor() *adapter.UnnumberedDescriptor {
	return &adapter.UnnumberedDescriptor{
		Name:               UnnumberedIfDescriptorName,
		KeySelector:        d.IsUnnumberedInterfaceKey,
		ValueTypeName:      proto.MessageName(&interfaces.Interface_Unnumbered{}),
		Add:                d.Add,
		Delete:             d.Delete,
		ModifyWithRecreate: d.ModifyWithRecreate,
		Dependencies:       d.Dependencies,
	}
}

// SetInterfaceIndex should be used to provide interface index immediately after
// the descriptor registration.
func (d *UnnumberedIfDescriptor) SetInterfaceIndex(ifIndex ifaceidx.IfaceMetadataIndex) {
	d.ifIndex = ifIndex
}

// IsUnnumberedInterfaceKey returns true if the key is identifying unnumbered
// VPP interface.
func (d *UnnumberedIfDescriptor) IsUnnumberedInterfaceKey(key string) bool {
	_, isValid := interfaces.ParseNameFromUnnumberedKey(key)
	return isValid
}

// Add sets interface as unnumbered.
func (d *UnnumberedIfDescriptor) Add(key string, unIntf *interfaces.Interface_Unnumbered) (metadata interface{}, err error) {
	ifName, _ := interfaces.ParseNameFromUnnumberedKey(key)

	ifMeta, found := d.ifIndex.LookupByName(ifName)
	if !found {
		err = errors.Errorf("failed to find unnumbered interface %s", ifName)
		d.log.Error(err)
		return nil, err
	}

	ifWithIPMeta, found := d.ifIndex.LookupByName(unIntf.InterfaceWithIp)
	if !found {
		err = errors.Errorf("failed to find interface %s referenced by unnumbered interface %s",
			unIntf.InterfaceWithIp, ifName)
		d.log.Error(err)
		return nil, err
	}

	// convert IP addresses to net.IPNet
	ipAddresses, err := addrs.StrAddrsToStruct(ifWithIPMeta.IPAddresses)
	if err != nil {
		err = errors.Errorf("failed to convert %s IP address list to IPNet structures: %v", ifName, err)
		d.log.Error(err)
		return nil, err
	}

	isIPv4, isIPv6 := getIPAddressVersions(ipAddresses)
	if isIPv4 {
		if err = d.ifHandler.SetInterfaceVrf(ifMeta.SwIfIndex, ifMeta.Vrf); err != nil {
			err = errors.Errorf("failed to set interface %s as IPv4 VRF %d: %v", ifName, ifMeta.Vrf, err)
			d.log.Error(err)
			return nil, err
		}
	}
	if isIPv6 {
		if err := d.ifHandler.SetInterfaceVrfIPv6(ifMeta.SwIfIndex, ifMeta.Vrf); err != nil {
			err = errors.Errorf("failed to set interface %s as IPv6 VRF %d: %v", ifName, ifMeta.Vrf, err)
			d.log.Error(err)
			return nil, err
		}
	}

	err = d.ifHandler.SetUnnumberedIP(ifMeta.SwIfIndex, ifWithIPMeta.SwIfIndex)
	if err != nil {
		d.log.Error(err)
	}

	return nil, err
}

// Delete un-sets interface as unnumbered.
func (d *UnnumberedIfDescriptor) Delete(key string, unIntf *interfaces.Interface_Unnumbered, metadata interface{}) error {
	ifName, _ := interfaces.ParseNameFromUnnumberedKey(key)

	ifMeta, found := d.ifIndex.LookupByName(ifName)
	if !found {
		err := errors.Errorf("failed to find unnumbered interface %s", ifName)
		d.log.Error(err)
		return err
	}

	err := d.ifHandler.UnsetUnnumberedIP(ifMeta.SwIfIndex)
	if err != nil {
		d.log.Error(err)
	}

	return err
}

// ModifyWithRecreate returns always true so that the link to interface with IP
// address is reconfigured with UnsetUnnumberedIP followed by SetUnnumberedIP for the new interface.
func (d *UnnumberedIfDescriptor) ModifyWithRecreate(key string, oldUnIntf, newUnIntf *interfaces.Interface_Unnumbered, oldMetadata interface{}) bool {
	return true
}

// Dependencies lists dependencies for an unnumbered VPP interface.
func (d *UnnumberedIfDescriptor) Dependencies(key string, unIntf *interfaces.Interface_Unnumbered) []scheduler.Dependency {
	// link between unnumbered interface and the referenced interface with IP address
	// - satisfied as along as the referenced interface is configured and has at least
	//   one IP address assigned
	return []scheduler.Dependency{{
		Label: unnumberedInterfaceHasIPDep,
		AnyOf: func(key string) bool {
			ifName, _, _, isIfaceAddrKey := interfaces.ParseInterfaceAddressKey(key)
			return isIfaceAddrKey && ifName == unIntf.InterfaceWithIp
		},
	}}
}
