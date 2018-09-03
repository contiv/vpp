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

package v1

import (
	"github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CRD Constants
const (
	CRDGroup                    string = nodeconfig.GroupName
	CRDGroupVersion             string = "v1"
	CRDContivNodeConfigPlural   string = "nodeconfigs"
	CRDFullContivNodeConfigName string = CRDContivNodeConfigPlural + "." + CRDGroup
)

// NodeConfig describes contiv node configuration custom resource
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NodeConfig struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	metav1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the custom resource spec
	Spec   NodeConfigSpec   `json:"spec,omitempty"`
	Status NodeConfigStatus `json:"status,omitempty"`
}

// InterfaceConfig encapsulates configuration for single interface.
type InterfaceConfig struct {
	InterfaceName string `json:"interfaceName"`
	IP            string `json:"ip,omitempty"`
	UseDHCP       bool   `json:"useDHCP,omitempty"`
}

// NodeConfigSpec is the spec for the contiv node configuration resource.
type NodeConfigSpec struct {
	MainVPPInterface   InterfaceConfig   `json:"mainVPPInterface,omitempty"`   // main VPP interface used for the inter-node connectivity
	OtherVPPInterfaces []InterfaceConfig `json:"otherVPPInterfaces,omitempty"` // other interfaces on VPP, not necessarily used for inter-node connectivity
	StealInterface     string            `json:"stealInterface,omitempty"`     // interface to be stolen from the host stack and bound to VPP
	Gateway            string            `json:"gateway,omitempty"`            // IP address of the default gateway
	NatExternalTraffic bool              `json:"natExternalTraffic,omitempty"` // whether to NAT external traffic or not
}

// NodeConfigList is a list of node configuration resource
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NodeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []NodeConfig `json:"items"`
}

// NodeConfigStatus is the state for the contiv ode configuration
type NodeConfigStatus struct {
	//Nodes   []telemetrymodel.Node  `json:"nodes"`
	//Reports telemetrymodel.Reports `json:"reports"`
	State   string `json:"state,omitempty"`
	Message string `json:"message,omitempty"`
}

// EqualsTo can be used to compare instances of InterfaceConfig.
func (intfCfg *InterfaceConfig) EqualsTo(intfCfg2 *InterfaceConfig) bool {
	return intfCfg.InterfaceName == intfCfg2.InterfaceName &&
		intfCfg.UseDHCP == intfCfg2.UseDHCP &&
		intfCfg.IP == intfCfg2.IP
}

// EqualsTo can be used to compare instances of NodeConfigSpec.
func (nc *NodeConfigSpec) EqualsTo(nc2 *NodeConfigSpec) bool {
	if !nc.MainVPPInterface.EqualsTo(&nc2.MainVPPInterface) {
		return false
	}
	if len(nc.OtherVPPInterfaces) != len(nc2.OtherVPPInterfaces) {
		return false
	}
	for _, otherIntf := range nc.OtherVPPInterfaces {
		found := false
		for _, otherIntf2 := range nc2.OtherVPPInterfaces {
			if otherIntf.EqualsTo(&otherIntf2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}

	}
	return nc.NatExternalTraffic == nc2.NatExternalTraffic &&
		nc.Gateway == nc2.Gateway &&
		nc.StealInterface == nc2.StealInterface
}
