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

package api

import "github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"

const (
	// SubnetMask defines the default subnet mask for pod addressing - TODO: must be refactored to consider CIDR
	SubnetMask = "/24"
	// VppVNI defines the default VNI for L2 connectivity - TODO: must be refactored to support configured values
	VppVNI     = 10
)

// VppCache defines the operations on the VPP node data store.
type VppCache interface {
	CreateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error
	RetrieveNode(nodeName string) (*telemetrymodel.Node, error)
	UpdateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error
	DeleteNode(nodeName string) error

	RetrieveNodeByHostIPAddr(ipAddr string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopMacAddr(macAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopIPAddr(ipAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByGigEIPAddr(ipAddress string) (*telemetrymodel.Node, error)

	RetrieveAllNodes() []*telemetrymodel.Node

	SetNodeLiveness(name string, nL *telemetrymodel.NodeLiveness) error
	SetNodeInterfaces(name string, nInt map[int]telemetrymodel.NodeInterface) error
	SetNodeBridgeDomain(name string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error
	SetNodeL2Fibs(name string, nL2f map[string]telemetrymodel.NodeL2FibEntry) error
	SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error
	SetNodeIPARPs(name string, nArps []telemetrymodel.NodeIPArpEntry) error

	SetSecondaryNodeIndices(node *telemetrymodel.Node) []string

	ClearCache()
	ReinitializeCache()
}
