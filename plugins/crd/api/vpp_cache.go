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

import (
	"github.com/ligato/cn-infra/health/statuscheck/model/status"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ipnet/restapi"
)

const (
	// SubnetMask defines the default subnet mask for pod addressing - TODO: must be refactored to consider CIDR
	SubnetMask = "/24"
	// VppVNI defines the default VNI for L2 connectivity - TODO: must be refactored to support configured values
	VppVNI = 10
)

// VppCache defines the operations on the VPP node data store.
type VppCache interface {
	CreateNode(ID uint32, nodeName, IPAdr string) error
	RetrieveNode(nodeName string) (*telemetrymodel.Node, error)
	UpdateNode(ID uint32, nodeName, IPAdr string) error
	DeleteNode(nodeName string) error

	RetrieveNodeByHostIPAddr(ipAddr string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopMacAddr(macAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopIPAddr(ipAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByGigEIPAddr(ipAddress string) (*telemetrymodel.Node, error)

	RetrieveAllNodes() []*telemetrymodel.Node

	SetNodeLiveness(name string, nL *status.AgentStatus) error
	SetNodeInterfaces(name string, nInt telemetrymodel.NodeInterfaces) error
	SetNodeBridgeDomain(name string, nBridge telemetrymodel.NodeBridgeDomains) error
	SetNodeL2Fibs(name string, nL2f telemetrymodel.NodeL2FibTable) error
	SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error
	SetNodeIPARPs(name string, nArps telemetrymodel.NodeIPArpTable) error
	SetNodeStaticRoutes(nodeName string, nSrs telemetrymodel.NodeStaticRoutes) error
	SetNodeIPam(nodeName string, nIPam restapi.NodeIPAMInfo) error
	SetLinuxInterfaces(nodeName string, nInt telemetrymodel.LinuxInterfaces) error

	SetSecondaryNodeIndices(node *telemetrymodel.Node) []string

	ClearCache()
	ReinitializeCache()
	DumpCache()
}
