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

package dbresources

import (
	"github.com/gogo/protobuf/proto"

	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/nodesync/vppnode"
)

// DBResource represents a Kubernetes resource whose state is reflected in the database.
type DBResource struct {
	// Keyword uniquely identifies the resource among all resources.
	Keyword string

	// KeyPrefix under which instances of this resource are stored in the database.
	KeyPrefix string

	// ProtoMessageName is the name of the protobuf message used to represent
	// the resource (use proto.MessageName to obtain).
	ProtoMessageName string
}

// GetDBResources returns metadata for all DB resources currently used by Contiv.
// Resources must be stored in DB under KSR key prefix!
func GetDBResources() []*DBResource {
	return []*DBResource{
		{
			Keyword:          vppnode.Keyword,
			ProtoMessageName: proto.MessageName((*vppnode.VppNode)(nil)),
			KeyPrefix:        vppnode.KeyPrefix,
		},
		{
			Keyword:          nodeconfig.Keyword,
			ProtoMessageName: proto.MessageName((*nodeconfig.NodeConfig)(nil)),
			KeyPrefix:        nodeconfig.KeyPrefix(),
		},
		{
			Keyword:          nodemodel.NodeKeyword,
			ProtoMessageName: proto.MessageName((*nodemodel.Node)(nil)),
			KeyPrefix:        nodemodel.KeyPrefix(),
		},
		{
			Keyword:          podmodel.PodKeyword,
			ProtoMessageName: proto.MessageName((*podmodel.Pod)(nil)),
			KeyPrefix:        podmodel.KeyPrefix(),
		},
		{
			Keyword:          nsmodel.NamespaceKeyword,
			ProtoMessageName: proto.MessageName((*nsmodel.Namespace)(nil)),
			KeyPrefix:        nsmodel.KeyPrefix(),
		},
		{
			Keyword:          policymodel.PolicyKeyword,
			ProtoMessageName: proto.MessageName((*policymodel.Policy)(nil)),
			KeyPrefix:        policymodel.KeyPrefix(),
		},
		{
			Keyword:          svcmodel.ServiceKeyword,
			ProtoMessageName: proto.MessageName((*svcmodel.Service)(nil)),
			KeyPrefix:        svcmodel.KeyPrefix(),
		},
		{
			Keyword:          epmodel.EndpointsKeyword,
			ProtoMessageName: proto.MessageName((*epmodel.Endpoints)(nil)),
			KeyPrefix:        epmodel.KeyPrefix(),
		},
	}
}
