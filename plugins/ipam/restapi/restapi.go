// Copyright (c) 2019 Cisco and/or its affiliates.
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

package restapi

import (
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"net"
)

const (
	// RESTPrefix is versioned prefix for REST urls.
	RESTPrefix = "/contiv/v1/"

	// RestURLNodeIPAM is versioned URL for the node IPAM REST endpoint.
	RestURLNodeIPAllocations = RESTPrefix + "ipam/allocations"
)

// PodIPAllocation represents IP allocation info about a pod.
type PodIPAllocation struct {
	PodID       pod.ID
	MainIP      net.IP
	CustomIfIPs map[string]net.IP
}

// NodeIPAllocations represents runtime IP allocation info about the current node.
type NodeIPAllocations struct {
	Pods []PodIPAllocation
}
