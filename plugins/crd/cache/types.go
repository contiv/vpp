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

package cache

import (
	"github.com/ligato/cn-infra/logging"
	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
)

// here goes different cache types
//Update this whenever a new DTO type is added.
const numDTOs = 5

//Cache holds various maps which all take different keys but point to the same underlying value.
type Cache struct {
	nMap       map[string]*telemetrymodel.Node
	loopIPMap  map[string]*telemetrymodel.Node
	gigEIPMap  map[string]*telemetrymodel.Node
	loopMACMap map[string]*telemetrymodel.Node
	k8sNodeMap map[string]*node.Node
	hostIPMap  map[string]*telemetrymodel.Node
	podMap     map[string]*telemetrymodel.Pod
	report     []string

	logger logging.Logger
}

