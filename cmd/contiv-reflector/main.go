// Copyright (c) 2017 Cisco and/or its affiliates.
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

package main

import (
	"time"

	"github.com/contiv/vpp/flavors/reflector"
	"github.com/ligato/cn-infra/core"
)

// Start Agent plugins selected for this example
func main() {

	flavor := reflector.FlavorReflector{}
	plugins := flavor.Plugins()

	// Create new agent
	agentVar := core.NewAgent(flavor.LogRegistry().NewLogger("core"), 15*time.Second, plugins...)

	core.EventLoopWithInterrupt(agentVar, nil)
}
