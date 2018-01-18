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
	"github.com/ligato/cn-infra/core"

	"os"
	"os/signal"
	"syscall"

	"github.com/contiv/vpp/flavors/contiv"
)

// Start Agent plugins selected for this example
func main() {
	// Create new agent
	agentVar := contiv.NewAgent()
	core.EventLoopWithInterrupt(agentVar, closeChanFiredBySigterm())
}

//TODO apply graceful shutdown also to other usages of CN-infra agent plugins

// closeChanFiredBySigterm creates close channel for CN-infra agent that will close when SIGTERM will be detected from surrounding OS
func closeChanFiredBySigterm() chan struct{} {
	// detect SIGTERM as part of pod delete
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	// convert SIGTERM detection to start of plugin shutdown in agent
	closeChan := make(chan struct{})
	go func() {
		<-sigChan
		close(closeChan)
	}()
	return closeChan
}
