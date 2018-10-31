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

package controller

import (
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/infra"


	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
)


type Controller struct {
	Deps

}

// Deps lists dependencies of the Controller.
type Deps struct {
	infra.PluginDeps
	Scheduler   scheduler.KVScheduler
	StatusCheck statuscheck.PluginStatusWriter
}

func (p *Controller) Init() error {
	return nil
}

// AfterInit registers plugin with StatusCheck.
func (p *Controller) AfterInit() error {
	if p.StatusCheck != nil {
		p.StatusCheck.Register(p.PluginName, nil)
	}
	return nil
}