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
	"github.com/contiv/vpp/plugins/crd"
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/health/probe"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/servicelabel"
)

// ContivCRD is a custom resource to provide Contiv-VPP telemetry information.
type ContivCRD struct {
	HealthProbe *probe.Plugin
	CRD         *crd.Plugin
}

func (c *ContivCRD) String() string {
	return "CRD"
}

// Init is called at startup phase. Method added in order to implement Plugin interface.
func (c *ContivCRD) Init() error {
	return nil
}

// AfterInit triggers the first resync.
func (c *ContivCRD) AfterInit() error {
	resync.DefaultPlugin.DoResync()
	return nil
}

// Close is called at cleanup phase. Method added in order to implement Plugin interface.
func (c *ContivCRD) Close() error {
	return nil
}

func main() {
	ksrServicelabel := servicelabel.NewPlugin(servicelabel.UseLabel(ksr.MicroserviceLabel))
	ksrServicelabel.SetName("ksrServiceLabel")

	ksrDataSync := kvdbsync.NewPlugin(kvdbsync.UseDeps(func(deps *kvdbsync.Deps) {
		deps.KvPlugin = &etcd.DefaultPlugin
		deps.ServiceLabel = ksrServicelabel
		deps.SetName("ksrDataSync")
	}))

	crd.DefaultPlugin.Watcher = ksrDataSync
	crd.DefaultPlugin.Publish = ksrDataSync

	ContivCRD := &ContivCRD{
		HealthProbe: &probe.DefaultPlugin,
		CRD:         &crd.DefaultPlugin,
	}

	a := agent.NewAgent(agent.AllPlugins(ContivCRD))
	if err := a.Run(); err != nil {
		logrus.DefaultLogger().Fatal(err)
	}
}
