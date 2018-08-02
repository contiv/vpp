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
	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/contiv/vpp/plugins/policy"
	"github.com/contiv/vpp/plugins/service"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/health/probe"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/logging/logmanager"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/linux"
	vpp_rest "github.com/ligato/vpp-agent/plugins/rest"
	"github.com/ligato/vpp-agent/plugins/telemetry"
	"github.com/ligato/vpp-agent/plugins/vpp"
	"github.com/ligato/vpp-agent/plugins/vpp/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/nat"
	"os"
	"sync"
	"time"
)

const defaultStartupTimeout = 45 * time.Second

// ContivAgent manages vswitch in contiv/vpp solution
type ContivAgent struct {
	Resync      *resync.Plugin
	LogManger   *logmanager.Plugin
	HTTP        *rest.Plugin
	HealthProbe *probe.Plugin
	Prometheus  *prometheus.Plugin

	ETCDDataSync    *kvdbsync.Plugin
	NodeIDDataSync  *kvdbsync.Plugin
	ServiceDataSync *kvdbsync.Plugin
	PolicyDataSync  *kvdbsync.Plugin

	KVProxy *kvdbproxy.Plugin
	Stats   *statscollector.Plugin

	LinuxLocalClient *localclient.Plugin
	GoVPP            *govppmux.Plugin
	Linux            *linux.Plugin
	VPP              *vpp.Plugin
	VPPrest          *vpp_rest.Plugin
	Telemetry        *telemetry.Plugin
	GRPC             *grpc.Plugin
	Contiv           *contiv.Plugin
	Policy           *policy.Plugin
	Service          *service.Plugin
}

func (c *ContivAgent) String() string {
	return "ContivAgent"
}

// Init is called in startup phase. Method added in order to implement Plugin interface.
func (c *ContivAgent) Init() error {
	return nil
}

// AfterInit triggers the first resync.
func (c *ContivAgent) AfterInit() error {
	c.Resync.DoResync()
	return nil
}

// Close is called in agent's cleanup phase. Method added in order to implement Plugin interface.
func (c *ContivAgent) Close() error {
	return nil
}

func main() {

	ksrServicelabel := servicelabel.NewPlugin(servicelabel.UseLabel(ksr.MicroserviceLabel))
	ksrServicelabel.SetName("ksrServiceLabel")

	newKSRprefixSync := func(name string) *kvdbsync.Plugin {
		return kvdbsync.NewPlugin(
			kvdbsync.UseDeps(func(deps *kvdbsync.Deps) {
				deps.KvPlugin = &etcd.DefaultPlugin
				deps.ResyncOrch = &resync.DefaultPlugin
				deps.ServiceLabel = ksrServicelabel
				deps.SetName(name)
			}))
	}

	etcdDataSync := kvdbsync.NewPlugin(kvdbsync.UseDeps(func(deps *kvdbsync.Deps) {
		deps.KvPlugin = &etcd.DefaultPlugin
		deps.ResyncOrch = &resync.DefaultPlugin
	}))

	nodeIDDataSync := newKSRprefixSync("nodeIdDataSync")
	serviceDataSync := newKSRprefixSync("serviceDataSync")
	policyDataSync := newKSRprefixSync("policyDataSync")

	//TODO  telemetry

	watcher := &datasync.KVProtoWatchers{&kvdbproxy.DefaultPlugin, local.Get()}

	var watchEventsMutex sync.Mutex

	vppPlugin := vpp.NewPlugin(
		vpp.UseDeps(func(deps *vpp.Deps) {
			deps.GoVppmux = &govppmux.DefaultPlugin
			deps.Publish = etcdDataSync
			deps.Watcher = watcher
			deps.WatchEventsMutex = &watchEventsMutex
		}),
	)

	linuxPlugin := linux.NewPlugin(
		linux.UseDeps(func(deps *linux.Deps) {
			deps.VPP = vppPlugin
			deps.Watcher = watcher
			deps.WatchEventsMutex = &watchEventsMutex
		}),
	)

	vppPlugin.Linux = linuxPlugin
	vppPlugin.DisableResync(acl.Prefix, nat.GlobalConfigPrefix(), nat.DNatPrefix())

	vppRest := vpp_rest.NewPlugin(vpp_rest.UseDeps(func(deps *vpp_rest.Deps) {
		deps.GoVppmux = &govppmux.DefaultPlugin
		deps.VPP = vppPlugin
		deps.HTTPHandlers = &rest.DefaultPlugin
	}))

	// we don't want to publish status to etcd
	statuscheck.DefaultPlugin.Transport = nil

	kvdbproxy.DefaultPlugin.KVDB = etcdDataSync
	grpc.DefaultPlugin.HTTP = &rest.DefaultPlugin

	contivPlugin := contiv.NewPlugin(contiv.UseDeps(func(deps *contiv.Deps) {
		deps.Resync = &resync.DefaultPlugin
		deps.GoVPP = &govppmux.DefaultPlugin
		deps.GRPC = &grpc.DefaultPlugin
		deps.VPP = vppPlugin
		deps.Proxy = &kvdbproxy.DefaultPlugin
		deps.ETCD = &etcd.DefaultPlugin
		deps.Watcher = nodeIDDataSync
	}))

	statscollector.DefaultPlugin.Contiv = contivPlugin
	statscollector.DefaultPlugin.Prometheus = &prometheus.DefaultPlugin
	vppPlugin.PublishStatistics = &statscollector.DefaultPlugin

	policyPlugin := policy.NewPlugin(policy.UseDeps(func(deps *policy.Deps) {
		deps.Resync = &resync.DefaultPlugin
		deps.Watcher = policyDataSync
		deps.Contiv = contivPlugin
		deps.GoVPP = &govppmux.DefaultPlugin
		deps.VPP = vppPlugin
	}))

	servicePlugin := service.NewPlugin(service.UseDeps(func(deps *service.Deps) {
		deps.ServiceLabel = &servicelabel.DefaultPlugin
		deps.Resync = &resync.DefaultPlugin
		deps.Watcher = serviceDataSync
		deps.Contiv = contivPlugin
		deps.VPP = vppPlugin
		deps.GoVPP = &govppmux.DefaultPlugin
		deps.Stats = &statscollector.DefaultPlugin
	}))

	contivAgent := &ContivAgent{
		Resync:          &resync.DefaultPlugin,
		LogManger:       &logmanager.DefaultPlugin,
		HTTP:            &rest.DefaultPlugin,
		HealthProbe:     &probe.DefaultPlugin,
		Prometheus:      &prometheus.DefaultPlugin,
		ETCDDataSync:    etcdDataSync,
		NodeIDDataSync:  nodeIDDataSync,
		ServiceDataSync: serviceDataSync,
		PolicyDataSync:  policyDataSync,
		GoVPP:           &govppmux.DefaultPlugin,
		VPP:             vppPlugin,
		VPPrest:         vppRest,
		Linux:           linuxPlugin,
		KVProxy:         &kvdbproxy.DefaultPlugin,
		Contiv:          contivPlugin,
		Stats:           &statscollector.DefaultPlugin,
		Policy:          policyPlugin,
		Service:         servicePlugin,
	}

	a := agent.NewAgent(agent.AllPlugins(contivAgent), agent.StartTimeout(getStartupTimeout()))
	if err := a.Run(); err != nil {
		logrus.DefaultLogger().Fatal(err)
	}

}

func getStartupTimeout() time.Duration {
	var err error
	var timeout time.Duration

	// valid env value must conform to duration format
	// e.g: 45s
	envVal := os.Getenv("STARTUPTIMEOUT")

	if timeout, err = time.ParseDuration(envVal); err != nil {
		timeout = defaultStartupTimeout
	}

	return timeout
}
