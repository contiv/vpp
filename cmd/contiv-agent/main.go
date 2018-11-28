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
	"os"
	"time"

	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/db/keyval/bolt"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/health/probe"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logmanager"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/rpc/rest"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/kvscheduler"
	linux_ifplugin "github.com/ligato/vpp-agent/plugins/linuxv2/ifplugin"
	linux_l3plugin "github.com/ligato/vpp-agent/plugins/linuxv2/l3plugin"
	linux_nsplugin "github.com/ligato/vpp-agent/plugins/linuxv2/nsplugin"
	"github.com/ligato/vpp-agent/plugins/telemetry"
	vpp_aclplugin "github.com/ligato/vpp-agent/plugins/vppv2/aclplugin"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"
	vpp_l2plugin "github.com/ligato/vpp-agent/plugins/vppv2/l2plugin"
	vpp_l3plugin "github.com/ligato/vpp-agent/plugins/vppv2/l3plugin"
	vpp_natplugin "github.com/ligato/vpp-agent/plugins/vppv2/natplugin"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/controller"
	controller_api "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/policy"
	"github.com/contiv/vpp/plugins/service"
	"github.com/contiv/vpp/plugins/statscollector"
)

const defaultStartupTimeout = 45 * time.Second

// ContivAgent manages vswitch in contiv/vpp solution
type ContivAgent struct {
	LogManager  *logmanager.Plugin
	HTTP        *rest.Plugin
	HealthProbe *probe.Plugin
	Prometheus  *prometheus.Plugin

	KVScheduler *kvscheduler.Scheduler
	Stats       *statscollector.Plugin

	GoVPP         *govppmux.Plugin
	LinuxIfPlugin *linux_ifplugin.IfPlugin
	LinuxL3Plugin *linux_l3plugin.L3Plugin
	VPPIfPlugin   *vpp_ifplugin.IfPlugin
	VPPL2Plugin   *vpp_l2plugin.L2Plugin
	VPPL3Plugin   *vpp_l3plugin.L3Plugin
	VPPNATPlugin  *vpp_natplugin.NATPlugin
	VPPACLPlugin  *vpp_aclplugin.ACLPlugin

	Telemetry *telemetry.Plugin
	GRPC      *grpc.Plugin

	Controller *controller.Controller
	NodeSync   *nodesync.NodeSync
	PodManager *podmanager.PodManager
	Contiv     *contiv.Plugin
	Policy     *policy.Plugin
	Service    *service.Plugin
}

func (c *ContivAgent) String() string {
	return "ContivAgent"
}

// Init is called in startup phase. Method added in order to implement Plugin interface.
func (c *ContivAgent) Init() error {
	return nil
}

// Close is called in agent's cleanup phase. Method added in order to implement Plugin interface.
func (c *ContivAgent) Close() error {
	return nil
}

func main() {
	// disable status check for etcd - Controller monitors the etcd status now
	etcd.DefaultPlugin.StatusCheck = nil

	// set sources for VPP configuration
	watcher := &datasync.KVProtoWatchers{local.Get()}
	kvscheduler.DefaultPlugin.Watcher = watcher // not really used at the moment

	// initialize vpp-agent plugins
	linux_ifplugin.DefaultPlugin.VppIfPlugin = &vpp_ifplugin.DefaultPlugin
	vpp_ifplugin.DefaultPlugin.LinuxIfPlugin = &linux_ifplugin.DefaultPlugin
	vpp_ifplugin.DefaultPlugin.PublishStatistics = &statscollector.DefaultPlugin
	vpp_aclplugin.DefaultPlugin.IfPlugin = &vpp_ifplugin.DefaultPlugin
	linux_nsplugin.DefaultPlugin.Log.SetLevel(logging.InfoLevel)

	// we don't want to publish status to etcd
	statuscheck.DefaultPlugin.Transport = nil

	// initialize GRPC
	grpc.DefaultPlugin.HTTP = &rest.DefaultPlugin

	// initialize Contiv plugins
	nodeSyncPlugin := &nodesync.DefaultPlugin

	podManager := &podmanager.DefaultPlugin

	contivPlugin := contiv.NewPlugin(contiv.UseDeps(func(deps *contiv.Deps) {
		deps.VPPIfPlugin = &vpp_ifplugin.DefaultPlugin
		deps.NodeSync = nodeSyncPlugin
		deps.PodManager = podManager
	}))

	statsCollector := &statscollector.DefaultPlugin
	statsCollector.Contiv = contivPlugin

	policyPlugin := policy.NewPlugin(policy.UseDeps(func(deps *policy.Deps) {
		deps.Contiv = contivPlugin
	}))

	servicePlugin := service.NewPlugin(service.UseDeps(func(deps *service.Deps) {
		deps.Contiv = contivPlugin
		deps.NodeSync = nodeSyncPlugin
		deps.PodManager = podManager
	}))

	controller := controller.NewPlugin(controller.UseDeps(func(deps *controller.Deps) {
		deps.LocalDB = &bolt.DefaultPlugin
		deps.RemoteDB = &etcd.DefaultPlugin
		deps.EventHandlers = []controller_api.EventHandler{
			nodeSyncPlugin,
			podManager,
			contivPlugin,
			servicePlugin,
			policyPlugin,
			statsCollector,
		}
	}))

	nodeSyncPlugin.EventLoop = controller
	podManager.EventLoop = controller
	contivPlugin.EventLoop = controller

	// initialize the agent
	contivAgent := &ContivAgent{
		LogManager:    &logmanager.DefaultPlugin,
		HTTP:          &rest.DefaultPlugin,
		HealthProbe:   &probe.DefaultPlugin,
		Prometheus:    &prometheus.DefaultPlugin,
		KVScheduler:   &kvscheduler.DefaultPlugin,
		Stats:         statsCollector,
		GoVPP:         &govppmux.DefaultPlugin,
		LinuxIfPlugin: &linux_ifplugin.DefaultPlugin,
		LinuxL3Plugin: &linux_l3plugin.DefaultPlugin,
		VPPIfPlugin:   &vpp_ifplugin.DefaultPlugin,
		VPPL2Plugin:   &vpp_l2plugin.DefaultPlugin,
		VPPL3Plugin:   &vpp_l3plugin.DefaultPlugin,
		VPPNATPlugin:  &vpp_natplugin.DefaultPlugin,
		VPPACLPlugin:  &vpp_aclplugin.DefaultPlugin,
		Telemetry:     &telemetry.DefaultPlugin,
		GRPC:          &grpc.DefaultPlugin,
		Controller:    controller,
		NodeSync:      nodeSyncPlugin,
		PodManager:    podManager,
		Contiv:        contivPlugin,
		Policy:        policyPlugin,
		Service:       servicePlugin,
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
