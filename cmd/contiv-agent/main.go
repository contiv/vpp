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

	"github.com/contiv/vpp/plugins/bgpreflector"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/controller"
	controller_api "github.com/contiv/vpp/plugins/controller/api"
	contivgrpc "github.com/contiv/vpp/plugins/grpc"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipv4net"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/policy"
	"github.com/contiv/vpp/plugins/service"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/kvscheduler"
	linux_ifplugin "github.com/ligato/vpp-agent/plugins/linux/ifplugin"
	linux_l3plugin "github.com/ligato/vpp-agent/plugins/linux/l3plugin"
	linux_nsplugin "github.com/ligato/vpp-agent/plugins/linux/nsplugin"
	rest_plugin "github.com/ligato/vpp-agent/plugins/restapi"
	"github.com/ligato/vpp-agent/plugins/telemetry"
	vpp_aclplugin "github.com/ligato/vpp-agent/plugins/vpp/aclplugin"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vpp/ifplugin"
	vpp_l2plugin "github.com/ligato/vpp-agent/plugins/vpp/l2plugin"
	vpp_l3plugin "github.com/ligato/vpp-agent/plugins/vpp/l3plugin"
	vpp_natplugin "github.com/ligato/vpp-agent/plugins/vpp/natplugin"
	vpp_puntplugin "github.com/ligato/vpp-agent/plugins/vpp/puntplugin"
	vpp_stnplugin "github.com/ligato/vpp-agent/plugins/vpp/stnplugin"
)

const (
	defaultStartupTimeout = 45 * time.Second

	grpcDBPath   = "/var/bolt/grpc.db"
	grpcEndpoint = "localhost:9111"
)

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
	VPPSTNPlugin  *vpp_stnplugin.STNPlugin
	VPPPuntPlugin *vpp_puntplugin.PuntPlugin

	Telemetry *telemetry.Plugin
	GRPC      *grpc.Plugin
	REST      *rest_plugin.Plugin

	Controller   *controller.Controller
	ContivConf   *contivconf.ContivConf
	ContivGRPC   *contivgrpc.Plugin
	NodeSync     *nodesync.NodeSync
	PodManager   *podmanager.PodManager
	IPAM         ipam.API
	IPv4Net      *ipv4net.IPv4Net
	Policy       *policy.Plugin
	Service      *service.Plugin
	BGPReflector *bgpreflector.BGPReflector
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
	//watcher := &datasync.KVProtoWatchers{local.Get()}
	//kvscheduler.DefaultPlugin.Watcher = watcher // not really used at the moment

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
	contivConf := contivconf.NewPlugin(contivconf.UseDeps(func(deps *contivconf.Deps) {
		deps.GoVPP = &govppmux.DefaultPlugin
	}))

	contivGRPC := contivgrpc.NewPlugin(contivgrpc.UseDeps(func(deps *contivgrpc.Deps) {
		deps.LocalDB = bolt.NewPlugin(func(plugin *bolt.Plugin) {
			plugin.PluginName = "bolt2"
			plugin.Config = &bolt.Config{
				DbPath:   grpcDBPath,
				FileMode: 0660,
			}
		})
		deps.GRPCServer = grpc.NewPlugin(func(plugin *grpc.Plugin) {
			plugin.PluginName = "grpc2"
			plugin.Config = &grpc.Config{
				Endpoint: grpcEndpoint,
			}
		})
	}))

	nodeSyncPlugin := &nodesync.DefaultPlugin

	podManager := &podmanager.DefaultPlugin

	ipamPlugin := ipam.NewPlugin(ipam.UseDeps(func(deps *ipam.Deps) {
		deps.ContivConf = contivConf
		deps.NodeSync = nodeSyncPlugin
	}))

	ipv4NetPlugin := ipv4net.NewPlugin(ipv4net.UseDeps(func(deps *ipv4net.Deps) {
		deps.GoVPP = &govppmux.DefaultPlugin
		deps.VPPIfPlugin = &vpp_ifplugin.DefaultPlugin
		deps.ContivConf = contivConf
		deps.IPAM = ipamPlugin
		deps.NodeSync = nodeSyncPlugin
		deps.PodManager = podManager
	}))

	statsCollector := &statscollector.DefaultPlugin
	statsCollector.IPv4Net = ipv4NetPlugin

	policyPlugin := policy.NewPlugin(policy.UseDeps(func(deps *policy.Deps) {
		deps.ContivConf = contivConf
		deps.IPAM = ipamPlugin
		deps.IPv4Net = ipv4NetPlugin
	}))

	servicePlugin := service.NewPlugin(service.UseDeps(func(deps *service.Deps) {
		deps.ContivConf = contivConf
		deps.IPAM = ipamPlugin
		deps.IPv4Net = ipv4NetPlugin
		deps.NodeSync = nodeSyncPlugin
		deps.PodManager = podManager
	}))

	bgpReflector := bgpreflector.NewPlugin(bgpreflector.UseDeps(func(deps *bgpreflector.Deps) {
		deps.ContivConf = contivConf
	}))

	controller := controller.NewPlugin(controller.UseDeps(func(deps *controller.Deps) {
		deps.LocalDB = &bolt.DefaultPlugin
		deps.RemoteDB = &etcd.DefaultPlugin
		deps.EventHandlers = []controller_api.EventHandler{
			contivConf,
			nodeSyncPlugin,
			podManager,
			ipamPlugin,
			ipv4NetPlugin,
			servicePlugin,
			policyPlugin,
			bgpReflector,
			statsCollector,
		}
		deps.ExtSources = []controller.ExternalConfigSource{
			contivGRPC,
		}
	}))

	contivConf.ContivAgentDeps = &contivconf.ContivAgentDeps{
		EventLoop: controller,
	}
	nodeSyncPlugin.EventLoop = controller
	podManager.EventLoop = controller
	ipamPlugin.EventLoop = controller
	ipv4NetPlugin.EventLoop = controller
	contivGRPC.EventLoop = controller
	bgpReflector.EventLoop = controller

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
		VPPSTNPlugin:  &vpp_stnplugin.DefaultPlugin,
		VPPPuntPlugin: &vpp_puntplugin.DefaultPlugin,
		Telemetry:     &telemetry.DefaultPlugin,
		GRPC:          &grpc.DefaultPlugin,
		REST:          &rest_plugin.DefaultPlugin,
		Controller:    controller,
		ContivConf:    contivConf,
		ContivGRPC:    contivGRPC,
		NodeSync:      nodeSyncPlugin,
		PodManager:    podManager,
		IPAM:          ipamPlugin,
		IPv4Net:       ipv4NetPlugin,
		Policy:        policyPlugin,
		Service:       servicePlugin,
		BGPReflector:  bgpReflector,
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
