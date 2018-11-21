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

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/agent"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/datasync/resync"
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
	"github.com/ligato/cn-infra/servicelabel"

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
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/policy"
	"github.com/contiv/vpp/plugins/service"
	"github.com/contiv/vpp/plugins/statscollector"

	"github.com/contiv/vpp/plugins/contiv/model/nodeinfo"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
)

const defaultStartupTimeout = 45 * time.Second

// ContivAgent manages vswitch in contiv/vpp solution
type ContivAgent struct {
	LogManager  *logmanager.Plugin
	HTTP        *rest.Plugin
	HealthProbe *probe.Plugin
	Prometheus  *prometheus.Plugin

	ContivDataSync  *kvdbsync.Plugin
	ServiceDataSync *kvdbsync.Plugin
	PolicyDataSync  *kvdbsync.Plugin

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

// AfterInit triggers the first resync.
func (c *ContivAgent) AfterInit() error {
	resync.DefaultPlugin.DoResync() // TODO: remove ResyncOrch bullshitter
	return nil
}

// Close is called in agent's cleanup phase. Method added in order to implement Plugin interface.
func (c *ContivAgent) Close() error {
	return nil
}

func main() {
	// disable status check for etcd
	etcd.DefaultPlugin.StatusCheck = nil

	// datasync of Kubernetes state data
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

	contivDataSync := newKSRprefixSync("contivDataSync")
	serviceDataSync := newKSRprefixSync("serviceDataSync")
	policyDataSync := newKSRprefixSync("policyDataSync")

	// set sources for VPP configuration
	watcher := &datasync.KVProtoWatchers{local.Get()}
	kvscheduler.DefaultPlugin.Watcher = watcher

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
	controller := controller.NewPlugin(controller.UseDeps(func(deps *controller.Deps) {
		deps.LocalDB = &bolt.DefaultPlugin
		deps.RemoteDB = &etcd.DefaultPlugin
		deps.DBResources = []*controller_api.DBResource{
			{
				Keyword:          nodeinfo.Keyword,
				ProtoMessageName: proto.MessageName((*nodeinfo.NodeInfo)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nodeinfo.AllocatedIDsKeyPrefix,
			},
			{
				Keyword:          nodeconfig.Keyword,
				ProtoMessageName: proto.MessageName((*nodeconfig.NodeConfig)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nodeconfig.KeyPrefix(),
			},
			{
				Keyword:          nodemodel.NodeKeyword,
				ProtoMessageName: proto.MessageName((*nodemodel.Node)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nodemodel.KeyPrefix(),
			},
			{
				Keyword:          podmodel.PodKeyword,
				ProtoMessageName: proto.MessageName((*podmodel.Pod)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + podmodel.KeyPrefix(),
			},
			{
				Keyword:          nsmodel.NamespaceKeyword,
				ProtoMessageName: proto.MessageName((*nsmodel.Namespace)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + nsmodel.KeyPrefix(),
			},
			{
				Keyword:          policymodel.PolicyKeyword,
				ProtoMessageName: proto.MessageName((*policymodel.Policy)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + policymodel.KeyPrefix(),
			},
			{
				Keyword:          svcmodel.ServiceKeyword,
				ProtoMessageName: proto.MessageName((*svcmodel.Service)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + svcmodel.KeyPrefix(),
			},
			{
				Keyword:          epmodel.EndpointsKeyword,
				ProtoMessageName: proto.MessageName((*epmodel.Endpoints)(nil)),
				KeyPrefix:        ksrServicelabel.GetAgentPrefix() + epmodel.KeyPrefix(),
			},
		}
		// TODO event handlers
	}))

	contivPlugin := contiv.NewPlugin(contiv.UseDeps(func(deps *contiv.Deps) {
		deps.VPPIfPlugin = &vpp_ifplugin.DefaultPlugin
		deps.Watcher = contivDataSync
	}))

	statscollector.DefaultPlugin.Contiv = contivPlugin

	policyPlugin := policy.NewPlugin(policy.UseDeps(func(deps *policy.Deps) {
		deps.Watcher = policyDataSync
		deps.Contiv = contivPlugin
	}))

	servicePlugin := service.NewPlugin(service.UseDeps(func(deps *service.Deps) {
		deps.Watcher = serviceDataSync
		deps.Contiv = contivPlugin
	}))

	// initialize the agent
	contivAgent := &ContivAgent{
		LogManager:      &logmanager.DefaultPlugin,
		HTTP:            &rest.DefaultPlugin,
		HealthProbe:     &probe.DefaultPlugin,
		Prometheus:      &prometheus.DefaultPlugin,
		ContivDataSync:  contivDataSync,
		ServiceDataSync: serviceDataSync,
		PolicyDataSync:  policyDataSync,
		KVScheduler:     &kvscheduler.DefaultPlugin,
		Stats:           &statscollector.DefaultPlugin,
		GoVPP:           &govppmux.DefaultPlugin,
		LinuxIfPlugin:   &linux_ifplugin.DefaultPlugin,
		LinuxL3Plugin:   &linux_l3plugin.DefaultPlugin,
		VPPIfPlugin:     &vpp_ifplugin.DefaultPlugin,
		VPPL2Plugin:     &vpp_l2plugin.DefaultPlugin,
		VPPL3Plugin:     &vpp_l3plugin.DefaultPlugin,
		VPPNATPlugin:    &vpp_natplugin.DefaultPlugin,
		VPPACLPlugin:    &vpp_aclplugin.DefaultPlugin,
		Telemetry:       &telemetry.DefaultPlugin,
		GRPC:            &grpc.DefaultPlugin,
		Controller:      controller,
		Contiv:          contivPlugin,
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
