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

package ksr

import (
	"fmt"
	"github.com/contiv/vpp/wiring"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
)

const (
	defaultName = "ksr"
	packageName = "ksr"
	// MicroserviceLabel is the microservice label used by contiv-ksr.
	MicroserviceLabel = "contiv-ksr"
)

// LogsFlagDefault - default file name
const LogsFlagDefault = "logs.conf"

// LogsFlagUsage used as flag usage (see implementation in declareFlags())
const LogsFlagUsage = "Location of the configuration files; also set via 'LOGS_CONFIG' env variable."

const (
	// KubeConfigAdmin is the default location of kubeconfig with admin credentials.
	KubeConfigAdmin = "/etc/kubernetes/admin.conf"

	// KubeConfigUsage explains the purpose of 'kube-config' flag.
	KubeConfigUsage = "Path to the kubeconfig file to use for the client connection to K8s cluster"
)

// Wire implements wiring.Wireable allowing us to use Wiring rather than Flavors
// to configure Plugin Dependencies.
func (plugin *Plugin) Wire(wiring wiring.Wiring) error {
	if wiring == nil {
		wiring = plugin.DefaultWiring(false)
	}
	err := wiring(plugin)
	return err
}

// Name implement wiring.Named
func (plugin *Plugin) Name() string {
	return string(plugin.Deps.PluginName)
}

// DefaultWiring implements wiring.DefaultWirable allowing us to get a fully wired version of this file
// without having to specify any wiring.
func (plugin *Plugin) DefaultWiring(overwrite bool) wiring.Wiring {
	return DefaultWiring(overwrite)
}

// DefaultWiring creates a DefaultWiring for the Plugin.  If overwrite is true, it will overwrite any exiting
// dependencies with Default values.  If overwrite is false, any already set dependency will be unchanged
func DefaultWiring(overwrite bool) wiring.Wiring {
	ret := func(plugin core.Plugin) error {

		p, ok := plugin.(*Plugin)
		if ok && overwrite {

			//  Note - all of this could be massively simplified if dependencies has default wiring
			if p.PluginName == "" {
				p.PluginName = defaultName
			}
			if p.Log == nil {
				l := logging.ForPlugin(p.Name(), logrus.NewLogRegistry())
				p.Log = l
			}
			if p.PluginConfig == nil {
				p.PluginConfig = config.ForPlugin(string(p.PluginName))
			}
			if p.ServiceLabel == nil {
				sl := &servicelabel.Plugin{}
				p.ServiceLabel = sl
				sl.MicroserviceLabel = MicroserviceLabel
			}
			if p.StatusCheck == nil {
				// Initializing a statuscheck, all but the Log coudl be set by sc.DefaultWiring()
				sc := &statuscheck.Plugin{}
				p.StatusCheck = sc
				sc.Deps.PluginName = core.PluginName("status-check")
				sc.Deps.Log = logging.ForPlugin(string(sc.PluginName), p.Log)

			}
			if p.KubeConfig == nil {
				config.ForPlugin("kube", KubeConfigAdmin, KubeConfigUsage)
			}
			dbsync := &kvdbsync.Plugin{}
			if p.Publish == nil {
				// TODO still need working for p.Publish dbsync == p.Publish
				// db == plugin.etcdv3, resync == nil, dbPlugName take from dbPlugin

				// Start Initializse a db - this could be replaced with db.DefaultWiring(db)
				db := &etcdv3.Plugin{}
				db.Deps.PluginName = "etcdv3"
				db.Deps.Log = logging.ForPlugin(string(db.Deps.PluginName), p.Log)

				db.Deps.PluginConfig = config.ForPlugin(string(db.Deps.PluginName))
				db.ServiceLabel = p.ServiceLabel
				// Initiazlize yet another StatusCheck that statuscheck.Plugin.DefaultWiring() could initizlize
				sc := &statuscheck.Plugin{}
				db.Deps.StatusCheck = sc
				sc.Deps.PluginName = core.PluginName(db.PluginName)
				sc.Deps.Log = logging.ForPlugin(string(sc.PluginName), p.Log)
				sc.Deps.Log = logging.ForPlugin(string(sc.PluginName), p.Log)
				db.ServiceLabel = p.ServiceLabel
				// End Initializse a db - this could be replaced with db.DefaultWiring(db)

				// All of this could be done by kvdbsync.Plugin.DefaultWiring(db) in the future
				p.Publish = dbsync
				p.Publish.Deps.Log = logging.ForPlugin(string(db.PluginName)+"-datasync", p.Log)
				p.Publish.KvPlugin = db
				p.Publish.ResyncOrch = nil

			}
			if p.StatusMonitor == nil {
				// TODO: This one is done!
				sm := &statuscheck.Plugin{}
				p.StatusMonitor = sm
				sm.Deps.PluginName = core.PluginName("status-check")
				sm.Deps.Log = logging.ForPlugin(string(sm.Deps.PluginName), p.Log)
				if dbsync != nil {
					sm.Transport = dbsync
				}
			}
			if p.StatsCollector.Prometheus == nil {
				prom := &prometheus.Plugin{}
				p.StatsCollector.Prometheus = prom

				prom.Deps.PluginName = "prometheus"
				prom.Deps.PluginConfig = config.ForPlugin(string(prom.Deps.PluginName))
				prom.ServiceLabel = p.ServiceLabel
				// Initiazlize yet another StatusCheck that statuscheck.Plugin.DefaultWiring() could initizlize
				sc := &statuscheck.Plugin{}
				prom.Deps.StatusCheck = sc
				sc.Deps.PluginName = core.PluginName(prom.PluginName)
				sc.Deps.Log = logging.ForPlugin(string(sc.PluginName), p.Log)
				sc.Deps.Log = logging.ForPlugin(string(sc.PluginName), p.Log)

				http := &rest.ForkPlugin{}
				prom.HTTP = http
				rest.DeclareHTTPPortFlag("http-probe")
				http.Deps.PluginName = "http-probe"
				http.Deps.Log = logging.ForPlugin(string(http.Deps.PluginName), p.Log)
				http.Deps.PluginConfig = config.ForPlugin(string(http.Deps.PluginName))

				rp := &rest.Plugin{}
				http.Deps.DefaultHTTP = rp
				rest.DeclareHTTPPortFlag("http")
				rp.Deps.PluginName = "etcdv3"
				rp.Deps.Log = logging.ForPlugin(string(rp.Deps.PluginName), p.Log)

				rp.Deps.PluginConfig = config.ForPlugin(string(rp.Deps.PluginName))

				http.Deps.DefaultHTTP = rp
			}
			return nil
		}
		return fmt.Errorf("Could not convert core.Plugin to *%s.Plugin", packageName)
	}
	return ret
}
