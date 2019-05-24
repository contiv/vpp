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

//go:generate protoc -I ./model/pod --gogo_out=plugins=grpc:./model/pod ./model/pod/pod.proto
//go:generate protoc -I ./model/namespace --gogo_out=plugins=grpc:./model/namespace ./model/namespace/namespace.proto
//go:generate protoc -I ./model/policy --gogo_out=plugins=grpc:./model/policy ./model/policy/policy.proto
//go:generate protoc -I ./model/service --gogo_out=plugins=grpc:./model/service ./model/service/service.proto
//go:generate protoc -I ./model/endpoints --gogo_out=plugins=grpc:./model/endpoints ./model/endpoints/endpoints.proto
//go:generate protoc -I ./model/node --gogo_out=plugins=grpc:./model/node ./model/node/node.proto
//go:generate protoc -I ./model/ksrapi --gogo_out=plugins=grpc:./model/ksrapi ./model/ksrapi/ksr_nb_api.proto
//go:generate protoc -I ./model/sfc --gogo_out=plugins=grpc:./model/sfc ./model/sfc/sfc.proto

package ksr

import (
	"fmt"
	"sync"
	"time"

	"github.com/contiv/vpp/plugins/ksr/model/ksrapi"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"context"
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/health/statuscheck/model/status"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/prometheus"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"
)

// Plugin watches K8s resources and causes all changes to be reflected in the ETCD
// data store.
type Plugin struct {
	Deps

	stopCh     chan struct{}
	wg         sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc

	k8sClientConfig *rest.Config
	k8sClientset    *kubernetes.Clientset

	nsReflector        *NamespaceReflector
	podReflector       *PodReflector
	policyReflector    *PolicyReflector
	serviceReflector   *ServiceReflector
	endpointsReflector *EndpointsReflector
	nodeReflector      *NodeReflector
	sfcPodReflector    *SfcPodReflector

	reflectorRegistry *ReflectorRegistry

	StatusMonitor  statuscheck.StatusReader
	etcdMonitor    EtcdMonitor
	StatsCollector StatsCollector
}

// EtcdMonitor defines the state data for the Etcd Monitor
type EtcdMonitor struct {
	// Operational status is the last seen operational status from the
	// plugin monitor
	status status.OperationalState
	// lastRev is the last seen revision of the plugin's status in the
	// data store
	lastRev int64
	// broker is the interface to a key-val data store.
	broker KeyProtoValBroker
	// reflector registry
	rr *ReflectorRegistry
}

// Deps defines dependencies of ksr plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig
	// broker is used to propagate changes into a key-value datastore.
	// contiv-ksr uses ETCD as datastore.
	Publish *kvdbsync.Plugin
	// Prometheus used to publish statistics
	Prometheus *prometheus.Plugin
}

// Reflector object types
const (
	namespaceObjType = "Namespace"
	podObjType       = "Pod"
	policyObjType    = "NetworkPolicy"
	endpointsObjType = "Endpoints"
	serviceObjType   = "Service"
	nodeObjType      = "Node"
	sfcPodObjType    = "SfcPod"
	electionPrefix   = "/contiv-ksr/election"
)

// Init builds K8s client-set based on the supplied kubeconfig and initializes
// all reflectors.
func (plugin *Plugin) Init() error {
	var err error
	plugin.Log.SetLevel(logging.DebugLevel)
	plugin.stopCh = make(chan struct{})
	plugin.ctx, plugin.cancelFunc = context.WithCancel(context.Background())

	plugin.reflectorRegistry = &ReflectorRegistry{
		lock:       sync.RWMutex{},
		reflectors: make(map[string]*Reflector),
	}

	kubeconfig := plugin.KubeConfig.GetConfigName()
	plugin.Log.WithField(ConfigFlagName, kubeconfig).Info("Loading kubernetes client config")
	plugin.k8sClientConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	plugin.k8sClientset, err = kubernetes.NewForConfig(plugin.k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	ksrPrefix := plugin.Publish.ServiceLabel.GetAgentPrefix()

	plugin.etcdMonitor.broker = plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix)
	plugin.etcdMonitor.status = status.OperationalState_INIT
	plugin.etcdMonitor.lastRev = 0
	plugin.etcdMonitor.rr = plugin.reflectorRegistry

	broker := plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix)

	plugin.nsReflector = &NamespaceReflector{
		Reflector: plugin.newReflector("-namespace", namespaceObjType, broker),
	}
	//plugin.nsReflectorLog.SetLevel(logging.DebugLevel)
	err = plugin.nsReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Namespace reflector")
		return err
	}

	plugin.podReflector = &PodReflector{
		Reflector: plugin.newReflector("-pod", podObjType, broker),
	}
	//plugin.podReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.podReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Pod reflector")
		return err
	}

	plugin.sfcPodReflector = &SfcPodReflector{
		Reflector: plugin.newReflector("-sfcPod", sfcPodObjType, broker),
	}
	//plugin.sfcPodReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.sfcPodReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Sfc Pod reflector")
		return err
	}

	plugin.policyReflector = &PolicyReflector{
		Reflector: plugin.newReflector("-policy", policyObjType, broker),
	}
	//plugin.policyReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.policyReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Policy reflector")
		return err
	}

	plugin.serviceReflector = &ServiceReflector{
		Reflector: plugin.newReflector("-service", serviceObjType, broker),
	}
	//plugin.serviceReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.serviceReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Service reflector")
		return err
	}

	plugin.endpointsReflector = &EndpointsReflector{
		Reflector: plugin.newReflector("-endpoints", endpointsObjType, broker),
	}
	//plugin.endpointsReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.endpointsReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Endpoints reflector")
		return err
	}

	plugin.nodeReflector = &NodeReflector{
		Reflector:    plugin.newReflector("-node", nodeObjType, broker),
		rootBroker:   plugin.Publish.Deps.KvPlugin.NewBroker(""),
		serviceLabel: plugin.ServiceLabel,
	}
	// plugin.nodeReflector.Log.SetLevel(logging.DebugLevel)
	err = plugin.nodeReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Node reflector")
		return err
	}

	plugin.StatsCollector.Log = plugin.Log.NewLogger("-metrics")
	plugin.StatsCollector.serviceLabel = plugin.Publish.ServiceLabel.GetAgentLabel()
	plugin.StatsCollector.Prometheus = plugin.Prometheus
	err = plugin.StatsCollector.Init()
	if err != nil {
		plugin.Log.WithField("rwErr", err).Error("Failed to initialize Stats Collector")
		return err
	}

	for _, r := range plugin.reflectorRegistry.getRegisteredReflectors() {
		plugin.StatsCollector.addReflector(r)
	}

	return nil
}

// AfterInit starts all reflectors. They have to be started in AfterInit so that
// the kvdbsync is fully initialized and ready for publishing when a k8s
// notification comes.
func (plugin *Plugin) AfterInit() error {
	go func() {
		if etcdPlugin, ok := plugin.Publish.KvPlugin.(*etcd.Plugin); ok {
			plugin.Log.Info("Start campaign in ksr leader election")

			_, err := etcdPlugin.CampaignInElection(plugin.ctx, electionPrefix)
			if err != nil {
				plugin.Log.Error(err)
				return
			}
			plugin.Log.Info("The instance was elected as leader.")

		} else {
			plugin.Log.Warn("leader election is not supported for a kv-store different from etcd")
		}

		plugin.reflectorRegistry.startReflectors()
		plugin.StatsCollector.start(plugin.stopCh, plugin.reflectorRegistry)

		go plugin.monitorEtcdStatus(plugin.stopCh)
	}()

	return nil
}

// Close stops all reflectors.
func (plugin *Plugin) Close() error {
	close(plugin.stopCh)
	plugin.cancelFunc()
	safeclose.CloseAll(plugin.nsReflector, plugin.podReflector, plugin.policyReflector,
		plugin.serviceReflector, plugin.endpointsReflector)
	plugin.wg.Wait()
	return nil
}

// monitorEtcdStatus monitors the KSR's connection to the Etcd Data Store.
func (plugin *Plugin) monitorEtcdStatus(closeCh chan struct{}) {
	for {
		select {
		case <-closeCh:
			plugin.Log.Info("Closing")
			return
		case <-time.After(1 * time.Second):
			sts := plugin.StatusMonitor.GetAllPluginStatus()
			for k, v := range sts {
				if k == "etcd" {
					plugin.etcdMonitor.processEtcdMonitorEvent(v.State)
					plugin.etcdMonitor.checkEtcdTransientError()
					break
				}
			}
		}
	}
}

// newReflector returns a new instance of KSR Reflector
func (plugin *Plugin) newReflector(logName string, objType string, broker KeyProtoValBroker) Reflector {
	return Reflector{
		Log:               plugin.Log.NewLogger(logName),
		K8sClientset:      plugin.k8sClientset,
		K8sListWatch:      &k8sCache{},
		Broker:            broker,
		dsSynced:          false,
		objType:           objType,
		ReflectorRegistry: plugin.reflectorRegistry,
	}
}

// processEtcdMonitorEvent processes ectd plugin's status events and, if an
// Etcd problem is detected, generates a resync event for all reflectors.
func (etcdm *EtcdMonitor) processEtcdMonitorEvent(ns status.OperationalState) {
	switch ns {
	case status.OperationalState_INIT:
		if etcdm.status == status.OperationalState_OK {
			etcdm.rr.dataStoreDownEvent()
		}
	case status.OperationalState_ERROR:
		if etcdm.status == status.OperationalState_OK {
			etcdm.rr.dataStoreDownEvent()
		}
	case status.OperationalState_OK:
		if etcdm.status == status.OperationalState_INIT ||
			etcdm.status == status.OperationalState_ERROR {
			etcdm.rr.dataStoreUpEvent()
		}
	}
	etcdm.status = ns
}

// checkEtcdTransientError checks is there was a transient error that results
// in data loss in Etcd. If yes, resync of all reflectors is triggered. As a
// byproduct, this function periodically writes reflector gauges to Etcd.
func (etcdm *EtcdMonitor) checkEtcdTransientError() {
	// Skip monitoring during data store resync
	if !etcdm.rr.ksrHasSynced() {
		return
	}

	oldStats := ksrapi.Stats{}
	found, rev, err := etcdm.broker.GetValue(ksrapi.Key("gauges"), &oldStats)
	if err != nil {
		// We only detect loss of data in etcd here; other failures are
		// detected by the plugin monitor.
		return
	}
	if !found {
		rev = 0
	}
	if rev < etcdm.lastRev {
		// Data loss detected (etcd restarted rev counter of ksr status)
		// Mark all reflectors out of sync with K8s
		etcdm.rr.dataStoreDownEvent()
		// Trigger all reflectors to resync their respecrtive data stores
		etcdm.rr.dataStoreUpEvent()
	}
	etcdm.lastRev = rev
	etcdm.broker.Put(ksrapi.Key("gauges"), etcdm.rr.getStats())
}
