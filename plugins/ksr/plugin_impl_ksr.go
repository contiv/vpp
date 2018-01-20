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

//go:generate protoc -I ./model/pod --go_out=plugins=grpc:./model/pod ./model/pod/pod.proto
//go:generate protoc -I ./model/namespace --go_out=plugins=grpc:./model/namespace ./model/namespace/namespace.proto
//go:generate protoc -I ./model/policy --go_out=plugins=grpc:./model/policy ./model/policy/policy.proto
//go:generate protoc -I ./model/service --go_out=plugins=grpc:./model/service ./model/service/service.proto
//go:generate protoc -I ./model/endpoints --go_out=plugins=grpc:./model/endpoints ./model/endpoints/endpoints.proto

package ksr

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/health/statuscheck"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"
)

// Plugin watches K8s resources and causes all changes to be reflected in the ETCD
// data store.
type Plugin struct {
	Deps

	stopCh chan struct{}
	wg     sync.WaitGroup

	k8sClientConfig *rest.Config
	k8sClientset    *kubernetes.Clientset

	StatusMonitor statuscheck.StatusReader

	nsReflector        *NamespaceReflector
	podReflector       *PodReflector
	policyReflector    *PolicyReflector
	serviceReflector   *ServiceReflector
	endpointsReflector *EndpointsReflector
}

// Deps defines dependencies of ksr plugin.
type Deps struct {
	local.PluginInfraDeps
	// Kubeconfig with k8s cluster address and access credentials to use.
	KubeConfig config.PluginConfig
	// Writer is used to propagate changes into a key-value datastore.
	// contiv-ksr uses ETCD as datastore.
	Publish *kvdbsync.Plugin
}

// ReflectorDeps lists dependencies of a reflector regardless of the reflected
// k8s resource type.
type ReflectorDeps struct {
	// Each reflector gets a separate child logger.
	Log logging.Logger
	// A K8s client is used to get the appropriate REST client.
	K8sClientset *kubernetes.Clientset
	// K8s List-Watch is used to watch for Kubernetes config changes.
	K8sListWatch K8sListWatcher
	// Writer is used to propagate changes into a datastore.
	Writer KeyProtoValWriter
	// Lister is used to list values from a datastore.
	Lister KeyProtoValLister
}

// Init builds K8s client-set based on the supplied kubeconfig and initializes
// all reflectors.
func (plugin *Plugin) Init() error {
	var err error
	plugin.Log.SetLevel(logging.DebugLevel)
	plugin.stopCh = make(chan struct{})

	kubeconfig := plugin.KubeConfig.GetConfigName()
	plugin.Log.WithField("kubeconfig", kubeconfig).Info("Loading kubernetes client config")
	plugin.k8sClientConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	plugin.k8sClientset, err = kubernetes.NewForConfig(plugin.k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	ksrPrefix := plugin.Publish.ServiceLabel.GetAgentPrefix()
	plugin.nsReflector = &NamespaceReflector{
		Reflector: Reflector{
			Log:          plugin.Log.NewLogger("-namespace"),
			K8sClientset: plugin.k8sClientset,
			K8sListWatch: &k8sCache{},
			Writer:       plugin.Publish,
			Lister:       plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix),
			dsSynced:     false,
			objType:      "Namespace",
		},
	}

	//plugin.nsReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	err = plugin.nsReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Namespace reflector")
		return err
	}

	plugin.podReflector = &PodReflector{
		Reflector: Reflector{
			Log:          plugin.Log.NewLogger("-pod"),
			K8sClientset: plugin.k8sClientset,
			K8sListWatch: &k8sCache{},
			Writer:       plugin.Publish,
			Lister:       plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix),
			dsSynced:     false,
			objType:      "Pod",
		},
	}
	err = plugin.podReflector.Init(plugin.stopCh, &plugin.wg)
	//plugin.podReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Pod reflector")
		return err
	}

	plugin.policyReflector = &PolicyReflector{
		Reflector: Reflector{
			Log:          plugin.Log.NewLogger("-policy"),
			K8sClientset: plugin.k8sClientset,
			K8sListWatch: &k8sCache{},
			Writer:       plugin.Publish,
			Lister:       plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix),
			dsSynced:     false,
			objType:      "Policy",
		},
	}
	//plugin.policyReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	err = plugin.policyReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Policy reflector")
		return err
	}

	plugin.serviceReflector = &ServiceReflector{
		Reflector: Reflector{
			Log:          plugin.Log.NewLogger("-service"),
			K8sClientset: plugin.k8sClientset,
			K8sListWatch: &k8sCache{},
			Writer:       plugin.Publish,
			Lister:       plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix),
			dsSynced:     false,
			objType:      "Service",
		},
	}
	err = plugin.serviceReflector.Init(plugin.stopCh, &plugin.wg)
	//plugin.serviceReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Service reflector")
		return err
	}

	plugin.endpointsReflector = &EndpointsReflector{
		Reflector: Reflector{
			Log:          plugin.Log.NewLogger("-endpoints"),
			K8sClientset: plugin.k8sClientset,
			K8sListWatch: &k8sCache{},
			Writer:       plugin.Publish,
			Lister:       plugin.Publish.Deps.KvPlugin.NewBroker(ksrPrefix),
			dsSynced:     false,
			objType:      "Endpoints",
		},
	}
	err = plugin.endpointsReflector.Init(plugin.stopCh, &plugin.wg)
	//plugin.endpointsReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Endpoints reflector")
		return err
	}

	return nil
}

// AfterInit starts all reflectors. They have to be started in AfterInit so that
// the kvdbsync is fully initialized and ready for publishing when a k8s
// notification comes.
func (plugin *Plugin) AfterInit() error {
	plugin.nsReflector.Start()
	plugin.podReflector.Start()
	plugin.policyReflector.Start()
	plugin.serviceReflector.Start()
	plugin.endpointsReflector.Start()

	go plugin.checkStatus(plugin.stopCh)

	return nil
}

// Close stops all reflectors.
func (plugin *Plugin) Close() error {
	close(plugin.stopCh)
	safeclose.CloseAll(plugin.nsReflector, plugin.podReflector, plugin.policyReflector,
		plugin.serviceReflector, plugin.endpointsReflector)
	plugin.wg.Wait()
	return nil
}

func (plugin *Plugin) checkStatus(closeCh chan struct{}) {
	for {
		select {
		case <-closeCh:
			plugin.Log.Info("Closing")
			return
		case <-time.After(1 * time.Second):
			status := plugin.StatusMonitor.GetAllPluginStatus()
			for k, v := range status {
				plugin.Log.Infof("Status[%v] = %v", k, v)
			}
		}
	}
}
