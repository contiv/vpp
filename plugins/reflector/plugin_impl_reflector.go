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

package reflector

import (
	"fmt"
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"
)

type Plugin struct {
	Deps
	*Config

	stopCh chan struct{}
	wg     sync.WaitGroup

	k8sClientConfig *rest.Config
	k8sClientset    *kubernetes.Clientset

	nsReflector     *NamespaceReflector
	podReflector    *PodReflector
	policyReflector *PolicyReflector
}

type Deps struct {
	local.PluginInfraDeps
	Publish *kvdbsync.Plugin
}

type ReflectorDeps struct {
	*Config
	Log          logging.Logger
	K8sClientset *kubernetes.Clientset
	Publish      *kvdbsync.Plugin
}

// Config holds the settings for the Reflector.
type Config struct {
	// Path to a kubeconfig file to use for accessing the k8s API.
	Kubeconfig string `default:"" split_words:"false" json:"kubeconfig"`
}

func (plugin *Plugin) Init() error {
	plugin.Log.SetLevel(logging.DebugLevel)
	plugin.stopCh = make(chan struct{})

	if plugin.Config == nil {
		plugin.Config = &Config{}
	}

	found, err := plugin.PluginConfig.GetValue(plugin.Config)
	if err != nil {
		return fmt.Errorf("error loading Reflector configuration file: %s", err)
	} else if found {
		plugin.Log.WithField("filename", plugin.PluginConfig.GetConfigName()).Info(
			"Loaded Reflector configuration file")
	} else {
		plugin.Log.Info("Using default Reflector configuration")
	}

	plugin.k8sClientConfig, err = clientcmd.BuildConfigFromFlags("", plugin.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	plugin.k8sClientset, err = kubernetes.NewForConfig(plugin.k8sClientConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	plugin.nsReflector = &NamespaceReflector{
		ReflectorDeps: ReflectorDeps{
			Log:          plugin.Log.NewLogger("-namespace"),
			Config:       plugin.Config,
			K8sClientset: plugin.k8sClientset,
			Publish:      plugin.Publish,
		},
	}
	plugin.nsReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	err = plugin.nsReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Namespace reflector")
		return err
	}

	plugin.podReflector = &PodReflector{
		ReflectorDeps: ReflectorDeps{
			Log:          plugin.Log.NewLogger("-pod"),
			Config:       plugin.Config,
			K8sClientset: plugin.k8sClientset,
			Publish:      plugin.Publish,
		},
	}
	plugin.podReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	err = plugin.podReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Pod reflector")
		return err
	}

	plugin.policyReflector = &PolicyReflector{
		ReflectorDeps: ReflectorDeps{
			Log:          plugin.Log.NewLogger("-policy"),
			Config:       plugin.Config,
			K8sClientset: plugin.k8sClientset,
			Publish:      plugin.Publish,
		},
	}
	plugin.policyReflector.ReflectorDeps.Log.SetLevel(logging.DebugLevel)
	err = plugin.policyReflector.Init(plugin.stopCh, &plugin.wg)
	if err != nil {
		plugin.Log.WithField("err", err).Error("Failed to initialize Policy reflector")
		return err
	}
	return nil
}

func (plugin *Plugin) AfterInit() error {
	plugin.nsReflector.Start()
	plugin.podReflector.Start()
	plugin.policyReflector.Start()
	return nil
}

func (plugin *Plugin) Close() error {
	close(plugin.stopCh)
	safeclose.CloseAll(plugin.nsReflector, plugin.podReflector, plugin.policyReflector)
	plugin.wg.Wait()
	return nil
}
