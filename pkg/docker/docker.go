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

package docker

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"

	"google.golang.org/grpc"

	"github.com/golang/glog"

	"k8s.io/kubernetes/cmd/kubelet/app/options"
	"k8s.io/kubernetes/pkg/kubelet"
	"k8s.io/kubernetes/pkg/kubelet/apis/kubeletconfig"
	kubeletconfiginternal "k8s.io/kubernetes/pkg/kubelet/apis/kubeletconfig"
	kubeletscheme "k8s.io/kubernetes/pkg/kubelet/apis/kubeletconfig/scheme"
	kubeletconfigv1alpha1 "k8s.io/kubernetes/pkg/kubelet/apis/kubeletconfig/v1alpha1"
	"k8s.io/kubernetes/pkg/kubelet/dockershim"
	"k8s.io/kubernetes/pkg/kubelet/dockershim/libdocker"
	"k8s.io/kubernetes/pkg/kubelet/server/streaming"
)

const (
	networkPluginName = "cni"
	networkPluginMTU  = 1460
)

// DockerRuntime serves the Contivshim gRPC api which will be
// consumed by contivshim
type DockerRuntime struct {
	dockershim.DockerService
}

// NewDockerRuntime initializes a docker runtime using CNI conifugration
func NewDockerRuntime(dockerRuntimeEndpoint string, streamingConfig *streaming.Config, cniNetDir string, cniPluginDir string, cgroupDriver string, dockerRuntimeRootDir string) (*DockerRuntime, error) {
	glog.Infof("Initialize docker runtime: docker runtime\n")

	kubeletScheme, _, err := kubeletscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}

	external := &kubeletconfigv1alpha1.KubeletConfiguration{}
	kubeletScheme.Default(external)
	kubeCfg := &kubeletconfig.KubeletConfiguration{}
	if err := kubeletScheme.Convert(external, kubeCfg, nil); err != nil {
		return nil, err
	}

	crOption := options.NewContainerRuntimeOptions()
	dockerClient := libdocker.ConnectToDockerOrDie(
		// dockerRuntimeEndpoint defaults to kubeCfg.DockerEndpoint
		dockerRuntimeEndpoint,
		kubeCfg.RuntimeRequestTimeout.Duration,
		crOption.ImagePullProgressDeadline.Duration,
	)
	// CNI plugin setting
	pluginSettings := dockershim.NetworkPluginSettings{
		HairpinMode:       kubeletconfiginternal.HairpinMode(kubeCfg.HairpinMode),
		NonMasqueradeCIDR: kubeCfg.NonMasqueradeCIDR,
		PluginName:        networkPluginName,
		PluginConfDir:     cniNetDir,
		PluginBinDir:      cniPluginDir,
		MTU:               networkPluginMTU,
	}
	var nl *kubelet.NoOpLegacyHost
	pluginSettings.LegacyRuntimeHost = nl
	// set cgroup driver to dockershim
	dockerInfo, err := dockerClient.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get info from docker: %v", err)
	}
	if len(dockerInfo.CgroupDriver) == 0 {
		glog.Warningf("No cgroup driver is set in Docker, use other configuration: %q", cgroupDriver)
	} else if dockerInfo.CgroupDriver != cgroupDriver {
		return nil, fmt.Errorf("misconfiguration: contivshim cgroup driver: %q is different from docker cgroup driver: %q", dockerInfo.CgroupDriver, cgroupDriver)
	}
	ds, err := dockershim.NewDockerService(
		dockerClient,
		crOption.PodSandboxImage,
		streamingConfig,
		&pluginSettings,
		kubeCfg.RuntimeCgroups,
		cgroupDriver,
		crOption.DockerExecHandlerName,
		dockerRuntimeRootDir,
		crOption.DockerDisableSharedPID,
	)
	if err != nil {
		return nil, err
	}

	// start streaming server by using dockerService
	startDockerStreamingServer(streamingConfig, ds)

	return &DockerRuntime{ds}, nil
}

// Serve starts dockershim gRPC server at unix://addr
func (s *DockerRuntime) Serve(addr string) error {
	glog.V(1).Infof("Start dockershim grpc server at %s", addr)
	var server *grpc.Server
	server = grpc.NewServer()
	if err := syscall.Unlink(addr); err != nil && !os.IsNotExist(err) {
		return err
	}

	lis, err := net.Listen("unix", addr)
	if err != nil {
		glog.Fatalf("Failed to listen %s: %v", addr, err)
		return err
	}

	defer lis.Close()
	return server.Serve(lis)
}

// ServiceName prints the Service name
func (s *DockerRuntime) ServiceName() string {
	return "Docker Runtime Service"
}

func startDockerStreamingServer(streamingConfig *streaming.Config, ds dockershim.DockerService) {
	httpServer := &http.Server{
		Addr:    streamingConfig.Addr,
		Handler: ds,
	}
	// TODO (brecode): handle TLS configuration.
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			glog.Errorf("Failed to start streaming server for docker runtime: %v", err)
			os.Exit(1)
		}
	}()
}
