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

package manager

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/context"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/logging/logrus"

	"github.com/contiv/vpp/pkg/cri-runtime"
	"github.com/golang/glog"
	"google.golang.org/grpc"
	kubeapi "k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"
	utilexec "k8s.io/utils/exec"
)

const (
	runtimeAPIVersion     = "0.1.0"
	runtimeVersion        = "0.1.0"
	contivshimRuntimeName = "contivshim"
	version               = "0.1.0"
	requestTimeout        = 5 * time.Second
	dialTimeout           = 2 * time.Second
)

// ContivshimManager serves the kubelet runtime gRPC api which will be
// consumed by kubelet
type ContivshimManager struct {
	// The grpc server.
	server *grpc.Server
	// The etcd client
	etcdEndpoint *string
	etcdClient   keyval.ProtoBroker
	// The runtime interface
	dockerRuntimeService criruntime.RuntimeService
	dockerImageService   criruntime.ImageManagerService
}

// NewContivshimManager creates a new ContivshimManager
func NewContivshimManager(
	etcdEndpoint *string,
	dockerRuntimeService criruntime.RuntimeService,
	dockerImageService criruntime.ImageManagerService,
) (*ContivshimManager, error) {
	s := &ContivshimManager{
		server:               grpc.NewServer(),
		etcdEndpoint:         etcdEndpoint,
		dockerRuntimeService: dockerRuntimeService,
		dockerImageService:   dockerImageService,
	}
	s.registerServer()

	// rastislavszabo: commenting ETCD stuff out for now...
	//cli, err := newEtcdClient(s.etcdEndpoint)
	//if err != nil {
	//	glog.Errorf("Could not connect to ETCD instance %v", err)
	//}
	//s.etcdClient = cli

	return s, nil
}

// Serve starts gRPC server at unix://addr
func (s *ContivshimManager) Serve(addr string) error {
	glog.V(1).Infof("Start contivshim grpc server at %s", addr)

	if err := syscall.Unlink(addr); err != nil && !os.IsNotExist(err) {
		return err
	}

	lis, err := net.Listen("unix", addr)
	if err != nil {
		glog.Fatalf("Failed to listen %s: %v", addr, err)
		return err
	}

	defer lis.Close()
	return s.server.Serve(lis)
}

func (s *ContivshimManager) registerServer() {
	kubeapi.RegisterRuntimeServiceServer(s.server, s)
	kubeapi.RegisterImageServiceServer(s.server, s)
}

// Version returns the runtime name, runtime version and runtime API version.
func (s *ContivshimManager) Version(ctx context.Context, req *kubeapi.VersionRequest) (*kubeapi.VersionResponse, error) {
	return &kubeapi.VersionResponse{
		Version:           version,
		RuntimeName:       contivshimRuntimeName,
		RuntimeVersion:    runtimeVersion,
		RuntimeApiVersion: runtimeAPIVersion,
	}, nil
}

// RunPodSandbox creates and start a Pod.
func (s *ContivshimManager) RunPodSandbox(ctx context.Context, req *kubeapi.RunPodSandboxRequest) (*kubeapi.RunPodSandboxResponse, error) {
	glog.V(1).Infof("RunPodSandbox from runtime service with request %s", req.String())
	// This is where we push configuration to etcd
	// TODO (brecode):
	// 1. Decide on the info passed
	// 2. Error handling if RunPodSandbox fails
	// 3. Check if Close should be called

	// rastislavszabo: commenting ETCD stuff out for now...
	//namespace := req.Config.Metadata.Namespace
	//reqvalue := &kubeapi.PodSandboxMetadata{Namespace: namespace}
	//s.etcdClient.Put("contiv", reqvalue)

	// req.Config holds additional POD information to be configureds
	resp, err := s.dockerRuntimeService.RunPodSandbox(req.Config)
	if err != nil {
		glog.Errorf("RunPodSandbox from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.RunPodSandboxResponse{PodSandboxId: resp}, nil
}

// StopPodSandbox stops the sandbox.
func (s *ContivshimManager) StopPodSandbox(ctx context.Context, req *kubeapi.StopPodSandboxRequest) (*kubeapi.StopPodSandboxResponse, error) {
	glog.V(3).Infof("StopPodSandbox from runtime service with request %s", req.String())

	err := s.dockerRuntimeService.StopPodSandbox(req.PodSandboxId)
	if err != nil {
		glog.Errorf("RunPodSandbox from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.StopPodSandboxResponse{}, nil
}

// RemovePodSandbox deletes the sandbox.
func (s *ContivshimManager) RemovePodSandbox(ctx context.Context, req *kubeapi.RemovePodSandboxRequest) (*kubeapi.RemovePodSandboxResponse, error) {
	glog.V(3).Infof("RemovePodSandbox from runtime service with request %s", req.String())
	// TODO (brecode): Delete associated etcd configuration from etcd
	err := s.dockerRuntimeService.RemovePodSandbox(req.PodSandboxId)
	if err != nil {
		glog.Errorf("RemovePodSandbox from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.RemovePodSandboxResponse{}, nil
}

// PodSandboxStatus returns the Status of the PodSandbox.
func (s *ContivshimManager) PodSandboxStatus(ctx context.Context, req *kubeapi.PodSandboxStatusRequest) (*kubeapi.PodSandboxStatusResponse, error) {
	glog.V(3).Infof("PodSandboxStatus with request %s", req.String())

	status, err := s.dockerRuntimeService.PodSandboxStatus(req.PodSandboxId)
	if err != nil {
		glog.Errorf("PodSandboxStatus from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.PodSandboxStatusResponse{Status: status}, nil
}

// ListPodSandbox returns a list of SandBox.
func (s *ContivshimManager) ListPodSandbox(ctx context.Context, req *kubeapi.ListPodSandboxRequest) (*kubeapi.ListPodSandboxResponse, error) {
	glog.V(3).Infof("ListPodSandbox with request %s", req.String())

	pods, err := s.dockerRuntimeService.ListPodSandbox(req.GetFilter())
	if err != nil {
		glog.Errorf("ListPodSandbox from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.ListPodSandboxResponse{Items: pods}, nil
}

// CreateContainer creates a new container in specified PodSandbox
func (s *ContivshimManager) CreateContainer(ctx context.Context, req *kubeapi.CreateContainerRequest) (*kubeapi.CreateContainerResponse, error) {
	glog.V(1).Infof("CreateContainer with request %s", req.String())
	// This is where we push configuration to etcd
	// TODO (brecode):
	// 1. Decide on the info passed and create secrets
	// 2. Error handling if CreateContainer fails
	// 3. Check if Close should be called

	const (
		ldpreloadLabel = "ldpreload"
		proxyTCPLabel  = "proxytcp"
		proxyUDPLabel  = "proxyudp"
		scopeGlobal    = "scopeglobal"
		scopeLocal     = "scopelocal"
	)

	labels := req.SandboxConfig.GetLabels()
	if labels[ldpreloadLabel] == "true" {
		mount := []*kubeapi.Mount{
			{
				HostPath:      "/dev/shm",
				ContainerPath: "/dev/shm",
			},
			{
				HostPath:      "/tmp/ldpreload/vpp-lib64",
				ContainerPath: "/ldp",
			},
		}
		req.Config.Mounts = append(req.Config.Mounts, mount...)

		envs := []*kubeapi.KeyValue{
			{
				Key:   "LD_LIBRARY_PATH",
				Value: "/ldp/:/usr/local/lib:/usr/lib/:/lib",
			},
			{
				Key:   "LD_PRELOAD",
				Value: "/ldp/libvcl_ldpreload.so.0.0.0",
			},
			{
				Key:   "VCL_APP_NAMESPACE_ID",
				Value: req.PodSandboxId,
			},
			{
				Key:   "VCL_APP_NAMESPACE_SECRET",
				Value: "42",
			},
		}
		if labels[proxyTCPLabel] == "true" {
			envs = append(envs, &kubeapi.KeyValue{
				Key:   "VCL_APP_PROXY_TRANSPORT_TCP",
				Value: "",
			})
		}
		if labels[proxyUDPLabel] == "true" {
			envs = append(envs, &kubeapi.KeyValue{
				Key:   "VCL_APP_PROXY_TRANSPORT_UDP",
				Value: "",
			})
		}
		if labels[scopeGlobal] == "true" {
			envs = append(envs, &kubeapi.KeyValue{
				Key:   "VCL_APP_SCOPE_GLOBAL",
				Value: "",
			})
		}
		if labels[scopeLocal] == "true" {
			envs = append(envs, &kubeapi.KeyValue{
				Key:   "VCL_APP_SCOPE_LOCAL",
				Value: "",
			})
		}
		glog.Infof("Setting %v %v", req.PodSandboxId, envs)

		req.Config.Envs = append(req.Config.Envs, envs...)
	}

	glog.V(1).Infof("CreateContainer config: %v", req.Config)
	containerID, err := s.dockerRuntimeService.CreateContainer(req.PodSandboxId, req.Config, req.SandboxConfig)

	if err != nil {
		glog.Errorf("CreateContainer from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.CreateContainerResponse{ContainerId: containerID}, nil
}

// StartContainer starts the container.
func (s *ContivshimManager) StartContainer(ctx context.Context, req *kubeapi.StartContainerRequest) (*kubeapi.StartContainerResponse, error) {
	glog.V(1).Infof("StartContainer with request %s", req.String())

	err := s.dockerRuntimeService.StartContainer(req.ContainerId)
	if err != nil {
		glog.Errorf("StartContainer from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.StartContainerResponse{}, nil
}

// StopContainer stops a running container with a grace period (i.e. timeout).
func (s *ContivshimManager) StopContainer(ctx context.Context, req *kubeapi.StopContainerRequest) (*kubeapi.StopContainerResponse, error) {
	glog.V(3).Infof("StopContainer with request %s", req.String())

	err := s.dockerRuntimeService.StopContainer(req.ContainerId, req.Timeout)
	if err != nil {
		glog.Errorf("StopContainer from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.StopContainerResponse{}, nil
}

// RemoveContainer removes the container.
func (s *ContivshimManager) RemoveContainer(ctx context.Context, req *kubeapi.RemoveContainerRequest) (*kubeapi.RemoveContainerResponse, error) {
	glog.V(3).Infof("RemoveContainer with request %s", req.String())
	// TODO (brecode): Delete associated etcd configuration from etcd
	err := s.dockerRuntimeService.RemoveContainer(req.ContainerId)
	if err != nil {
		glog.Errorf("RemoveContainer from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.RemoveContainerResponse{}, nil
}

// ListContainers lists all containers by filters.
func (s *ContivshimManager) ListContainers(ctx context.Context, req *kubeapi.ListContainersRequest) (*kubeapi.ListContainersResponse, error) {
	glog.V(3).Infof("ListContainers with request %s", req.String())

	containers, err := s.dockerRuntimeService.ListContainers(req.GetFilter())
	if err != nil {
		glog.Errorf("ListContainers from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.ListContainersResponse{
		Containers: containers,
	}, nil
}

// ContainerStatus returns the container status.
func (s *ContivshimManager) ContainerStatus(ctx context.Context, req *kubeapi.ContainerStatusRequest) (*kubeapi.ContainerStatusResponse, error) {
	glog.V(3).Infof("ContainerStatus with request %s", req.String())

	contStatus, err := s.dockerRuntimeService.ContainerStatus(req.ContainerId)
	if err != nil {
		glog.Errorf("ContainerStatus from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.ContainerStatusResponse{
		Status: contStatus,
	}, nil
}

// UpdateContainerResources is this
func (s *ContivshimManager) UpdateContainerResources(
	ctx context.Context,
	req *kubeapi.UpdateContainerResourcesRequest,
) (*kubeapi.UpdateContainerResourcesResponse, error) {
	glog.V(3).Infof("UpdateContainerResources with request %s", req.String())

	if err := s.dockerRuntimeService.UpdateContainerResources(
		req.GetContainerId(),
		req.GetLinux(),
	); err != nil {
		glog.Errorf("UpdateContainerResources from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.UpdateContainerResourcesResponse{}, nil
}

// ExecSync runs a command in a container synchronously.
func (s *ContivshimManager) ExecSync(ctx context.Context, req *kubeapi.ExecSyncRequest) (*kubeapi.ExecSyncResponse, error) {
	glog.V(3).Infof("ExecSync with request %s", req.String())

	stdout, stderr, err := s.dockerRuntimeService.ExecSync(req.ContainerId, req.Cmd, time.Duration(req.Timeout)*time.Second)
	var exitCode int32
	if err != nil {
		exitError, ok := err.(utilexec.ExitError)
		if !ok {
			glog.Errorf("ExecSync from dockershim failed: %v", err)
			return nil, err
		}
		exitCode = int32(exitError.ExitStatus())
	}

	return &kubeapi.ExecSyncResponse{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}, nil
}

// Exec prepares a streaming endpoint to execute a command in the container.
func (s *ContivshimManager) Exec(ctx context.Context, req *kubeapi.ExecRequest) (*kubeapi.ExecResponse, error) {
	glog.V(3).Infof("Exec with request %s", req.String())

	resp, err := s.dockerRuntimeService.Exec(req)
	if err != nil {
		glog.Errorf("Exec from dockershim failed: %v", err)
		return nil, err
	}

	return resp, nil
}

// Attach prepares a streaming endpoint to attach to a running container.
func (s *ContivshimManager) Attach(ctx context.Context, req *kubeapi.AttachRequest) (*kubeapi.AttachResponse, error) {
	glog.V(3).Infof("Attach with request %s", req.String())

	resp, err := s.dockerRuntimeService.Attach(req)
	if err != nil {
		glog.Errorf("Attach from dockershim failed: %v", err)
		return nil, err
	}

	return resp, nil
}

// PortForward prepares a streaming endpoint to forward ports from a PodSandbox.
func (s *ContivshimManager) PortForward(ctx context.Context, req *kubeapi.PortForwardRequest) (*kubeapi.PortForwardResponse, error) {
	glog.V(3).Infof("PortForward with request %s", req.String())

	resp, err := s.dockerRuntimeService.PortForward(req)
	if err != nil {
		glog.Errorf("PortForward from dockershim failed: %v", err)
		return nil, err
	}
	return resp, nil
}

// UpdateRuntimeConfig updates runtime configuration if specified
func (s *ContivshimManager) UpdateRuntimeConfig(ctx context.Context, req *kubeapi.UpdateRuntimeConfigRequest) (*kubeapi.UpdateRuntimeConfigResponse, error) {
	glog.V(3).Infof("Update docker runtime configure with request %s", req.String())
	err := s.dockerRuntimeService.UpdateRuntimeConfig(req.GetRuntimeConfig())
	if err != nil {
		glog.Errorf("UpdateRuntimeConfig from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.UpdateRuntimeConfigResponse{}, nil
}

// Status returns the status of the criruntime.
func (s *ContivshimManager) Status(ctx context.Context, req *kubeapi.StatusRequest) (*kubeapi.StatusResponse, error) {
	glog.V(3).Infof("Status docker runtime service with request %s", req.String())
	resp, err := s.dockerRuntimeService.Status()
	if err != nil {
		glog.Errorf("Status from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.StatusResponse{Status: resp}, nil
}

// ListImages lists existing images.
func (s *ContivshimManager) ListImages(ctx context.Context, req *kubeapi.ListImagesRequest) (*kubeapi.ListImagesResponse, error) {
	glog.V(3).Infof("ListImages with request %s", req.String())
	images, err := s.dockerImageService.ListImages(req.GetFilter())
	if err != nil {
		glog.Errorf("ListImages from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.ListImagesResponse{
		Images: images,
	}, nil
}

// ImageStatus returns the status of the image.
func (s *ContivshimManager) ImageStatus(ctx context.Context, req *kubeapi.ImageStatusRequest) (*kubeapi.ImageStatusResponse, error) {
	glog.V(3).Infof("ImageStatus with request %s", req.String())

	status, err := s.dockerImageService.ImageStatus(req.Image)
	if err != nil {
		glog.Errorf("ImageStatus from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.ImageStatusResponse{Image: status}, nil
}

// PullImage pulls a image with authentication config.
func (s *ContivshimManager) PullImage(ctx context.Context, req *kubeapi.PullImageRequest) (*kubeapi.PullImageResponse, error) {
	glog.V(3).Infof("PullImage with request %s", req.String())

	imageRef, err := s.dockerImageService.PullImage(req.Image, req.Auth)
	if err != nil {
		glog.Errorf("PullImage from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.PullImageResponse{
		ImageRef: imageRef,
	}, nil
}

// RemoveImage removes the image.
func (s *ContivshimManager) RemoveImage(ctx context.Context, req *kubeapi.RemoveImageRequest) (*kubeapi.RemoveImageResponse, error) {
	glog.V(3).Infof("RemoveImage with request %s", req.String())

	err := s.dockerImageService.RemoveImage(req.GetImage())
	if err != nil {
		glog.Errorf("RemoveImage from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.RemoveImageResponse{}, nil
}

// ImageFsInfo returns information of the filesystem that is used to store images.
func (s *ContivshimManager) ImageFsInfo(ctx context.Context, req *kubeapi.ImageFsInfoRequest) (*kubeapi.ImageFsInfoResponse, error) {
	glog.V(3).Infof("ImageFsInfo with request %s", req.String())
	return nil, fmt.Errorf("not implemented")
}

// ContainerStats returns information of the container filesystem.
func (s *ContivshimManager) ContainerStats(ctx context.Context, req *kubeapi.ContainerStatsRequest) (*kubeapi.ContainerStatsResponse, error) {
	glog.V(3).Infof("ContainerStats with request %s", req.String())

	stats, err := s.dockerRuntimeService.ContainerStats(req.GetContainerId())
	if err != nil {
		glog.Errorf("ContainerStatsveImage from dockershim failed: %v", err)
		return nil, err
	}

	return &kubeapi.ContainerStatsResponse{Stats: stats}, nil
}

//ListContainerStats is this
func (s *ContivshimManager) ListContainerStats(ctx context.Context, req *kubeapi.ListContainerStatsRequest) (*kubeapi.ListContainerStatsResponse, error) {
	glog.V(3).Infof("ListContainerStats with request %s", req.String())
	stats, err := s.dockerRuntimeService.ListContainerStats(req.Filter)
	if err != nil {
		glog.Errorf("ListContainerStats from dockershim failed: %v", err)
		return nil, err
	}
	return &kubeapi.ListContainerStatsResponse{Stats: stats}, nil
}

func newEtcdClient(etcdEndpoint *string) (keyval.ProtoBroker, error) {
	config := &etcd.Config{
		Endpoints:             []string{*etcdEndpoint},
		DialTimeout:           1 * time.Second,
		OpTimeout:             3 * time.Second,
		InsecureTransport:     true,
		InsecureSkipTLSVerify: true,
		Certfile:              "",
		Keyfile:               "",
		CAfile:                "",
	}
	db := &etcd.BytesConnectionEtcd{}
	ok := true
	cfg, err := etcd.ConfigToClient(config)
	if err != nil {
		return nil, err
	}

	for ok {
		db, err = etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
		if err != nil {
			glog.Errorf("Could not connect to etcd, retrying...: %v", err)
		} else {
			break
		}
	}

	// Initialize proto decorator.
	protoDb := kvproto.NewProtoWrapper(db)
	return protoDb, nil
}
