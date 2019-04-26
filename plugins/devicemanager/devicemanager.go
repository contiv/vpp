// Copyright (c) 2018 Cisco and/or its affiliates.
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

package devicemanager

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/fsouza/go-dockerclient"
	"github.com/kubernetes/kubernetes/staging/src/k8s.io/apimachinery/pkg/util/rand"
	devicepluginapi "k8s.io/kubernetes/pkg/kubelet/apis/deviceplugin/v1beta1"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	podresourcesapi "k8s.io/kubernetes/pkg/kubelet/apis/podresources/v1alpha1"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/infra"
)

const (
	// "devices" suppported by this device plugin
	memifResourceName = "contivpp.io/memif"
	memifCapacity     = 100

	// memif socket location
	memifHostDir      = "/var/run/contiv/memif"
	memifContainerDir = "/run/vpp/memif.sock"
	memifSockFileName = "memif.sock"

	// env vars passed into the pods
	memifSocketEnvVar = "MEMIF_SOCKET"
	memifSecretEnvVar = "MEMIF_SECRET"

	// contiv k8s annotations
	memifHostSocketAnnotation      = "io.contivpp.memif.socket.host"
	memifContainerSocketAnnotation = "io.contivpp.memif.socket.container"
	memifSecretAnnotation          = "io.contivpp.memif.secret"
	k8sAnnotationPrefix            = "annotation."

	// grpc endpoints for communication with kubelet
	devicePluginSocketName      = "contiv-vpp.sock"
	devicePluginEndpoint        = devicepluginapi.DevicePluginPath + devicePluginSocketName
	kubeletPodResourcesEndpoint = "unix:///var/lib/kubelet/pod-resources/kubelet.sock"

	// labels attached to (not only sandbox) container to identify the pod it belongs to
	k8sLabelForPodName      = "io.kubernetes.pod.name"
	k8sLabelForPodNamespace = "io.kubernetes.pod.namespace"

	// state value of running pods
	runningPodState = "running"

	// timers & others
	grpcClientTimeout          = 10 * time.Second
	deviceListPeriod           = 20 * time.Second
	defaultPodResourcesMaxSize = 1024 * 1024 * 16 // 16 Mb
)

var (
	errNotInitialized = fmt.Errorf("plugin is not initialized")
)

// DeviceManager plugin implements allocation & connection of special devices that may need
// to be connected to pods in case they are defined in resources section of a pod definition.
type DeviceManager struct {
	Deps

	initialized bool // guards whether the plugin has initialized successfully

	grpcServer       *grpc.Server
	podResClient     podresourcesapi.PodResourcesListerClient
	podResClientConn *grpc.ClientConn
	dockerClient     DockerClient
	termSignal       chan bool

	podMemifs         map[podmodel.ID]*MemifInfo // pod ID to memif info map
	deviceAllocations map[string]*MemifInfo      // device name to memif info map
}

// Deps lists dependencies of the DeviceManager plugin.
type Deps struct {
	infra.PluginDeps

	ContivConf contivconf.API
	EventLoop  controller.EventLoop
}

// DockerClient defines API of a Docker client needed by PodManager.
// The interface allows to inject mock Docker client in the unit tests.
type DockerClient interface {
	// Ping pings the docker server.
	Ping() error
	// ListContainers returns a slice of containers matching the given criteria.
	ListContainers(opts docker.ListContainersOptions) ([]docker.APIContainers, error)
	// InspectContainer returns information about a container by its ID.
	InspectContainer(id string) (*docker.Container, error)
}

// Init initializes plugin internals.
func (d *DeviceManager) Init() (err error) {

	// init device plugin gRPC during the first resync
	err = d.startDevicePluginServer()
	if err != nil {
		d.Log.Warn(err)
		// do not return an error if this fails - the CNI is still working
	}

	// connect to kubelet pod resources server endpoint
	d.podResClient, d.podResClientConn, err = podresources.GetClient(kubeletPodResourcesEndpoint,
		grpcClientTimeout, defaultPodResourcesMaxSize)
	if err != nil {
		d.Log.Warn(err)
		// do not return an error if this fails - the CNI is still working
	}

	// connect to Docker server
	d.dockerClient, err = docker.NewClientFromEnv()
	if err != nil {
		d.Log.Warn(err)
		// do not return an error if this fails - the CNI is still working
	}

	d.termSignal = make(chan bool, 1)
	d.podMemifs = make(map[podmodel.ID]*MemifInfo)
	d.deviceAllocations = make(map[string]*MemifInfo)

	d.initialized = true

	return nil
}

// HandlesEvent selects:
//   - any Resync event
//   - Allocate Device
func (d *DeviceManager) HandlesEvent(event controller.Event) bool {

	if event.Method() != controller.Update {
		return true
	}
	if _, isAllocateDevice := event.(*AllocateDevice); isAllocateDevice {
		return true
	}

	// unhandled event
	return false
}

// Resync resynchronizes Device Manager. The first resync starts the device plugin server.
func (d *DeviceManager) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) (err error) {

	if !d.initialized {
		return nil // no error
	}
	_, isHealingResync := event.(*controller.HealingResync)
	if resyncCount > 1 && !isHealingResync {
		return nil
	}

	// list all docker containers
	listOpts := docker.ListContainersOptions{
		All: true,
	}
	containers, err := d.dockerClient.ListContainers(listOpts)
	if err != nil {
		return controller.NewFatalError(
			fmt.Errorf("failed to list docker containers: %v", err))
	}

	// inspect every container to re-construct pod memif metadata
	for _, container := range containers {
		if container.State != runningPodState {
			d.Log.Debugf("Ignoring non-running container: %v", container.ID)
			continue
		}
		// read pod identifier from labels
		podName, hasPodName := container.Labels[k8sLabelForPodName]
		podNamespace, hasPodNamespace := container.Labels[k8sLabelForPodNamespace]
		podID := podmodel.ID{Name: podName, Namespace: podNamespace}
		if !hasPodName || !hasPodNamespace {
			d.Log.Warnf("Container '%s' is missing pod identification\n",
				container.ID)
			continue
		}

		// check if the container has memif metadata
		memifHostSocket, hasMemifHostSocket := container.Labels[k8sAnnotationPrefix+memifHostSocketAnnotation]
		if hasMemifHostSocket {
			d.podMemifs[podID] = &MemifInfo{
				HostSocket:      memifHostSocket,
				ContainerSocket: container.Labels[k8sAnnotationPrefix+memifContainerSocketAnnotation],
				Secret:          container.Labels[k8sAnnotationPrefix+memifSecretAnnotation],
			}
			d.Log.Debugf("Found locally running Pod %v with memif info: %s", podID, d.podMemifs[podID].String())
		}
	}

	return
}

// Update handles AllocateDevice events.
func (d *DeviceManager) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	if !d.initialized {
		return "", nil // no error
	}

	// handle AllocateDevice
	if ad, isAllocateDevice := event.(*AllocateDevice); isAllocateDevice {

		// create a new host directory for the memif socket
		hostDir := filepath.Join(memifHostDir, rand.String(20))
		os.MkdirAll(hostDir, os.ModeDir)

		hostPath := filepath.Join(hostDir, memifSockFileName)
		containerPath := filepath.Join(memifContainerDir, memifSockFileName)

		// generate a secret
		secret := rand.String(20)

		// set container runtime data
		ad.Envs = map[string]string{
			memifSocketEnvVar: containerPath,
			memifSecretEnvVar: secret,
		}
		// set container annotations (used for resync)
		ad.Annotations = map[string]string{
			memifHostSocketAnnotation:      hostPath,
			memifContainerSocketAnnotation: containerPath,
			memifSecretAnnotation:          secret,
		}
		// mount allocated socket dir into the container
		ad.Mounts = []Mount{
			{
				HostPath:      hostDir,
				ContainerPath: memifContainerDir,
			},
		}
		// store allocated data in the internal map
		for _, dev := range ad.DevicesIDs {
			d.deviceAllocations[dev] = &MemifInfo{
				Secret:          secret,
				HostSocket:      hostPath,
				ContainerSocket: containerPath,
			}
		}
	}

	return
}

// Revert is NOOP - never called.
func (d *DeviceManager) Revert(event controller.Event) error {
	return nil
}

// Close cleans up the resources.
func (d *DeviceManager) Close() error {
	if !d.initialized {
		return nil // no error
	}

	// stop ListAndWatch goroutine
	d.termSignal <- true

	if d.grpcServer != nil {
		d.grpcServer.Stop()
	}

	if d.podResClientConn != nil {
		d.podResClientConn.Close()
	}

	return nil
}

// GetDevicePluginOptions returns options to be communicated with DeviceManager.
// (implementation of the DevicePluginServer interface)
func (d *DeviceManager) GetDevicePluginOptions(ctx context.Context, empty *devicepluginapi.Empty) (*devicepluginapi.DevicePluginOptions, error) {
	if !d.initialized {
		return nil, errNotInitialized
	}
	return &devicepluginapi.DevicePluginOptions{
		PreStartRequired: false,
	}, nil
}

// PreStartContainer is called, if indicated by DeviceManager Plugin during registration phase,
// before each container start. DeviceManager plugin can run device specific operations
// such as resetting the device before making devices available to the container.
// (implementation of the DevicePluginServer interface)
func (d *DeviceManager) PreStartContainer(ctx context.Context, psRqt *devicepluginapi.PreStartContainerRequest) (*devicepluginapi.PreStartContainerResponse, error) {
	if !d.initialized {
		return nil, errNotInitialized
	}
	return &devicepluginapi.PreStartContainerResponse{}, nil
}

// ListAndWatch returns a stream of list of available Devices.
// (implementation of the DevicePluginServer interface)
func (d *DeviceManager) ListAndWatch(empty *devicepluginapi.Empty, stream devicepluginapi.DevicePlugin_ListAndWatchServer) error {
	if !d.initialized {
		return errNotInitialized
	}

	// pretend we are able to handle memifCapacity devices
	resp := &devicepluginapi.ListAndWatchResponse{}
	for i := 0; i < memifCapacity; i++ {
		resp.Devices = append(resp.Devices, &devicepluginapi.Device{
			ID:     memifResourceName + "/" + strconv.Itoa(i),
			Health: devicepluginapi.Healthy,
		})
	}

	err := stream.Send(resp)
	if err != nil {
		d.Log.Errorf("Cannot update device list: %v", err)
		return err
	}

	// periodically update list of available devices (the list is always the same)
	timer := time.NewTicker(deviceListPeriod)
	for {
		select {
		case <-timer.C:
			// send list of devices
			err := stream.Send(resp)
			if err != nil {
				d.Log.Errorf("Cannot update device list: %v", err)
			}

		case <-d.termSignal:
			d.Log.Infof("Stopping periodical update of available devices")
			return nil
		}
	}
}

// Allocate is called during container creation when a container requests supported device.
// It is supposed to allocate requested devices and return container runtime details consumed by Kubelet.
// (implementation of the DevicePluginServer interface)
func (d *DeviceManager) Allocate(ctx context.Context, rqt *devicepluginapi.AllocateRequest) (*devicepluginapi.AllocateResponse, error) {
	if !d.initialized {
		return nil, errNotInitialized
	}

	d.Log.Debugf("Allocate device request: %v", rqt)

	resp := &devicepluginapi.AllocateResponse{}

	for _, cr := range rqt.ContainerRequests {

		// push AllocateDeviceEvent event and wait for the result
		event := NewAllocateDeviceEvent(cr.DevicesIDs)
		err := d.EventLoop.PushEvent(event)
		if err != nil {
			d.Log.Error(err)
			return nil, err
		}

		// wait until event processing finishes
		err = event.Wait()

		containerResp := &devicepluginapi.ContainerAllocateResponse{
			Envs:        event.Envs,
			Annotations: event.Annotations,
		}
		for _, m := range event.Mounts {
			containerResp.Mounts = append(containerResp.Mounts, &devicepluginapi.Mount{
				HostPath:      m.HostPath,
				ContainerPath: m.ContainerPath,
			})
		}
		resp.ContainerResponses = append(resp.ContainerResponses, containerResp)
	}

	return resp, nil
}

// GetPodMemifInfo returns info related to memif devices connected to the specified pod.
func (d *DeviceManager) GetPodMemifInfo(pod podmodel.ID) (info *MemifInfo, err error) {
	if !d.initialized {
		return nil, errNotInitialized
	}

	// look into the cache first
	if info, hasInfo := d.podMemifs[pod]; hasInfo {
		return info, nil
	}

	// ask kubelet about about the devices connected to this pod
	devs, err := d.getPodDevices(pod)
	if err != nil {
		return
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("no devices found for pod %v", pod)
	}

	// return info for the first device (all others have the same memif info)
	info = d.deviceAllocations[devs[0]]
	d.podMemifs[pod] = info

	return info, nil
}

// ReleasePodMemif cleans up memif-related resources for the given pod.
func (d *DeviceManager) ReleasePodMemif(pod podmodel.ID) {
	if !d.initialized {
		return
	}
	info, err := d.GetPodMemifInfo(pod)

	if err == nil && info != nil {
		// delete memif socket & dir
		err = os.Remove(info.HostSocket)
		if err != nil {
			d.Log.Warnf("Error by deleting memif socket %s: %v", info.HostSocket, err)
		}
		dir := filepath.Dir(info.HostSocket)
		err = os.Remove(dir)
		if err != nil {
			d.Log.Warnf("Error by deleting memif dir %s: %v", dir, err)
		}

		// delete pod to memif info mapping
		delete(d.podMemifs, pod)
	}
}

// getPodDevices looks up devices connected to the given pod.
func (d *DeviceManager) getPodDevices(pod podmodel.ID) (devicesIDs []string, err error) {
	if d.podResClient == nil {
		err = fmt.Errorf("not connected to the kubelet pod resouces server")
		d.Log.Errorf("Cannot list pod %v devices: %v", pod, err)
		return
	}

	// list pod resources
	ctx, cancel := context.WithTimeout(context.Background(), grpcClientTimeout)
	defer cancel()

	resp, err := d.podResClient.List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		d.Log.Errorf("Cannot list pod %v devices: %v", pod, err)
		return
	}

	for _, r := range resp.PodResources {
		if r.Namespace == pod.Namespace && r.Name == pod.Name {
			for _, c := range r.Containers {
				for _, d := range c.Devices {
					devicesIDs = append(devicesIDs, d.DeviceIds...)
				}
			}
			break
		}
	}
	return devicesIDs, nil
}

// startDevicePluginServer starts gRPC server serving device allocation requests.
func (d *DeviceManager) startDevicePluginServer() error {

	d.Log.Infof("Starting device plugin server at: %s", devicePluginEndpoint)

	os.Remove(devicePluginEndpoint)
	lis, err := net.Listen("unix", devicePluginEndpoint)
	if err != nil {
		d.Log.Errorf("Error by starting Contiv Network DeviceManager Plugin server: %v", err)
		return err
	}

	d.grpcServer = grpc.NewServer()
	devicepluginapi.RegisterDevicePluginServer(d.grpcServer, d)
	go d.grpcServer.Serve(lis)

	// Wait for server to start by launching a blocking connection
	conn, err := grpc.Dial(devicePluginEndpoint, grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}),
	)
	if err != nil {
		d.Log.Errorf("Unable to establish test connection with %s gRPC server: %v", memifResourceName, err)
		return err
	}
	d.Log.Infof("%s device plugin endpoint started serving", memifResourceName)
	conn.Close()

	// register device plugin within kubelet
	err = d.registerDevicePlugin(devicepluginapi.KubeletSocket, devicePluginSocketName, memifResourceName)
	if err != nil {
		// Stop server
		d.grpcServer.Stop()
		d.Log.Error(err)
		return err
	}
	return nil
}

// registerDevicePlugin connects to Kubelet and registers our device plugin within it.
func (d *DeviceManager) registerDevicePlugin(kubeletEndpoint, pluginEndpoint, resourceName string) error {

	// connect to Kubelet
	conn, err := grpc.Dial(kubeletEndpoint, grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))
	if err != nil {
		d.Log.Errorf("Contiv Network DeviceManager Plugin cannot connect to Kubelet service: %v", err)
		return err
	}
	defer conn.Close()
	client := devicepluginapi.NewRegistrationClient(conn)

	// send register request
	request := &devicepluginapi.RegisterRequest{
		Version:      devicepluginapi.Version,
		Endpoint:     pluginEndpoint,
		ResourceName: resourceName,
	}
	if _, err = client.Register(context.Background(), request); err != nil {
		d.Log.Errorf("Unable register device plugin to Kubelet: %v", err)
		return err
	}
	return nil
}
