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

//go:generate protoc -I ./cni --gogo_out=plugins=grpc:./cni ./cni/cni.proto

package podmanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/fsouza/go-dockerclient"

	"github.com/ligato/cn-infra/infra"
	grpcplugin "github.com/ligato/cn-infra/rpc/grpc"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/podmanager/cni"
)

const (
	// name of the CNI request argument that stores pod name
	podNameExtraArg = "K8S_POD_NAME"

	// name of the CNI request argument that stores pod namespace
	podNamespaceExtraArg = "K8S_POD_NAMESPACE"

	// label attached to the sandbox container of every pod
	k8sLabelForSandboxContainer = "io.kubernetes.docker.type=podsandbox"

	// labels attached to (not only sandbox) container to identify the pod it belongs to
	k8sLabelForPodName      = "io.kubernetes.pod.name"
	k8sLabelForPodNamespace = "io.kubernetes.pod.namespace"

	// state value of running pods
	runningPodState = "running"

	// possible return value for CNI requests
	cniResultOk  uint32 = 0
	cniResultErr uint32 = 1
)

// PodManager plugin manages pods deployed on this node. It serves Add/Delete CNI
// requests, converts them to AddPod and DeletePod events, and maintains a map
// of metadata for all locally deployed pods, with enough information for other
// plugins to be able to (re)construct connectivity between pods and the vswitch.
type PodManager struct {
	Deps
	dockerClient DockerClient

	// map of locally deployed pods
	pods LocalPods
}

// Deps lists dependencies of PodManager.
type Deps struct {
	infra.PluginDeps
	EventLoop controller.EventLoop
	GRPC      grpcplugin.Server
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

var (
	// Error thrown by PodManager.Update (main event loop) when Kubernetes asks
	// to configure pod which is already configured but with different parameters.
	// PodManager.Add() will act by sending an event to remove the obsolete pod
	// connectivity.
	errObsoletePod = fmt.Errorf("obsolete pod configuration detected")
)

// Init connects to Docker server and also registers the plugin to serve
// Add/Delete CNI requests.
func (pm *PodManager) Init() (err error) {
	// init attributes
	pm.pods = make(LocalPods)

	// connect to Docker server
	pm.dockerClient, err = docker.NewClientFromEnv()
	if err != nil {
		return err
	}

	cni.RegisterRemoteCNIServer(pm.GRPC.GetServer(), pm)
	return nil
}

// GetLocalPods returns all currently locally deployed pods.
// The method should be called only from within the main event loop
// (not thread safe) and not before the startup resync.
func (pm *PodManager) GetLocalPods() LocalPods {
	return pm.pods
}

// HandlesEvent select AddPod, DeletePod and any resync events.
func (pm *PodManager) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if _, isAddPod := event.(*AddPod); isAddPod {
		return true
	}
	if _, isDeletePod := event.(*DeletePod); isDeletePod {
		return true
	}
	return false
}

// Resync re-synchronizes the map of local pods using information provided
// by Docker server.
func (pm *PodManager) Resync(_ controller.Event, _ controller.KubeStateData,
	resyncCount int, _ controller.ResyncOperations) error {

	// No need to resync the state of running pods in the run-time - local pod
	// will not be added/deleted without the agent knowing about it.
	if resyncCount > 1 {
		return nil
	}

	// list all sandbox containers
	listOpts := docker.ListContainersOptions{
		All: true,
		Filters: map[string][]string{
			"label": {k8sLabelForSandboxContainer},
		},
	}
	containers, err := pm.dockerClient.ListContainers(listOpts)
	if err != nil {
		return controller.NewFatalError(
			fmt.Errorf("failed to list sandbox containers: %v", err))
	}

	// inspect every sandbox to re-construct the pod metadata
	for _, container := range containers {
		if container.State != runningPodState {
			pm.Log.Debugf("Ignoring non-running sandbox container: %v", container.ID)
			continue
		}
		// read pod identifier from labels
		podName, hasPodName := container.Labels[k8sLabelForPodName]
		podNamespace, hasPodNamespace := container.Labels[k8sLabelForPodNamespace]
		podID := podmodel.ID{Name: podName, Namespace: podNamespace}
		if !hasPodName || !hasPodNamespace {
			pm.Log.Warnf("Sandbox container '%s' is missing pod identification\n",
				container.ID)
			continue
		}
		// inspect every sandbox container to obtain the PID, which is used in the network
		// namespace reference
		details, err := pm.dockerClient.InspectContainer(container.ID)
		if err != nil {
			pm.Log.Warnf("Failed to inspect sandbox container '%s': %v\n",
				container.ID, err)
			continue
		}
		// ignore bare (without process) sandbox containers
		if details.State.Pid == 0 {
			continue
		}
		// add pod into the set of running pods
		pm.pods[podID] = &LocalPod{
			ID:               podID,
			ContainerID:      container.ID,
			NetworkNamespace: fmt.Sprintf("/proc/%d/ns/net", details.State.Pid),
		}
		pm.Log.Debugf("Found locally running Pod: %+v", pm.pods[podID])
	}

	pm.Log.Debugf("PodManager state after resync: pods=%s", pm.pods.String())
	return nil
}

// Update handles AddPod and DeletePod events.
func (pm *PodManager) Update(event controller.Event, _ controller.UpdateOperations) (changeDescription string, err error) {
	if addPod, isAddPod := event.(*AddPod); isAddPod {
		// check for obsolete pod entry
		if pod, hasPod := pm.pods[addPod.Pod]; hasPod {
			if pod.ContainerID != addPod.ContainerID ||
				pod.NetworkNamespace != addPod.NetworkNamespace {
				return "", errObsoletePod
			}
		}

		// add pod into the map of local pods
		pm.pods[addPod.Pod] = &LocalPod{
			ID:               addPod.Pod,
			ContainerID:      addPod.ContainerID,
			NetworkNamespace: addPod.NetworkNamespace,
		}
	}
	if deletePod, isDeletePod := event.(*DeletePod); isDeletePod {
		_, hasPod := pm.pods[deletePod.Pod]
		if !hasPod {
			pm.Log.Warnf("Unknown pod to delete: %v", deletePod.Pod)
		} else {
			delete(pm.pods, deletePod.Pod)
		}
	}
	return "", nil
}

// Revert is used to remove a pod entry from the map of local pods when AddPod event fails.
func (pm *PodManager) Revert(event controller.Event) error {
	if addPod, isAddPod := event.(*AddPod); isAddPod {
		delete(pm.pods, addPod.Pod)
	}
	return nil
}

// Add converts CNI Add request to AddPod event.
func (pm *PodManager) Add(ctx context.Context, request *cni.CNIRequest) (reply *cni.CNIReply, err error) {
	pm.Log.Info("Add pod request received ", *request)

	// push AddPod event and wait for the result
	event := NewAddPodEvent(request)
	err = pm.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	if err == errObsoletePod {
		// remove the obsolete pod first
		delEvent := NewDeletePodEvent(request)
		err = pm.EventLoop.PushEvent(delEvent)
		if err == nil {
			err = event.Wait()
		}
		if err != nil {
			// treat error as warning
			pm.Log.Warnf("Error while removing obsolete pod container: %v", err)
			err = nil
		}
		// retry AddPod event
		event := NewAddPodEvent(request)
		err = pm.EventLoop.PushEvent(event)
		if err == nil {
			err = event.Wait()
		}
	}

	reply = pm.cniReplyForAddPod(request, event, err)
	return reply, err
}

// Delete converts CNI Delete request to DeletePod event.
func (pm *PodManager) Delete(ctx context.Context, request *cni.CNIRequest) (reply *cni.CNIReply, err error) {
	pm.Log.Info("Delete pod request received ", *request)

	// push DeletePod event and wait for the result
	event := NewDeletePodEvent(request)
	err = pm.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	return pm.cniReplyForDeletePod(err), err
}

// cniReplyForAddPod builds CNI reply for processed AddPod event.
func (pm *PodManager) cniReplyForAddPod(request *cni.CNIRequest, event *AddPod, err error) (reply *cni.CNIReply) {
	if err != nil {
		reply = pm.cniErrorReply(err)
		pm.Log.Debugf("CNI Add request reply: %+v", *reply)
		return reply
	}

	reply = &cni.CNIReply{
		Result: cniResultOk,
	}

	// collect interfaces defined by event handlers
	for _, iface := range event.Interfaces {
		cniIface := &cni.CNIReply_Interface{
			Name:    iface.HostName,
			Sandbox: request.NetworkNamespace,
		}
		for _, ipAddr := range iface.IPAddresses {
			cniIface.IpAddresses = append(cniIface.IpAddresses, &cni.CNIReply_Interface_IP{
				Version: cniIPVersion(ipAddr.Version),
				Address: ipAddr.Address.String(),
				Gateway: ipAddr.Gateway.String(),
			})
		}
		reply.Interfaces = append(reply.Interfaces, cniIface)
	}

	// collect routes defined by event handlers
	for _, route := range event.Routes {
		reply.Routes = append(reply.Routes, &cni.CNIReply_Route{
			Dst: route.Network.String(),
			Gw:  route.Gateway.String(),
		})
	}
	pm.Log.Debugf("CNI Add request reply: %+v", *reply)
	return reply
}

// cniReplyForDeletePod builds CNI reply for processed DeletePod event.
func (pm *PodManager) cniReplyForDeletePod(err error) (reply *cni.CNIReply) {
	if err != nil {
		reply = pm.cniErrorReply(err)
	} else {
		reply = &cni.CNIReply{
			Result: cniResultOk,
		}
	}
	pm.Log.Debugf("CNI Delete request reply: %+v", *reply)
	return reply
}

// cniErrorReply returns CNI reply for failed request.
func (pm *PodManager) cniErrorReply(err error) *cni.CNIReply {
	return &cni.CNIReply{
		Result: cniResultErr,
		Error:  err.Error(),
	}
}

// parseCniExtraArgs parses CNI extra arguments from a string into a map.
func parseCniExtraArgs(input string) map[string]string {
	res := map[string]string{}

	pairs := strings.Split(input, ";")
	for i := range pairs {
		kv := strings.Split(pairs[i], "=")
		if len(kv) == 2 {
			res[kv[0]] = kv[1]
		}
	}
	return res
}

func cniIPVersion(version IPVersion) cni.CNIReply_Interface_IP_Version {
	if version == IPv6 {
		return cni.CNIReply_Interface_IP_IPV6
	}
	return cni.CNIReply_Interface_IP_IPV4
}
