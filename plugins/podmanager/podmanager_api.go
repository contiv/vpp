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

package podmanager

import (
	"fmt"
	"net"

	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/podmanager/cni"
)

/********************************* Plugin API *********************************/

// API defines methods provided by PodManager for use by other plugins.
type API interface {
	// GetLocalPods returns all currently locally deployed pods.
	// The method should be called only from within the main event loop
	// (not thread safe) and not before the startup resync.
	GetLocalPods() LocalPods
}

// LocalPod represents a locally deployed pod (locally = on this node).
type LocalPod struct {
	ID               podmodel.ID
	ContainerID      string
	NetworkNamespace string
}

// LocalPods is a map of pod-ID -> Pod info.
type LocalPods map[podmodel.ID]*LocalPod

// String returns human-readable string representation of pod metadata.
func (p *LocalPod) String() string {
	return fmt.Sprintf("Pod <ID:%v, Container:%s, Ns:%s>",
		p.ID, p.ContainerID, p.NetworkNamespace)
}

// String returns a string representation of the pods.
func (ps LocalPods) String() string {
	str := "{"
	first := true
	for podID, pod := range ps {
		if !first {
			str += ", "
		}
		first = false
		str += fmt.Sprintf("%v: %s", podID, pod.String())
	}
	str += "}"
	return str
}

/******************************* Add Pod Event ********************************/

// AddPod event is triggered when a new pod is being deployed on this node.
type AddPod struct {
	result chan error

	// input arguments (read by event handlers)
	Pod              podmodel.ID
	ContainerID      string
	NetworkNamespace string

	// output arguments (edited by event handlers)
	Interfaces []PodInterface
	Routes     []Route
}

// PodInterface represents a single pod interface.
type PodInterface struct {
	HostName    string           // name of the interface in the host stack
	IPAddresses []*IPWithGateway // list of assigned IP addresses
}

// IPWithGateway encapsulates IP address and gateway.
type IPWithGateway struct {
	Version IPVersion
	Address *net.IPNet // IP with mask combined
	Gateway net.IP
}

// IPVersion is either v4 or v6.
type IPVersion int

const (
	// IPv4 represents IP version 4.
	IPv4 IPVersion = iota
	// IPv6 represents IP version 6.
	IPv6
)

// Route represents single IP route.
type Route struct {
	Network *net.IPNet
	Gateway net.IP
}

// NewAddPodEvent is constructor for AddPod event.
func NewAddPodEvent(request *cni.CNIRequest) *AddPod {
	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := podmodel.ID{
		Name:      extraArgs[podNameExtraArg],
		Namespace: extraArgs[podNamespaceExtraArg],
	}
	return &AddPod{
		Pod:              podID,
		ContainerID:      request.ContainerId,
		NetworkNamespace: request.NetworkNamespace,
		result:           make(chan error, 1),
	}
}

// GetName returns name of the AddPod event.
func (ev *AddPod) GetName() string {
	return fmt.Sprintf("Add Pod %s", ev.Pod.String())
}

// String describes AddPod event.
func (ev *AddPod) String() string {
	return fmt.Sprintf("%s\n"+
		"* Container: %s\n"+
		"* Network namespace: %s",
		ev.GetName(), ev.ContainerID, ev.NetworkNamespace)
}

// Method is Update.
func (ev *AddPod) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is RevertOnFailure.
func (ev *AddPod) TransactionType() controller.UpdateTransactionType {
	return controller.RevertOnFailure
}

// Direction is forward.
func (ev *AddPod) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns true.
func (ev *AddPod) IsBlocking() bool {
	return true
}

// Done propagates error to the event producer.
func (ev *AddPod) Done(err error) {
	ev.result <- err
	return
}

// Waits waits for the result of the AddPod event.
func (ev *AddPod) Wait() error {
	return <-ev.result
}

/****************************** Delete Pod Event ******************************/

// DeletePod event is triggered when pod deployed on this node is being terminated.
type DeletePod struct {
	result chan error

	Pod podmodel.ID
}

// NewDeletePodEvent is constructor for DeletePod event.
func NewDeletePodEvent(request *cni.CNIRequest) *DeletePod {
	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := podmodel.ID{
		Name:      extraArgs[podNameExtraArg],
		Namespace: extraArgs[podNamespaceExtraArg],
	}
	return &DeletePod{
		Pod:    podID,
		result: make(chan error, 1),
	}
}

// GetName returns name of the DeletePod event.
func (ev *DeletePod) GetName() string {
	return fmt.Sprintf("Delete Pod %s", ev.Pod.String())
}

// String describes DeletePod event.
func (ev *DeletePod) String() string {
	return ev.GetName()
}

// Method is Update.
func (ev *DeletePod) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is BestEffort.
func (ev *DeletePod) TransactionType() controller.UpdateTransactionType {
	return controller.BestEffort
}

// Direction is Reverse.
func (ev *DeletePod) Direction() controller.UpdateDirectionType {
	return controller.Reverse
}

// IsBlocking returns true.
func (ev *DeletePod) IsBlocking() bool {
	return true
}

// Done propagates error to the event producer.
func (ev *DeletePod) Done(err error) {
	ev.result <- err
	return
}

// Waits waits for the result of the DeletePod event.
func (ev *DeletePod) Wait() error {
	return <-ev.result
}
