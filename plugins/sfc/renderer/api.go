/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package renderer

import (
	"fmt"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
)

// SFCRendererAPI defines the API of Service Function Chain Renderer.
type SFCRendererAPI interface {
	// AddChain is called for a newly added service function chain.
	AddChain(chain *ContivSFC) error

	// UpdateChain informs renderer about a change in the configuration
	// or in the state of a service function chain.
	UpdateChain(oldChain, newChain *ContivSFC) error

	// DeleteChain is called for every removed service function chain.
	DeleteChain(chain *ContivSFC) error

	// Resync provides a complete snapshot of all service function chain-related data.
	// The renderer should resolve any discrepancies between the state of SFC in K8s
	// and the currently rendered configuration.
	Resync(resyncEv *ResyncEventData) error
}

// ContivSFC is a less-abstract, free of indirect references representation
// of Service Function Chain in Contiv. It contains lists of individual chain instances,
// each referencing pods that need to be chained together.
type ContivSFC struct {
	// Name uniquely identifies a service function chain.
	Name string

	// Network defines a custom network where the chain is being rendered,
	// may be empty in case of the default network.
	Network string

	// Chain contains a list of instances of the service function chain
	// (each chain can render into multiple instances e.g. in case of multiple pods
	// matching a pod selector)
	Chain []*ServiceFunction
}

// String converts ContivSFC into a human-readable string.
func (sfc ContivSFC) String() string {
	chain := "["
	for idx, f := range sfc.Chain {
		chain += f.String()
		if idx < len(sfc.Chain)-1 {
			chain += ", "
		}
	}
	chain += "]"
	return fmt.Sprintf("ContivSFC Name: %s Network: %s, Chain: %s",
		sfc.Name, sfc.Network, chain)
}

// ServiceFunctionType defines type of a service function in the chain.
type ServiceFunctionType int

const (
	// Pod means that the service function item is a k8s pod.
	Pod ServiceFunctionType = 0

	// ExternalInterface means that the service function item is an external VPP interface.
	ExternalInterface ServiceFunctionType = iota
)

// String converts ProtocolType into a human-readable string.
func (t ServiceFunctionType) String() string {
	switch t {
	case Pod:
		return "pod"
	case ExternalInterface:
		return "external-interface"
	}
	return "INVALID"
}

// ServiceFunction represents a single service function element in the chain.
//
// It can be represented by multiple interfaces or running pods, which can render into
// multiple traffic paths. It is the responsibility of the SFC renderer to render
// that into a physical networking configuration that makes sense for the particular case
// (e.g. load-balance the traffic through multiple chains, or just select one of the
// candidate pods making the rest of the pods a hot backup).
type ServiceFunction struct {
	// Type defines the type of the service function
	Type ServiceFunctionType

	// Pods satisfying the pod selector criteria for this service function.
	Pods []*PodSF

	// ExternalInterface satisfying the interface selector criteria for this service function.
	ExternalInterface *InterfaceSF
}

// String converts ServiceFunction into a human-readable string.
func (sf ServiceFunction) String() string {
	if sf.Type == ExternalInterface {
		return fmt.Sprintf("<ExternalInterface: %s>", sf.ExternalInterface.String())
	}
	if len(sf.Pods) == 1 {
		return fmt.Sprintf("<Pod: %s>", sf.Pods[0].String())
	}
	pods := ""
	for idx, pod := range sf.Pods {
		pods += pod.String()
		if idx < len(sf.Pods)-1 {
			pods += ", "
		}
	}
	pods += ""
	return fmt.Sprintf("<Pods: %s>", sf.Pods[0].String())
}

// PodSF represents a pod-type service function.
type PodSF struct {
	ID     pod.ID // pod identifier
	NodeID uint32 // ID of the node where the service function runs
	Local  bool   // true if this is a node-local pod

	InputInterface  string // name of the interface trough which the traffic enters the pod
	OutputInterface string // name of the interface using which the traffic leaves the pod
}

// String converts PodSF into a human-readable string.
func (pod PodSF) String() string {
	return fmt.Sprintf("{ID: %s, NodeID: %d, Local:%v, InputInterface: %s, OutputInterface:%s}",
		pod.ID, pod.NodeID, pod.Local, pod.InputInterface, pod.OutputInterface)
}

// InterfaceSF represents an interface-type service function.
type InterfaceSF struct {
	InterfaceName string // name of the interface trough which the traffic flows
	NodeID        uint32 // ID of the node where the interface resides
	Local         bool   // true if this is a node-local interface
}

// String converts InterfaceSF into a human-readable string.
func (iface InterfaceSF) String() string {
	return fmt.Sprintf("{InterfaceName: %s, NodeID: %d, Local:%v}",
		iface.InterfaceName, iface.NodeID, iface.Local)
}

// ResyncEventData wraps an entire state of K8s services as provided by the Processor.
type ResyncEventData struct {
	// Chains is a list of all currently deployed service function chains.
	Chains []*ContivSFC
}

// String converts ResyncEventData into a human-readable string.
func (red ResyncEventData) String() string {
	chains := ""
	for idx, service := range red.Chains {
		chains += service.String()
		if idx < len(red.Chains)-1 {
			chains += ", "
		}
	}
	return fmt.Sprintf("ResyncEventData Chains: %s", chains)
}
