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
	"strings"
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

	// ChainInstances contains a list of instances of the service function chain
	// (each chain can render into multiple instances e.g. in case of multiple pods
	// matching a pod selector)
	ChainInstances []*ServiceFunctionChain
}

// String converts ContivSFC into a human-readable string.
func (sfc ContivSFC) String() string {
	instances := ""
	for idx, i := range sfc.ChainInstances {
		instances += "["
		for idx2, f := range i.ServiceFunctions {
			instances += f.String()
			if idx2 < len(i.ServiceFunctions)-1 {
				instances += ", "
			}
		}
		instances += "]"
		if idx < len(sfc.ChainInstances)-1 {
			instances += ", "
		}
	}
	return fmt.Sprintf("ContivSFC %s Network: %s, ChainsInstances: {%s}",
		sfc.Name, sfc.Network, instances)
}

// ServiceFunctionChain represents a single service function chain instance (chain of individual pods/interfaces).
type ServiceFunctionChain struct {
	ServiceFunctions []ServiceFunction
}

// String converts ServiceFunctionChain into a human-readable string.
func (chain ServiceFunctionChain) String() string {
	sfcList := ""
	for idx, f := range chain.ServiceFunctions {
		sfcList += f.String()
		if idx < len(chain.ServiceFunctions)-1 {
			sfcList += ", "
		}
	}
	return fmt.Sprintf("ServiceFunctions: %s", sfcList)
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

// ServiceFunction represents a single service function chain item.
type ServiceFunction struct {
	Type ServiceFunctionType

	// Physical locator of a service function
	NodeID uint32 // ID of the node where the service function runs
	Local  bool   // true if this is a node-local service function
	Pod    pod.ID // pod identifier, applicable only for pod type of service functions

	// Names of pod interfaces or external interfaces used for forwarding the traffic to / from a service function:
	//   - for a service function that starts the chain, only OutputInterface is valid
	//   - for a service function that ends the chain, only InputInterface is valid
	InputInterface  string // name of the interface using which the traffic enters the service function
	OutputInterface string // name of the interface using which the traffic leaves the service function
}

// String ServiceFunction Backend into a human-readable string.
func (sf ServiceFunction) String() string {
	extras := ""
	if sf.Type == Pod {
		extras = "Pod:" + sf.Pod.String() + ", "
	}
	if sf.InputInterface != "" {
		extras = "InputInterface:" + sf.InputInterface + ", "
	}
	if sf.OutputInterface != "" {
		extras = "OutputInterface:" + sf.OutputInterface + ", "
	}
	extras = strings.TrimRight(extras, ", ")
	return fmt.Sprintf("<Type:%s NodeID:%d, Local:%t, %s>", sf.Type, sf.NodeID, sf.Local, extras)
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
