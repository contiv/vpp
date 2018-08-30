/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/nodeconfig.proto

package nodeconfig

import (
	"github.com/ligato/cn-infra/datasync/kvdbsync"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
)

// Handler handler implements Handler interface,
type Handler struct {
	Deps
}

// Deps defines dependencies for NodeConfig CRD Handler.
type Deps struct {
	Log     logging.Logger
	Publish *kvdbsync.Plugin // KeyProtoValWriter does not define Delete
}

// Init initializes handler configuration
// NodeConfig Handler will be taking action on resource CRUD
func (h *Handler) Init() error {
	return nil
}

// ObjectCreated is called when a CRD object is created
func (h *Handler) ObjectCreated(obj interface{}) {
	h.Log.Debugf("Object created with value: %v", obj)
	nodeConfig, ok := obj.(*v1.NodeConfig)
	if !ok {
		h.Log.Warn("Failed to cast newly created node-config object")
		return
	}

	nodeConfigProto := h.nodeConfigToProto(nodeConfig)
	h.Publish.Put(model.Key(nodeConfig.GetName()), nodeConfigProto)
}

// ObjectDeleted is called when a CRD object is deleted
func (h *Handler) ObjectDeleted(obj interface{}) {
	h.Log.Debugf("Object deleted with value: %v", obj)
	nodeConfig, ok := obj.(*v1.NodeConfig)
	if !ok {
		h.Log.Warn("Failed to cast delete event")
		return
	}

	h.Publish.Delete(model.Key(nodeConfig.GetName()))
}

// ObjectUpdated is called when a CRD object is updated
func (h *Handler) ObjectUpdated(obj interface{}) {
	h.Log.Debugf("Object updated with value: %v", obj)
	nodeConfig, ok := obj.(*v1.NodeConfig)
	if !ok {
		h.Log.Warn("Failed to cast updated node-config object")
		return
	}

	nodeConfigProto := h.nodeConfigToProto(nodeConfig)
	h.Publish.Put(model.Key(nodeConfig.GetName()), nodeConfigProto)
}

// nodeConfigToProto converts node-config data from the Contiv's own CRD representation
// into the corresponding protobuf-modelled data format.
func (h *Handler) nodeConfigToProto(nodeConfig *v1.NodeConfig) *model.NodeConfig {
	nodeConfigProto := &model.NodeConfig{}
	nodeConfigProto.NodeName = nodeConfig.Name
	if nodeConfig.Spec.MainVPPInterface.InterfaceName != "" {
		nodeConfigProto.MainVppInterface = h.interfaceConfigToProto(nodeConfig.Spec.MainVPPInterface)
	}
	nodeConfigProto.Gateway = nodeConfig.Spec.Gateway
	nodeConfigProto.StealInterface = nodeConfig.Spec.StealInterface
	nodeConfigProto.NatExternalTraffic = nodeConfig.Spec.NatExternalTraffic
	for _, otherNode := range nodeConfig.Spec.OtherVPPInterfaces {
		nodeConfigProto.OtherVppInterfaces = append(nodeConfigProto.OtherVppInterfaces,
			h.interfaceConfigToProto(otherNode))
	}

	return nodeConfigProto
}

func (h *Handler) interfaceConfigToProto(intfConfig v1.InterfaceConfig) *model.NodeConfig_InterfaceConfig {
	proto := &model.NodeConfig_InterfaceConfig{}
	proto.InterfaceName = intfConfig.InterfaceName
	proto.Ip = intfConfig.IP
	proto.UseDhcp = intfConfig.UseDHCP
	return proto
}
