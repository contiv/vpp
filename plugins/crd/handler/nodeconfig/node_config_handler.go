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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/nodeconfig.proto

package nodeconfig

import (
	"errors"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "NodeConfig"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *Handler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.Keyword + "/", true
}

// IsCrdKeySuffix always returns true - the key prefix does not overlap with
// other CRDs or KSR-reflected K8s data.
func (h *Handler) IsCrdKeySuffix(keySuffix string) bool {
	return true
}

// CrdObjectToKVData converts the K8s representation of NodeConfig into the
// corresponding proto message representation.
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	nodeConfig, ok := obj.(*v1.NodeConfig)
	if !ok {
		return nil, errors.New("failed to cast into NodeConfig struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.nodeConfigToProto(nodeConfig),
			KeySuffix: nodeConfig.GetName(),
		},
	}
	return
}

// IsExclusiveKVDB returns true - this is the only writer for NodeConfig KVs
// in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return true
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	nodeConfig, ok := obj.(*v1.NodeConfig)
	if !ok {
		return errors.New("failed to cast into NodeConfig struct")
	}
	nodeConfig = nodeConfig.DeepCopy()
	if opRetval == nil {
		nodeConfig.Status.State = v1.StatusSuccess
	} else {
		nodeConfig.Status.State = v1.StatusFailure
		nodeConfig.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.NodeconfigV1().NodeConfigs(nodeConfig.Namespace).Update(nodeConfig)
	return err
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
	protoVal := &model.NodeConfig_InterfaceConfig{}
	protoVal.InterfaceName = intfConfig.InterfaceName
	protoVal.Ip = intfConfig.IP
	protoVal.UseDhcp = intfConfig.UseDHCP
	return protoVal
}
