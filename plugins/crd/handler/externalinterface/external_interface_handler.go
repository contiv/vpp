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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/externalinterface.proto

package externalinterface

import (
	"errors"

	"github.com/contiv/vpp/plugins/crd/handler/externalinterface/model"
	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "ExternalInterface"
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

// CrdObjectToKVData converts the K8s representation of ExternalInterface into the
// corresponding proto message representation.
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	extIface, ok := obj.(*v1.ExternalInterface)
	if !ok {
		return nil, errors.New("failed to cast into ExternalInterface struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.externalInterfaceToProto(extIface),
			KeySuffix: extIface.GetName(),
		},
	}
	return
}

// IsExclusiveKVDB returns true - this is the only writer for ExternalInterface KVs
// in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return true
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	extIface, ok := obj.(*v1.ExternalInterface)
	if !ok {
		return errors.New("failed to cast into ExternalInterface struct")
	}
	extIface = extIface.DeepCopy()
	if opRetval == nil {
		extIface.Status.Status = v1.StatusSuccess
	} else {
		extIface.Status.Status = v1.StatusFailure
		extIface.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().ExternalInterfaces(extIface.Namespace).Update(extIface)
	return err
}

func (h *Handler) externalInterfaceToProto(externalIf *v1.ExternalInterface) *model.ExternalInterface {
	protoVal := &model.ExternalInterface{
		Name:    externalIf.Name,
		Network: externalIf.Spec.Network,
	}
	switch externalIf.Spec.Type {
	case "L2":
		protoVal.Type = model.ExternalInterface_L2
	case "L3":
		protoVal.Type = model.ExternalInterface_L3
	}
	for _, ni := range externalIf.Spec.Nodes {
		protoVal.Nodes = append(protoVal.Nodes, h.nodeInterfaceToProto(ni))
	}
	return protoVal
}

func (h *Handler) nodeInterfaceToProto(nodeIf v1.NodeInterface) *model.ExternalInterface_NodeInterface {
	protoVal := &model.ExternalInterface_NodeInterface{
		Node:             nodeIf.Node,
		VppInterfaceName: nodeIf.VppInterfaceName,
		Ip:               nodeIf.IP,
		Vlan:             nodeIf.VLAN,
	}
	return protoVal
}
