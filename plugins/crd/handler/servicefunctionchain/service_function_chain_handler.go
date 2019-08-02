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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/servicefunctionchain.proto

package servicefunctionchain

import (
	"errors"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "ServiceFunctionChain"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *Handler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.Keyword, true
}

// IsCrdKeySuffix always returns true - the key prefix does not overlap with
// other CRDs or KSR-reflected K8s data.
func (h *Handler) IsCrdKeySuffix(keySuffix string) bool {
	return true
}

// CrdObjectToProto converts the K8s representation of ServiceFunctionChain into the
// corresponding proto message representation.
func (h *Handler) CrdObjectToProto(obj interface{}) (data proto.Message, keySuffix string, err error) {
	svc, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		return nil, "", errors.New("failed to cast into ServiceFunctionChain struct")
	}

	data = h.serviceFunctionChainToProto(svc)
	keySuffix = svc.GetName()
	return
}

// CrdProtoFactory creates an empty instance of the CRD proto model.
func (h *Handler) CrdProtoFactory() proto.Message {
	return &model.ServiceFunctionChain{}
}

// IsExclusiveKVDB returns true - this is the only writer for ServiceFunctionChain KVs
// in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return true
}

// serviceFunctionChainToProto converts service function chain data from the Contiv's own CRD representation
// to the corresponding protobuf-modelled data format.
func (h *Handler) serviceFunctionChainToProto(serviceFunctionChain *v1.ServiceFunctionChain) *model.ServiceFunctionChain {
	chain := &model.ServiceFunctionChain{}
	chain.Name = serviceFunctionChain.Name

	for _, c := range serviceFunctionChain.Spec.Chain {
		chain.Chain = append(chain.Chain,
			h.serviceFunctionToProto(c))
	}

	return chain
}

func (h *Handler) serviceFunctionToProto(sf v1.ServiceFunction) *model.ServiceFunctionChain_ServiceFunction {
	protoVal := &model.ServiceFunctionChain_ServiceFunction{}
	protoVal.Name = sf.Name
	switch sf.Type {
	case "Pod":
		protoVal.Type = model.ServiceFunctionChain_ServiceFunction_Pod
	case "ExternalInterface":
		protoVal.Type = model.ServiceFunctionChain_ServiceFunction_ExternalInterface
	default:
		protoVal.Type = model.ServiceFunctionChain_ServiceFunction_Pod
	}
	protoVal.PodSelector = map[string]string{}
	for k, v := range sf.PodSelector {
		protoVal.PodSelector[k] = v
	}
	protoVal.Interface = sf.Interface
	protoVal.InputInterface = sf.InputInterface
	protoVal.OutputInterface = sf.OutputInterface
	return protoVal
}
