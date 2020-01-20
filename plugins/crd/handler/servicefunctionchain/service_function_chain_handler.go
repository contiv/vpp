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

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/servicefunctionchain.proto

package servicefunctionchain

import (
	"errors"
	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "ServiceFunctionChain"
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
	svc, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		return nil, errors.New("failed to cast into ServiceFunctionChain struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.serviceFunctionChainToProto(svc),
			KeySuffix: svc.GetName(),
		},
	}
	return
}

// IsExclusiveKVDB returns true - this is the only writer for ServiceFunctionChain KVs
// in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return true
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	svc, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		return errors.New("failed to cast into ServiceFunctionChain struct")
	}
	svc = svc.DeepCopy()
	if opRetval == nil {
		svc.Status.Status = v1.StatusSuccess
	} else {
		svc.Status.Status = v1.StatusFailure
		svc.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().ServiceFunctionChains(svc.Namespace).Update(svc)
	return err
}

// serviceFunctionChainToProto converts service function chain data from the Contiv's own CRD representation
// to the corresponding protobuf-modelled data format.
func (h *Handler) serviceFunctionChainToProto(serviceFunctionChain *v1.ServiceFunctionChain) *model.ServiceFunctionChain {
	chain := &model.ServiceFunctionChain{
		Name:           serviceFunctionChain.Name,
		Unidirectional: serviceFunctionChain.Spec.Unidirectional,
		Network:        serviceFunctionChain.Spec.Network,
	}

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

// Validation generates OpenAPIV3 validator for SFC CRD
func Validation() *apiextv1beta1.CustomResourceValidation {
	one := int64(1)
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"chain"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"unidirectional": {
							Type: "boolean",
						},
						"network": {
							Type: "string",
						},
						"chain": {
							Type: "array",
							Items: &apiextv1beta1.JSONSchemaPropsOrArray{
								Schema: &apiextv1beta1.JSONSchemaProps{
									Type:     "object",
									Required: []string{"type"},
									Properties: map[string]apiextv1beta1.JSONSchemaProps{
										"name": {
											Type: "string",
										},
										"type": {
											Type: "string",
											Enum: []apiextv1beta1.JSON{
												{
													Raw: []byte(`"Pod"`),
												},
												{
													Raw: []byte(`"ExternalInterface"`),
												},
											},
										},
										"podSelector": {
											Type: "object",
											AdditionalProperties: &apiextv1beta1.JSONSchemaPropsOrBool{
												Schema: &apiextv1beta1.JSONSchemaProps{
													Type: "string",
												},
											},
											MinProperties: &one,
										},
										"interface": {
											Type: "string",
										},
										"inputInterface": {
											Type: "string",
										},
										"outputInterface": {
											Type: "string",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return validation
}
