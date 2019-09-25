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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/customnetwork.proto

package customnetwork

import (
	"errors"
	"github.com/contiv/vpp/plugins/crd/handler/customnetwork/model"
	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
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
	return "CustomNetwork"
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

// CrdObjectToKVData converts the K8s representation of CustomNetwork into the
// corresponding proto message representation.
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	customNet, ok := obj.(*v1.CustomNetwork)
	if !ok {
		return nil, errors.New("failed to cast into CustomNetwork struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.customNetworkToProto(customNet),
			KeySuffix: customNet.GetName(),
		},
	}
	return
}

// IsExclusiveKVDB returns true - this is the only writer for CustomNetwork KVs
// in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return true
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	customNet, ok := obj.(*v1.CustomNetwork)
	if !ok {
		return errors.New("failed to cast into CustomNetwork struct")
	}
	customNet = customNet.DeepCopy()
	if opRetval == nil {
		customNet.Status.Status = v1.StatusSuccess
	} else {
		customNet.Status.Status = v1.StatusFailure
		customNet.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().CustomNetworks(customNet.Namespace).Update(customNet)
	return err
}

// customNetworkToProto converts custom-network data from the Contiv's own CRD representation
// to the corresponding protobuf-modelled data format.
func (h *Handler) customNetworkToProto(customNetwork *v1.CustomNetwork) *model.CustomNetwork {
	customNetworkProto := &model.CustomNetwork{}
	customNetworkProto.Name = customNetwork.Name

	switch customNetwork.Spec.Type {
	case "L2":
		customNetworkProto.Type = model.CustomNetwork_L2
	case "L3":
		customNetworkProto.Type = model.CustomNetwork_L3
	case "STUB":
		customNetworkProto.Type = model.CustomNetwork_STUB
	}
	customNetworkProto.SubnetCIDR = customNetwork.Spec.SubnetCIDR
	customNetworkProto.SubnetOneNodePrefix = customNetwork.Spec.SubnetOneNodePrefixLen
	return customNetworkProto
}

// Validation generates OpenAPIV3 validator for custom network CRD
func Validation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"type"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"type": {
							Type: "string",
							Enum: []apiextv1beta1.JSON{
								{
									Raw: []byte(`"L2"`),
								},
								{
									Raw: []byte(`"L3"`),
								},
								{
									Raw: []byte(`"STUB"`),
								},
							},
						},
						"subnetCIDR": {
							Type:        "string",
							Description: "IPv4 or IPv6 address with prefix length",
							Pattern:     `^[0-9a-fA-F:\.]+/[0-9]+$`,
						},
						"subnetOneNodePrefix": {
							Type: "integer",
						},
					},
				},
			},
		},
	}
	return validation
}
