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

package customconfiguration

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/logging"
	"reflect"
	"strings"

	"go.ligato.io/vpp-agent/v2/pkg/models"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "CustomConfiguration"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *Handler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return "/vnf-agent/", false
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *Handler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of CustomConfiguration into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	customConfig, ok := obj.(*v1.CustomConfiguration)
	if !ok {
		return nil, errors.New("failed to cast into CustomConfiguration struct")
	}
	for _, item := range customConfig.Spec.ConfigItems {
		kvdata, err := h.configItemToKVData(item, customConfig.Spec.Microservice)
		if err != nil {
			h.Log.Error(err)
			return nil, err
		}
		data = append(data, kvdata)
	}
	return
}

type withName struct {
	Name string `json:"name"`
}

func (h *Handler) configItemToKVData(item v1.ConfigurationItem, globalMs string) (kvdata kvdbreflector.KVData, err error) {
	var modelSpec *models.KnownModel
	// search in the registered core vpp-agent models
	for _, m := range models.RegisteredModels() {
		if m.Spec().Module == item.Module && m.Spec().Type == item.Type &&
			(item.Version == "" || m.Spec().Version == item.Version) {
			modelSpec = &m
			break
		}
	}

	// convert YAML to JSON
	jsonData, err := yaml.YAMLToJSON([]byte(item.Data))
	if err != nil {
		h.Log.Error(err)
		return kvdata, err
	}

	// determine the destination microservice
	microservice := item.Microservice
	if microservice == "" {
		microservice = globalMs
		if microservice == "" {
			err = fmt.Errorf("missing microservice label for configuration item: %+v", item)
			h.Log.Error(err)
			return kvdata, err
		}
	}

	// use registered model if available
	if modelSpec != nil {
		h.Log.Debugf("Found model for item (%+v): %s", item, modelSpec)
		// this is a configuration item of a registered model - try to unmarshal
		protoMsg := modelSpec.ProtoName()
		valueType := proto.MessageType(protoMsg)
		if valueType == nil {
			err = fmt.Errorf("unknown proto message defined for config item: %+v", item)
			h.Log.Error(err)
			return kvdata, err
		}
		value := reflect.New(valueType.Elem()).Interface().(proto.Message)
		err = jsonpb.UnmarshalString(string(jsonData), value)
		if err != nil {
			h.Log.Error(err)
			return kvdata, err
		}
		key, err := models.GetKey(value)
		if err != nil {
			h.Log.Error(err)
			return kvdata, err
		}
		kvdata = kvdbreflector.KVData{
			ProtoMsg:  value,
			KeySuffix: microservice + "/" + key,
		}
		return kvdata, nil
	}

	// unknown model - try to determine key suffix without a registered model
	h.Log.Debugf("Failed to find model for item (%+v)", item)
	version := item.Version
	if version == "" {
		version = "v1" // default
	}
	name := item.Name
	if name == "" {
		// try to get from the data
		wn := &withName{}
		err = json.Unmarshal(jsonData, wn)
		if err == nil {
			name = wn.Name
		}
	}

	// build the key
	modulePath := strings.Replace(item.Module, ".", "/", -1)
	keySuffix := fmt.Sprintf("%s/config/%s/%s/%s/%s", microservice, modulePath, version, item.Type, name)
	if name == "" {
		// handle global (unnamed) models
		keySuffix = strings.TrimSuffix(keySuffix, "/")
	}

	kvdata = kvdbreflector.KVData{
		MarshalledData: jsonData,
		KeySuffix:      keySuffix,
	}
	return kvdata, nil
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	customConfig, ok := obj.(*v1.CustomConfiguration)
	if !ok {
		return errors.New("failed to cast into CustomConfiguration struct")
	}
	customConfig = customConfig.DeepCopy()
	if opRetval == nil {
		customConfig.Status.Status = v1.StatusSuccess
	} else {
		customConfig.Status.Status = v1.StatusFailure
		customConfig.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().CustomConfigurations(customConfig.Namespace).Update(customConfig)
	return err
}

// Validation generates OpenAPIV3 validator for CustomConfiguration CRD
func Validation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"configItems"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"configItems": {
							Type: "array",
							Items: &apiextv1beta1.JSONSchemaPropsOrArray{
								Schema: &apiextv1beta1.JSONSchemaProps{
									Type:     "object",
									Required: []string{"module", "type", "data"},
									Properties: map[string]apiextv1beta1.JSONSchemaProps{
										"module": {
											Type: "string",
										},
										"type": {
											Type: "string",
										},
										"data": {
											Type: "string",
										},
										"name": {
											Type: "string",
										},
										"version": {
											Type: "string",
										},
										"microservice": {
											Type: "string",
										},
									},
								},
							},
						},
						"microservice": {
							Type: "string",
						},
					},
				},
			},
		},
	}
	return validation
}
