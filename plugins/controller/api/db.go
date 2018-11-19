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

package api

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
	"strings"
)

// KeyValuePairs is a set of key-value pairs.
type KeyValuePairs map[string]proto.Message

// KubeStateData contains Kubernetes state data organized as key-value pairs sorted
// by the resource type.
type KubeStateData map[string]KeyValuePairs // resource name -> {(key, value)}

type DBResource struct {
	Name             string
	ProtoMessageName string
	KeyPrefix        string
}

/******************************** DB Resync ***********************************/

type DBResync struct {
	KubeState      KubeStateData
	ExternalConfig map[string][]byte // key -> raw value
}

type withName interface {
	// GetName is implemented by resources with Name.
	GetName() string
}

type withNamespace interface {
	// GetNamespace is implemented by resources with Namespace.
	GetNamespace() string
}

func (ev *DBResync) GetName() string {
	return "Database Resync"
}

func (ev *DBResync) String() string {
	str := ev.GetName()

	// describe Kubernetes state
	for resource, data := range ev.KubeState {
		var strPerResource []string
		for key, value := range data {
			var valueStr string
			valWithName, hasName := value.(withName)
			valWithNamespace, hasNamespace := value.(withNamespace)
			if !hasName {
				valueStr = key
			}
			if hasName && !hasNamespace {
				valueStr = valWithName.GetName()
			}
			if hasName && hasNamespace {
				valueStr = valWithNamespace.GetNamespace() + "/" + valWithName.GetName()
			}
			strPerResource = append(strPerResource, valueStr)
		}
		str += fmt.Sprintf("\n* %dx %s: %s",
			len(data), resource, strings.Join(strPerResource, ", "))
	}

	// describe external config if there is any
	var externalKeys []string
	for key := range ev.ExternalConfig {
		externalKeys = append(externalKeys, key)
	}
	if len(externalKeys) > 0 {
		str += fmt.Sprintf("\n* %dx external config items: %s",
			len(externalKeys), strings.Join(externalKeys, ", "))
	}
	return str
}

func (ev *DBResync) Method() EventMethodType {
	return Resync
}

/***************************** Kube State Change ******************************/

type KubeStateChange struct {
	Key       string
	PrevValue proto.Message
	NewValue  proto.Message
}

func (ev *KubeStateChange) GetName() string {
	return "Kubernetes State Change"
}

func (ev *KubeStateChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* key: %s\n"+
		"* prev-value: %s\n"+
		"* new-value: %s", ev.GetName(), ev.Key, ev.PrevValue.String(), ev.NewValue.String())
}

func (ev *KubeStateChange) Method() EventMethodType {
	return Update
}

func (ev *KubeStateChange) TransactionType() UpdateTransactionType {
	return BestEffort
}

func (ev *KubeStateChange) Direction() UpdateDirectionType {
	return Forward
}

/*************************** External Config Change ***************************/

type ExternalConfigChange struct {
	Key       string
	PrevValue []byte
	NewValue  []byte
}

func (ev *ExternalConfigChange) GetName() string {
	return "External Config Change"
}

func (ev *ExternalConfigChange) String() string {
	return fmt.Sprintf("%s (key: %s)", ev.GetName(), ev.Key)
}

func (ev *ExternalConfigChange) Method() EventMethodType {
	return Update
}

func (ev *ExternalConfigChange) TransactionType() UpdateTransactionType {
	return BestEffort
}

func (ev *ExternalConfigChange) Direction() UpdateDirectionType {
	return Forward
}
