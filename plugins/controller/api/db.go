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
	"sort"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/dbresources"
)

// KeyValuePairs is a set of key-value pairs.
type KeyValuePairs map[string]proto.Message

// KubeStateData contains Kubernetes state data organized as key-value pairs sorted
// by the resource type.
type KubeStateData map[string]KeyValuePairs // resource name -> {(key, value)}

/******************************** DB Resync ***********************************/

// DBResync is a Resync Event that carries snapshot of the database for all watched
// Kubernetes resources and the external configuration (for vpp-agent).
type DBResync struct {
	Local          bool // against local DB?
	KubeState      KubeStateData
	ExternalConfig KeyValuePairs
}

// NewDBResync is a constructor for DBResync
func NewDBResync() *DBResync {
	return &DBResync{
		KubeState:      NewKubeStateData(),
		ExternalConfig: make(KeyValuePairs),
	}
}

// NewKubeStateData is a constructor for KubeStateData.
func NewKubeStateData() KubeStateData {
	kubeStateData := make(KubeStateData)
	for _, resource := range dbresources.GetDBResources() {
		kubeStateData[resource.Keyword] = make(KeyValuePairs)
	}
	return kubeStateData
}

// withName is implemented by Kubernetes resources that have a name.
type withName interface {
	// GetName is implemented by resources with Name.
	GetName() string
}

// withNamespace is implemented by Kubernetes resources that are in a namespace.
type withNamespace interface {
	// GetNamespace is implemented by resources with Namespace.
	GetNamespace() string
}

// GetName returns name of the DBResync event.
func (ev *DBResync) GetName() string {
	return "Database Resync"
}

// String describes DBResync event.
func (ev *DBResync) String() string {
	str := ev.GetName()
	if ev.Local {
		str += " (Local DB)"
	} else {
		str += " (Remote DB)"
	}

	// order resources alphabetically
	var resources []string
	for resource := range ev.KubeState {
		resources = append(resources, resource)
	}
	sort.Strings(resources)

	// describe Kubernetes state
	empty := true
	for _, resource := range resources {
		var (
			withColon     string
			resourceItems []string
		)
		data := ev.KubeState[resource]
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
			resourceItems = append(resourceItems, valueStr)
		}
		if len(resourceItems) == 0 {
			continue
		}
		empty = false
		sort.Strings(resourceItems)
		str += fmt.Sprintf("\n* %dx %s%s",
			len(data), resource, withColon)
		for _, resourceItem := range resourceItems {
			str += "\n    - " + resourceItem
		}
	}

	// describe external config if there is any
	var externalKeys []string
	for key := range ev.ExternalConfig {
		externalKeys = append(externalKeys, key)
	}
	sort.Strings(externalKeys)
	if len(externalKeys) > 0 {
		empty = false
		str += fmt.Sprintf("\n* %dx external config items: %s",
			len(externalKeys), strings.Join(externalKeys, ", "))
	}

	// handle empty DB
	if empty {
		str += " - empty dataset"
	}
	return str
}

// Method is FullResync.
func (ev *DBResync) Method() EventMethodType {
	return FullResync
}

// IsBlocking returns false.
func (ev *DBResync) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *DBResync) Done(error) {
	return
}

/***************************** Kube State Change ******************************/

// KubeStateChange is an Update event that represents change for one key from
// Kubernetes state data.
type KubeStateChange struct {
	Key       string
	Resource  string
	PrevValue proto.Message // nil if newly added
	NewValue  proto.Message // nil if deleted
}

// GetName returns name of the KubeStateChange event.
func (ev *KubeStateChange) GetName() string {
	return "Kubernetes State Change"
}

// String describes KubeStateChange event.
func (ev *KubeStateChange) String() string {
	return fmt.Sprintf("%s\n"+
		"* resource: %s\n"+
		"* key: %s\n"+
		"* prev-value: %s\n"+
		"* new-value: %s", ev.GetName(), ev.Resource, ev.Key,
		protoToString(ev.PrevValue), protoToString(ev.NewValue))
}

// Method is Update.
func (ev *KubeStateChange) Method() EventMethodType {
	return Update
}

// TransactionType is BestEffort.
func (ev *KubeStateChange) TransactionType() UpdateTransactionType {
	return BestEffort
}

// Direction is forward.
func (ev *KubeStateChange) Direction() UpdateDirectionType {
	if ev.NewValue == nil {
		// the item is being removed - undo changes in the reverse direction
		return Reverse
	}
	return Forward
}

// IsBlocking returns false.
func (ev *KubeStateChange) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *KubeStateChange) Done(error) {
	return
}

// protoToString converts proto message to string
func protoToString(msg proto.Message) string {
	if msg == nil {
		return "<nil>"
	}
	return msg.String()
}

/*************************** External Config Change ***************************/

// ExternalConfigChange is an Update event that represents change for one or more
// keys from the external configuration (for vpp-agent).
type ExternalConfigChange struct {
	result   chan error
	blocking bool

	Source     string
	UpdatedKVs KeyValuePairs
}

// NewExternalConfigChange is a constructor for ExternalConfigChange.
func NewExternalConfigChange(source string, blocking bool) *ExternalConfigChange {
	return &ExternalConfigChange{
		result:     make(chan error, 1),
		blocking:   blocking,
		Source:     source,
		UpdatedKVs: make(KeyValuePairs),
	}
}

// GetName returns name of the ExternalConfigChange event.
func (ev *ExternalConfigChange) GetName() string {
	return "External Config Change"
}

// String describes ExternalConfigChange event.
func (ev *ExternalConfigChange) String() string {
	const (
		PutOpName = "PUT"
		DelOpName = "DEL"
	)
	var hasPut, hasDelete bool
	flags := []string{strings.ToUpper(ev.Source)}

	for _, value := range ev.UpdatedKVs {
		if value == nil {
			hasDelete = true
		} else {
			hasPut = true
		}
	}
	if hasPut != hasDelete {
		if hasPut {
			flags = append(flags, PutOpName)
		} else {
			flags = append(flags, DelOpName)
		}
	}
	str := ev.GetName() + " " + flagsToString(flags, 0)
	for key, value := range ev.UpdatedKVs {
		var flags []string
		if hasPut == hasDelete {
			if value != nil {
				flags = append(flags, PutOpName)
			} else {
				flags = append(flags, DelOpName)
			}
		}
		str += fmt.Sprintf("\n* %skey: %s", flagsToString(flags, 1), key)
		str += fmt.Sprintf("\n  new-value: %s", value)
	}
	return str
}

func flagsToString(flags []string, trailingSpace int) string {
	if len(flags) == 0 {
		return ""
	}
	return "[" + strings.Join(flags, ", ") + "]" + strings.Repeat(" ", trailingSpace)
}

// Method is Update.
func (ev *ExternalConfigChange) Method() EventMethodType {
	return Update
}

// TransactionType is BestEffort.
func (ev *ExternalConfigChange) TransactionType() UpdateTransactionType {
	return BestEffort
}

// Direction is Forward.
func (ev *ExternalConfigChange) Direction() UpdateDirectionType {
	return Forward
}

// IsBlocking returns what is configured in the constructor.
func (ev *ExternalConfigChange) IsBlocking() bool {
	return ev.blocking
}

// Done propagates error to the event producer.
func (ev *ExternalConfigChange) Done(err error) {
	ev.result <- err
	return
}

// Wait waits for the result of the ExternalConfigChange event.
func (ev *ExternalConfigChange) Wait() error {
	return <-ev.result
}

/*************************** External Config Resync ***************************/

// ExternalConfigResync is a Resync event triggered by external config source.
// Note: External config from Remote DB uses DBResync instead.
type ExternalConfigResync struct {
	result   chan error
	blocking bool

	Source         string
	ExternalConfig KeyValuePairs
}

// NewExternalConfigResync is a constructor for ExternalConfigResync.
func NewExternalConfigResync(source string, blocking bool) *ExternalConfigResync {
	return &ExternalConfigResync{
		result:         make(chan error, 1),
		blocking:       blocking,
		Source:         source,
		ExternalConfig: make(KeyValuePairs),
	}
}

// GetName returns name of the ExternalConfigResync event.
func (ev *ExternalConfigResync) GetName() string {
	return "External Config Resync"
}

// String describes ExternalConfigResync event.
func (ev *ExternalConfigResync) String() string {
	flags := []string{strings.ToUpper(ev.Source)}
	str := ev.GetName() + " " + flagsToString(flags, 0)
	for key := range ev.ExternalConfig {
		str += fmt.Sprintf("\n* key: %s", key)
	}
	return str
}

// Method is Update.
func (ev *ExternalConfigResync) Method() EventMethodType {
	return UpstreamResync
}

// IsBlocking returns what is configured in the constructor.
func (ev *ExternalConfigResync) IsBlocking() bool {
	return ev.blocking
}

// Done propagates error to the event producer.
func (ev *ExternalConfigResync) Done(err error) {
	ev.result <- err
	return
}

// Wait waits for the result of the ExternalConfigResync event.
func (ev *ExternalConfigResync) Wait() error {
	return <-ev.result
}
