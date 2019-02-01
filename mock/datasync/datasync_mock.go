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

package datasync

import (
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"

	"github.com/contiv/vpp/dbresources"
	controller "github.com/contiv/vpp/plugins/controller/api"
)

// MockDataSync can be used to generate datasync events from provided data.
type MockDataSync struct {
	resyncCount int
	data        map[string]*ProtoData
	anyError    error
}

// ProtoData is used to store proto message with revision.
type ProtoData struct {
	val proto.Message
	rev int64
}

// MockKeyVal implements KeyVal interface.
type MockKeyVal struct {
	key string
	val proto.Message
	rev int64
}

// MockChangeEvent implements ChangeEvent interface.
type MockChangeEvent struct {
	mds *MockDataSync
	wr  *MockProtoWatchResp
}

// MockProtoWatchResp implements ProtoWatchResp interface.
type MockProtoWatchResp struct {
	eventType datasync.Op
	MockKeyVal
	prevVal proto.Message
}

// MockResyncEvent implements ResyncEvent interface.
type MockResyncEvent struct {
	mds         *MockDataSync
	data        map[string]*ProtoData
	keyPrefixes []string
}

// MockKeyValIterator implements KeyValIterator interface.
type MockKeyValIterator struct {
	mre    *MockResyncEvent
	keys   []string
	cursor int
}

//// Data Sync ////

// NewMockDataSync is a constructor for MockDataSync.
func NewMockDataSync() *MockDataSync {
	return &MockDataSync{
		data: make(map[string]*ProtoData),
	}
}

// RestartResyncCount is called after simulated restart to reset the resync counter
// (next resync will be startup).
func (mds *MockDataSync) RestartResyncCount() {
	mds.resyncCount = 0
}

// Put allows to put a new value under the given key and to get the corresponding
// data change event.
func (mds *MockDataSync) Put(key string, value proto.Message) datasync.ChangeEvent {
	newVal, prevVal, rev := mds.put(key, value)
	return &MockChangeEvent{
		mds: mds,
		wr: &MockProtoWatchResp{
			eventType: datasync.Put,
			MockKeyVal: MockKeyVal{
				key: key,
				val: newVal,
				rev: rev,
			},
			prevVal: prevVal,
		},
	}
}

// put is internal implementation of the Put operation
func (mds *MockDataSync) put(key string, value proto.Message) (newVal, prevVal proto.Message, rev int64) {
	if value == nil {
		panic("Put nil value")
	}
	if _, modify := mds.data[key]; modify {
		prevVal = mds.data[key].val
		mds.data[key].val = value
		mds.data[key].rev++
	} else {
		mds.data[key] = &ProtoData{
			val: value,
			rev: 0,
		}
	}
	return value, prevVal, mds.data[key].rev
}

// PutEvent executes Put() and returns the change as KubeStateChange event from Controller.
func (mds *MockDataSync) PutEvent(key string, value proto.Message) (event *controller.KubeStateChange) {
	newVal, prevVal, _ := mds.put(key, value)

	return &controller.KubeStateChange{
		Key:       key,
		Resource:  mds.getResourceByKey(key),
		PrevValue: prevVal,
		NewValue:  newVal,
	}
}

// getResourceByKey tries to find resource-keyword for the resource with the given key.
func (mds *MockDataSync) getResourceByKey(key string) string {
	for _, resource := range dbresources.GetDBResources() {
		if strings.HasPrefix(key, resource.KeyPrefix) {
			return resource.Keyword
		}
	}
	return ""
}

// Delete allows to remove value under the given key and to get the corresponding
// data change event.
func (mds *MockDataSync) Delete(key string) datasync.ChangeEvent {
	prevVal, rev := mds.del(key)
	if prevVal == nil {
		return nil
	}
	return &MockChangeEvent{
		mds: mds,
		wr: &MockProtoWatchResp{
			eventType: datasync.Delete,
			MockKeyVal: MockKeyVal{
				key: key,
				rev: rev,
				val: nil,
			},
			prevVal: prevVal,
		},
	}
}

// del is internal implementation of the Delete operation
func (mds *MockDataSync) del(key string) (prevVal proto.Message, rev int64) {
	if _, found := mds.data[key]; !found {
		return nil, 0
	}
	mds.data[key].rev++
	prevVal = mds.data[key].val
	mds.data[key].val = nil
	return prevVal, mds.data[key].rev
}

// DeleteEvent executes Delete() and returns the change as KubeStateChange event from Controller.
func (mds *MockDataSync) DeleteEvent(key string) (event *controller.KubeStateChange) {
	prevVal, _ := mds.del(key)
	if prevVal == nil {
		return nil
	}
	return &controller.KubeStateChange{
		Key:       key,
		Resource:  mds.getResourceByKey(key),
		PrevValue: prevVal,
		NewValue:  nil,
	}
}

// Resync returns resync event corresponding to a given list of key prefixes
// and the current state of the mocked data store.
func (mds *MockDataSync) Resync(keyPrefix ...string) datasync.ResyncEvent {
	mds.resyncCount++
	mre := &MockResyncEvent{
		keyPrefixes: keyPrefix,
		data:        make(map[string]*ProtoData),
	}
	// copy datastore
	for key, data := range mds.data {
		if data.val == nil {
			continue
		}
		mre.data[key] = &ProtoData{
			val: proto.Clone(data.val),
			rev: data.rev,
		}
	}
	return mre
}

// ResyncEvent returns the same data as Resync(), but formatted as DBResync event
// from the controller.
func (mds *MockDataSync) ResyncEvent(keyPrefix ...string) (event *controller.DBResync, resyncCount int) {
	mds.resyncCount++
	event = controller.NewDBResync()
	for key, data := range mds.data {
		if data.val == nil {
			continue
		}
		resource := mds.getResourceByKey(key)
		event.KubeState[resource][key] = data.val
	}
	return event, mds.resyncCount
}

// AnyError returns non-nil if any data change or resync event was processed
// unsuccessfully.
func (mds *MockDataSync) AnyError() error {
	return mds.anyError
}

//// Key-Value ////

// GetValue returns the associated value.
func (mkv *MockKeyVal) GetValue(value proto.Message) error {
	if mkv.val == nil {
		return nil
	}
	tmp, err := proto.Marshal(mkv.val)
	if err != nil {
		return err
	}
	return proto.Unmarshal(tmp, value)
}

// GetRevision returns the associated revision.
func (mkv *MockKeyVal) GetRevision() (rev int64) {
	return mkv.rev
}

// GetKey returns the associated key.
func (mkv *MockKeyVal) GetKey() string {
	return mkv.key
}

//// Change Event ////

// Done stores non-nil error to MockDataSync.
func (mche *MockChangeEvent) Done(err error) {
	if err != nil {
		mche.mds.anyError = err
	}
}

func (mche *MockChangeEvent) GetChanges() []datasync.ProtoWatchResp {
	return []datasync.ProtoWatchResp{mche.wr}
}

// GetChangeType returns either "Put" or "Delete".
func (mpw *MockProtoWatchResp) GetChangeType() datasync.Op {
	return mpw.eventType
}

// GetPrevValue returns the previous value.
func (mpw *MockProtoWatchResp) GetPrevValue(prevValue proto.Message) (prevValueExist bool, err error) {
	if mpw.prevVal == nil {
		return false, nil
	}
	tmp, err := proto.Marshal(mpw.prevVal)
	if err != nil {
		return true, err
	}
	return true, proto.Unmarshal(tmp, prevValue)
}

//// Resync Event ////

// Done stores non-nil error to MockDataSync.
func (mre *MockResyncEvent) Done(err error) {
	if err != nil {
		mre.mds.anyError = err
	}
}

// GetValues returns map "key-prefix->iterator".
func (mre *MockResyncEvent) GetValues() map[ /*keyPrefix*/ string]datasync.KeyValIterator {
	values := make(map[string]datasync.KeyValIterator)
	for _, prefix := range mre.keyPrefixes {
		var keys []string
		for key := range mre.data {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		if len(keys) > 0 {
			values[prefix] = &MockKeyValIterator{
				mre:  mre,
				keys: keys,
			}
		}
	}

	return values
}

//// Key Value Iterator ////

// GetNext returns the next item in the list.
func (mkvi *MockKeyValIterator) GetNext() (kv datasync.KeyVal, allReceived bool) {
	if mkvi.cursor == len(mkvi.keys) {
		return nil, true
	}
	key := mkvi.keys[mkvi.cursor]
	kv = &MockKeyVal{
		key: key,
		val: mkvi.mre.data[key].val,
		rev: mkvi.mre.data[key].rev,
	}
	mkvi.cursor++
	return kv, false
}
