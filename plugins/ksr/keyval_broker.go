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

package ksr

import (
	"encoding/json"
	"errors"

	"github.com/ligato/cn-infra/db/keyval"

	"github.com/golang/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
)

// Error message if not data is found for a given key
const (
	noDataForKey = "No data assigned to key "
)

// KeyProtoValBroker allows reflectors to push their data changes to a data
// store. This interface extends the same name interface from cn-infra/datasync
// with the Delete() operation.
type KeyProtoValBroker interface {
	// Put <data> to ETCD or to any other key-value based data source.
	Put(key string, data proto.Message, opts ...datasync.PutOption) error

	// Delete data under the <key> in ETCD or in any other key-value based data
	// source.
	Delete(key string, opts ...datasync.DelOption) (existed bool, err error)

	// GetValue reads a value from etcd stored under the given key.
	GetValue(key string, reqObj proto.Message) (found bool, revision int64, err error)

	// List values stored in etcd under the given prefix.
	ListValues(prefix string) (keyval.ProtoKeyValIterator, error)
}

// dataStoreItem defines the struture of the data store in the mock data store.
type dataStoreItem struct {
	val proto.Message
	rev int64
}

// mockKeyProtoVaBroker is a mock implementation of KeyProtoValBroker used
// in unit tests.
type mockKeyProtoVaBroker struct {
	numErr int
	err    error
	ds     map[string]dataStoreItem
}

// newMockKeyProtoValBroker returns a new instance of mockKeyProtoVaBroker.
func newMockKeyProtoValBroker() *mockKeyProtoVaBroker {
	return &mockKeyProtoVaBroker{
		numErr: 0,
		err:    nil,
		ds:     make(map[string]dataStoreItem),
	}
}

// injectError sets the error value to be returned from 'numErr' subsequent
// data store operations to the specified value.
func (mock *mockKeyProtoVaBroker) injectError(err error, numErr int) {
	mock.numErr = numErr
	mock.err = err
}

// clearError resets the error value returned from data store operations
// to nil.
func (mock *mockKeyProtoVaBroker) clearError() {
	mock.injectError(nil, 0)
}

// Put puts data into an in-memory map simulating a key-value datastore.
func (mock *mockKeyProtoVaBroker) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	if mock.numErr > 0 {
		mock.numErr--
		return mock.err
	}

	newData := dataStoreItem{val: data, rev: 1}
	oldData, found := mock.ds[key]
	if found {
		newData.rev = oldData.rev + 1
	}
	mock.ds[key] = newData
	return nil
}

// Delete removes data from an in-memory map simulating a key-value datastore.
func (mock *mockKeyProtoVaBroker) Delete(key string, opts ...datasync.DelOption) (existed bool, err error) {
	if mock.numErr > 0 {
		mock.numErr--
		return false, mock.err
	}

	_, existed = mock.ds[key]
	if !existed {
		return false, nil
	}
	delete(mock.ds, key)
	return true, nil
}

// GetValue is a helper for unit tests to get value stored under a given key.
func (mock *mockKeyProtoVaBroker) GetValue(key string, out proto.Message) (found bool, revision int64, err error) {
	if mock.numErr > 0 {
		mock.numErr--
		return false, 0, mock.err
	}

	data, exists := mock.ds[key]
	if !exists {
		return false, 0, errors.New(noDataForKey + key)
	}
	proto.Merge(out, data.val)
	return true, data.rev, nil
}

// ClearDs is a helper which allows to clear the in-memory map simulating
// a key-value datastore.
func (mock *mockKeyProtoVaBroker) ClearDs() {
	for key := range mock.ds {
		delete(mock.ds, key)
	}
}

// ListValues returns the mockProtoKeyValIterator which will contain some
// mock values down the road
func (mock *mockKeyProtoVaBroker) ListValues(prefix string) (keyval.ProtoKeyValIterator, error) {
	if mock.numErr > 0 {
		mock.numErr--
		return nil, mock.err
	}

	var values []keyval.ProtoKeyVal
	for key, dsItem := range mock.ds {
		pkv := mockProtoKeyval{
			key: key,
			msg: dsItem.val,
		}
		values = append(values, &pkv)
	}
	return &mockProtoKeyValIterator{
		values: values,
		idx:    0,
	}, nil
}

// mockProtoKeyValIterator is a mock implementation of ProtoKeyValIterator
// used in unit tests.
type mockProtoKeyValIterator struct {
	values []keyval.ProtoKeyVal
	idx    int
}

type mockProtoKeyval struct {
	key string
	msg proto.Message
}

func (pkv *mockProtoKeyval) GetKey() string {
	return pkv.key
}

func (pkv *mockProtoKeyval) GetPrevValue(prevValue proto.Message) (prevValueExist bool, err error) {
	return false, nil
}

func (pkv *mockProtoKeyval) GetValue(value proto.Message) error {
	buf, err := json.Marshal(pkv.msg)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, value)
}

func (pkv *mockProtoKeyval) GetRevision() (rev int64) {
	return 0
}

// GetNext getting the next mocked keyval.ProtoKeyVal value from
// mockProtoKeyValIterator
func (it *mockProtoKeyValIterator) GetNext() (kv keyval.ProtoKeyVal, stop bool) {
	if it.idx == len(it.values) {
		return nil, true
	}
	kv = it.values[it.idx]
	it.idx++
	return kv, stop
}

// Close is a mock for mockProtoKeyValIterator
func (it *mockProtoKeyValIterator) Close() error {
	return nil
}
