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

	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/db/keyval"
)

// KeyProtoValLister allows a reflector to list values that the reflector
// previously stored in in ETCD.
type KeyProtoValLister interface {
	// List values stored in etcd under the given prefix.
	ListValues(prefix string) (keyval.ProtoKeyValIterator, error)
}

// mockKeyProtoValLister is a mock implementation of KeyProtoValLister
// used in unit tests.
type mockKeyProtoValLister struct {
	numErr int
	err    error
	ds     map[string]proto.Message
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

// newMockKeyProtoValLister initializes a new instance of
// newMockKeyProtoValLister.
func newMockKeyProtoValLister(ds map[string]proto.Message) *mockKeyProtoValLister {
	return &mockKeyProtoValLister{
		err:    nil,
		numErr: 0,
		ds:     ds,
	}
}

// ListValues returns the mockProtoKeyValIterator which will contain some
// mock values down the road
func (kvl *mockKeyProtoValLister) ListValues(prefix string) (keyval.ProtoKeyValIterator, error) {
	if kvl.numErr > 0 {
		kvl.numErr--
		return nil, kvl.err
	}

	var values []keyval.ProtoKeyVal
	for key, msg := range kvl.ds {
		pkv := mockProtoKeyval{
			key: key,
			msg: msg,
		}
		values = append(values, &pkv)
	}
	return &mockProtoKeyValIterator{
		values: values,
		idx:    0,
	}, nil
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

// injectError sets the error value to be returned from 'numErr' subsequent
// list operations.
func (kvl *mockKeyProtoValLister) injectError(err error, numErr int) {
	kvl.numErr = numErr
	kvl.err = err
}
