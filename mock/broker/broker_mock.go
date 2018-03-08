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

package broker

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"strings"
)

type MockBroker struct {
	Data map[string]proto.Message
}

func (mb *MockBroker) Keys() []string {
	var res []string
	for k := range mb.Data {
		res = append(res, k)
	}
	return res
}

func (mb *MockBroker) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	if mb.Data == nil {
		mb.Data = map[string]proto.Message{}
	}
	mb.Data[key] = data
	return nil
}

func (mb *MockBroker) Delete(key string, opts ...datasync.DelOption) (found bool, err error) {
	_, found = mb.Data[key]
	delete(mb.Data, key)
	return found, nil
}

func (mb *MockBroker) GetValue(key string, val proto.Message) (found bool, rev int64, err error) {
	return false, 0, nil
}

func (mb *MockBroker) NewTxn() keyval.ProtoTxn {
	return nil
}

func (mb *MockBroker) ListKeys(prefix string) (keyval.ProtoKeyIterator, error) {
	return nil, nil
}

func (mb *MockBroker) ListValues(key string) (keyval.ProtoKeyValIterator, error) {
	var match []string
	for k := range mb.Data {
		if strings.HasPrefix(k, key) {
			match = append(match, k)
		}
	}
	return &mockIt{broker: mb, match: match}, nil
}

type mockIt struct {
	broker *MockBroker
	match  []string
	index  int
}

func (mi *mockIt) GetNext() (kv keyval.ProtoKeyVal, stop bool) {
	if mi.index >= len(mi.match) {
		return nil, true
	}
	key := mi.match[mi.index]
	kv = &mockKv{key: key, val: mi.broker.Data[key]}
	mi.index++
	return kv, false

}

func (mi *mockIt) Close() error {
	return nil
}

type mockKv struct {
	key string
	val proto.Message
}

func (mk *mockKv) GetValue(val proto.Message) error {
	tmp, err := proto.Marshal(mk.val)
	if err != nil {
		return err
	}
	return proto.Unmarshal(tmp, val)

}

func (mk *mockKv) GetPrevValue(val proto.Message) (exists bool, err error) {
	return false, nil
}

func (mk *mockKv) GetKey() string {
	return mk.key
}

func (mk *mockKv) GetRevision() int64 {
	return 0
}
