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

package ipam_test

import (
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/ipam/model"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"strings"
	"testing"
)

func TestPersistingAllocatedIPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	broker := &mockBroker{}
	myIpam, err := ipam.New(logrus.DefaultLogger(), 1, newDefaultConfig(), broker)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(myIpam).NotTo(gomega.BeNil())

	// allocated three IPs
	_, err = myIpam.NextPodIP("first")
	gomega.Expect(err).To(gomega.BeNil())

	_, err = myIpam.NextPodIP("second")
	gomega.Expect(err).To(gomega.BeNil())

	_, err = myIpam.NextPodIP("third")
	gomega.Expect(err).To(gomega.BeNil())

	// check that there are corresponding record for each of them
	gomega.Expect(len(broker.data)).To(gomega.BeEquivalentTo(3))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("second")))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("third")))

	// release one IP
	err = myIpam.ReleasePodIP("second")
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(broker.data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("third")))

	// load data by another IPAM instance
	anotherIPAM, err := ipam.New(logrus.DefaultLogger(), 1, newDefaultConfig(), broker)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(anotherIPAM).NotTo(gomega.BeNil())

	err = anotherIPAM.ReleasePodIP("third")
	gomega.Expect(err).To(gomega.BeNil())

	_, err = anotherIPAM.NextPodIP("fourth")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(broker.data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.keys()).To(gomega.ContainElement(model.Key("fourth")))

}

type mockBroker struct {
	data map[string]proto.Message
}

func (mb *mockBroker) keys() []string {
	var res []string
	for k := range mb.data {
		res = append(res, k)
	}
	return res
}

func (mb *mockBroker) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	if mb.data == nil {
		mb.data = map[string]proto.Message{}
	}
	mb.data[key] = data
	return nil
}

func (mb *mockBroker) Delete(key string, opts ...datasync.DelOption) (found bool, err error) {
	_, found = mb.data[key]
	delete(mb.data, key)
	return found, nil
}

func (mb *mockBroker) GetValue(key string, val proto.Message) (found bool, rev int64, err error) {
	return false, 0, nil
}

func (mb *mockBroker) NewTxn() keyval.ProtoTxn {
	return nil
}

func (mb *mockBroker) ListKeys(prefix string) (keyval.ProtoKeyIterator, error) {
	return nil, nil
}

func (mb *mockBroker) ListValues(key string) (keyval.ProtoKeyValIterator, error) {
	var match []string
	for k := range mb.data {
		if strings.HasPrefix(k, key) {
			match = append(match, k)
		}
	}
	return &mockIt{broker: mb, match: match}, nil
}

type mockIt struct {
	broker *mockBroker
	match  []string
	index  int
}

func (mi *mockIt) GetNext() (kv keyval.ProtoKeyVal, stop bool) {
	if mi.index >= len(mi.match) {
		return nil, true
	}
	key := mi.match[mi.index]
	kv = &mockKv{key: key, val: mi.broker.data[key]}
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
