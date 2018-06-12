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

package containeridx

import (
	"github.com/contiv/vpp/mock/broker"
	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
)

func TestPersistingAllocatedIPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	broker := &broker.MockBroker{}
	idx := NewConfigIndex(logrus.DefaultLogger(), "title", broker)
	gomega.Expect(idx).NotTo(gomega.BeNil())

	// register three containers
	err := idx.RegisterContainer("first", &container.Persisted{ID: "first"})
	gomega.Expect(err).To(gomega.BeNil())

	err = idx.RegisterContainer("second", &container.Persisted{ID: "second"})
	gomega.Expect(err).To(gomega.BeNil())

	err = idx.RegisterContainer("third", &container.Persisted{ID: "third"})
	gomega.Expect(err).To(gomega.BeNil())

	// check that there are corresponding record for each of them
	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(3))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("second")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("third")))

	// release one IP
	_, found, err := idx.UnregisterContainer("second")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(found).To(gomega.BeTrue())

	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("third")))

	// load data by another configIndex instance
	anotherIdx := NewConfigIndex(logrus.DefaultLogger(), "title2", broker)
	gomega.Expect(anotherIdx).NotTo(gomega.BeNil())

	_, found, err = anotherIdx.UnregisterContainer("third")
	gomega.Expect(found).To(gomega.BeTrue())
	gomega.Expect(err).To(gomega.BeNil())

	err = anotherIdx.RegisterContainer("fourth", &container.Persisted{ID: "fourth"})
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(container.Key("fourth")))

}
