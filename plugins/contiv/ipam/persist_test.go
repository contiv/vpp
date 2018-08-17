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
	"github.com/contiv/vpp/mock/broker"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/ipam/model"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
)

func TestPersistingAllocatedIPs(t *testing.T) {
	gomega.RegisterTestingT(t)
	broker := &broker.MockBroker{}
	myIpam, err := ipam.New(logrus.DefaultLogger(), 1, "", newDefaultConfig(), nil, broker, nil)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(myIpam).NotTo(gomega.BeNil())

	// allocated three IPs
	_, err = myIpam.NextPodIP("first")
	gomega.Expect(err).To(gomega.BeNil())

	secondIP, err := myIpam.NextPodIP("second")
	gomega.Expect(err).To(gomega.BeNil())

	_, err = myIpam.NextPodIP("third")
	gomega.Expect(err).To(gomega.BeNil())

	// check that there are corresponding record for each of them
	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(3))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("second")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("third")))

	// release one IP
	err = myIpam.ReleasePodIP("second")
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("third")))

	// load data by another IPAM instance
	anotherIPAM, err := ipam.New(logrus.DefaultLogger(), 1, "", newDefaultConfig(), nil, broker, nil)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(anotherIPAM).NotTo(gomega.BeNil())

	err = anotherIPAM.ReleasePodIP("third")
	gomega.Expect(err).To(gomega.BeNil())

	fourthIP, err := anotherIPAM.NextPodIP("fourth")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(broker.Data)).To(gomega.BeEquivalentTo(2))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("first")))
	gomega.Expect(broker.Keys()).To(gomega.ContainElement(model.Key("fourth")))

	// check that IPs are not reused even after restart
	gomega.Expect(secondIP).ToNot(gomega.BeEquivalentTo(fourthIP))

}
