// Copyright (c) 2017 Cisco and/or its affiliates.
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

package ipam

import (
	"net"
	"testing"

	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
)

type configTestVars struct {
	log *logrus.Logger
}

var ctv configTestVars

func TestValidator(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	ctv.log = logrus.DefaultLogger()
	ctv.log.SetLevel(logging.DebugLevel)

	// Do the testing
	t.Run("testApplyIPAM", testApplyIPAM)
}

func ipNet(network string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(network)
	gomega.Expect(err).To(gomega.BeNil())
	return ipNet
}

func testApplyIPAM(t *testing.T) {
	// Try with  /14 subnet mask
	configData1 := &contivconf.IPAMConfig{
		ContivCIDR: ipNet("10.128.0.0/14"),
	}
	// Try with invalid subnet mask
	configData2 := &contivconf.IPAMConfig{
		ContivCIDR: ipNet("10.130.0.0/18"),
	}
	// Try with /14 subnet mask
	configData3 := &contivconf.IPAMConfig{
		ContivCIDR: ipNet("192.254.0.0/12"),
	}

	// Try with overridden NodeInterconnectCIDR
	configData4 := &contivconf.IPAMConfig{
		ContivCIDR: ipNet("10.128.0.0/14"),
		CustomIPAMSubnets: contivconf.CustomIPAMSubnets{
			NodeInterconnectCIDR: ipNet("192.168.16.0/24"),
		},
	}

	// Try with NodeInterconnectDHCP enabled
	configData5 := &contivconf.IPAMConfig{
		ContivCIDR:           ipNet("10.128.0.0/14"),
		NodeInterconnectDHCP: true,
	}

	subnets, err := dissectContivCIDR(configData1)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(subnets.PodSubnetCIDR.String()).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(subnets.VPPHostSubnetCIDR.String()).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(subnets.NodeInterconnectCIDR.String()).To(gomega.Equal("10.130.0.0/23"))
	gomega.Expect(subnets.VxlanCIDR.String()).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(subnets.PodVPPSubnetCIDR.String()).To(gomega.Equal("10.130.4.0/25"))

	subnets, err = dissectContivCIDR(configData2)
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

	subnets, err = dissectContivCIDR(configData3)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(subnets.PodSubnetCIDR.String()).To(gomega.Equal("192.240.0.0/16"))
	gomega.Expect(subnets.VPPHostSubnetCIDR.String()).To(gomega.Equal("192.241.0.0/16"))
	gomega.Expect(subnets.NodeInterconnectCIDR.String()).To(gomega.Equal("192.242.0.0/23"))
	gomega.Expect(subnets.VxlanCIDR.String()).To(gomega.Equal("192.242.2.0/23"))
	gomega.Expect(subnets.PodVPPSubnetCIDR.String()).To(gomega.Equal("192.242.4.0/25"))

	subnets, err = dissectContivCIDR(configData4)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(subnets.PodSubnetCIDR.String()).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(subnets.VPPHostSubnetCIDR.String()).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(subnets.NodeInterconnectCIDR.String()).To(gomega.Equal("192.168.16.0/24"))
	gomega.Expect(subnets.VxlanCIDR.String()).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(subnets.PodVPPSubnetCIDR.String()).To(gomega.Equal("10.130.4.0/25"))

	subnets, err = dissectContivCIDR(configData5)
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(subnets.PodSubnetCIDR.String()).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(subnets.VPPHostSubnetCIDR.String()).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(subnets.NodeInterconnectCIDR).To(gomega.BeNil())
	gomega.Expect(subnets.VxlanCIDR.String()).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(subnets.PodVPPSubnetCIDR.String()).To(gomega.Equal("10.130.4.0/25"))
}
