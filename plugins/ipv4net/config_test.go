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

package ipv4net

import (
	"github.com/contiv/vpp/plugins/ipv4net/ipam"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
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

func testApplyIPAM(t *testing.T) {
	// Try with  /14 subnet mask
	configData1 := &Config{
		IPAMConfig: ipam.Config{
			ContivCIDR: "10.128.0.0/14",
		},
	}
	// Try with invalid subnet mask
	configData2 := &Config{
		IPAMConfig: ipam.Config{
			ContivCIDR: "10.130.0.0/18",
		},
	}
	// Try with /14 subnet mask
	configData3 := &Config{
		IPAMConfig: ipam.Config{
			ContivCIDR: "192.254.0.0/12",
		},
	}
	// try with manual ipam config
	configData4 := &Config{
		IPAMConfig: ipam.Config{
			NodeInterconnectDHCP:          false,
			NodeInterconnectCIDR:          "192.168.16.0/24",
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			PodVPPSubnetCIDR:              "10.2.1.0/24",
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			VxlanCIDR:                     "192.168.30.0/24",
			ContivCIDR:                    "",
		},
	}

	// Try with overridden NodeInterconnectCIDR
	configData5 := &Config{
		IPAMConfig: ipam.Config{
			ContivCIDR:           "10.128.0.0/14",
			NodeInterconnectCIDR: "192.168.16.0/24",
		},
	}

	// Try with NodeInterconnectDHCP enabled
	configData6 := &Config{
		IPAMConfig: ipam.Config{
			ContivCIDR:           "10.128.0.0/14",
			NodeInterconnectDHCP: true,
		},
	}

	err := configData1.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(configData1.IPAMConfig.PodSubnetCIDR).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(configData1.IPAMConfig.VPPHostSubnetCIDR).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(configData1.IPAMConfig.NodeInterconnectCIDR).To(gomega.Equal("10.130.0.0/23"))
	gomega.Expect(configData1.IPAMConfig.VxlanCIDR).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(configData1.IPAMConfig.PodVPPSubnetCIDR).To(gomega.Equal("10.130.4.0/25"))

	err = configData2.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.Not(gomega.BeNil()))

	err = configData3.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(configData3.IPAMConfig.PodSubnetCIDR).To(gomega.Equal("192.240.0.0/16"))
	gomega.Expect(configData3.IPAMConfig.VPPHostSubnetCIDR).To(gomega.Equal("192.241.0.0/16"))
	gomega.Expect(configData3.IPAMConfig.NodeInterconnectCIDR).To(gomega.Equal("192.242.0.0/23"))
	gomega.Expect(configData3.IPAMConfig.VxlanCIDR).To(gomega.Equal("192.242.2.0/23"))
	gomega.Expect(configData3.IPAMConfig.PodVPPSubnetCIDR).To(gomega.Equal("192.242.4.0/25"))

	err = configData4.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(configData4.IPAMConfig.PodSubnetCIDR).To(gomega.Equal("10.1.0.0/16"))
	gomega.Expect(configData4.IPAMConfig.VPPHostSubnetCIDR).To(gomega.Equal("172.30.0.0/16"))
	gomega.Expect(configData4.IPAMConfig.NodeInterconnectCIDR).To(gomega.Equal("192.168.16.0/24"))
	gomega.Expect(configData4.IPAMConfig.VxlanCIDR).To(gomega.Equal("192.168.30.0/24"))
	gomega.Expect(configData4.IPAMConfig.PodVPPSubnetCIDR).To(gomega.Equal("10.2.1.0/24"))

	err = configData5.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(configData5.IPAMConfig.PodSubnetCIDR).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(configData5.IPAMConfig.VPPHostSubnetCIDR).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(configData5.IPAMConfig.NodeInterconnectCIDR).To(gomega.Equal("192.168.16.0/24"))
	gomega.Expect(configData5.IPAMConfig.VxlanCIDR).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(configData5.IPAMConfig.PodVPPSubnetCIDR).To(gomega.Equal("10.130.4.0/25"))

	err = configData6.ApplyIPAMConfig()
	gomega.Expect(err).To(gomega.BeNil())

	gomega.Expect(configData6.IPAMConfig.PodSubnetCIDR).To(gomega.Equal("10.128.0.0/16"))
	gomega.Expect(configData6.IPAMConfig.VPPHostSubnetCIDR).To(gomega.Equal("10.129.0.0/16"))
	gomega.Expect(configData6.IPAMConfig.NodeInterconnectCIDR).To(gomega.Equal(""))
	gomega.Expect(configData6.IPAMConfig.NodeInterconnectDHCP).To(gomega.BeTrue())
	gomega.Expect(configData6.IPAMConfig.VxlanCIDR).To(gomega.Equal("10.130.2.0/23"))
	gomega.Expect(configData6.IPAMConfig.PodVPPSubnetCIDR).To(gomega.Equal("10.130.4.0/25"))
}
