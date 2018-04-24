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

package testdata

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

const (
	namespace  = "default"
	namespace2 = "namespace2"
)

var (
	PodIDs = []podmodel.ID{
		{Name: "pod1", Namespace: namespace},
		{Name: "pod2", Namespace: namespace},
		{Name: "pod3", Namespace: namespace},
		{Name: "pod4", Namespace: namespace},
		{Name: "pod5", Namespace: namespace},
		{Name: "pod6", Namespace: namespace2},
	}

	PodIPs = []string{
		/* node 1: */
		"10.10.1.1",
		"10.10.1.2",
		"10.10.2.1",
		"10.10.2.2",
		"10.10.2.3",
		/* node 2: */
		"10.10.10.1",
	}

	PodIfNames = []string{
		"node1-tap1",
		"node1-tap2",
		"node1-tap3",
		"node1-tap4",
		"node1-tap5",
		"node2-tap1",
	}

	// aliases
	Pod1 = PodIDs[0]
	Pod2 = PodIDs[1]
	Pod3 = PodIDs[2]
	Pod4 = PodIDs[3]
	Pod5 = PodIDs[4]
	Pod6 = PodIDs[5]

	Pod1IP = PodIPs[0]
	Pod2IP = PodIPs[1]
	Pod3IP = PodIPs[2]
	Pod4IP = PodIPs[3]
	Pod5IP = PodIPs[4]
	Pod6IP = PodIPs[5]

	Pod1IfName = PodIfNames[0]
	Pod2IfName = PodIfNames[1]
	Pod3IfName = PodIfNames[2]
	Pod4IfName = PodIfNames[3]
	Pod5IfName = PodIfNames[4]
	Pod6IfName = PodIfNames[5]
)

// Input data for test-set 1:
type TestSet1And2 struct {
	Rule *renderer.ContivRule
}

var Ts1 = TestSet1And2{ /* one egress rule */
	Rule: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork("192.168.0.0/16"),
		DestNetwork: IpNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	},
}

// Input data for test-set 2:
var Ts2 = TestSet1And2{ /* one ingress rule */
	Rule: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork(""),
		DestNetwork: IpNetwork("192.168.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    80,
	},
}

// Input data for test-set 3:
type TestSet3To6 struct {
	Rule1, Rule2 *renderer.ContivRule
}

var Ts3 = TestSet3To6{ /* multiple egress rules */
	Rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork("10.10.0.0/16"),
		DestNetwork: IpNetwork(""),
		Protocol:    renderer.ANY,
		SrcPort:     0,
		DestPort:    0,
	},
	Rule2: DenyAll(),
}

// Input data for test-set 4:
var Ts4 = TestSet3To6{ /* multiple ingress rules */
	Rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork(""),
		DestNetwork: IpNetwork("10.10.0.0/16"),
		Protocol:    renderer.ANY,
		SrcPort:     0,
		DestPort:    0,
	},
	Rule2: DenyAll(),
}

var Ts5 = TestSet3To6{ /* multiple egress rules - only TCP allowed */
	Rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork("10.10.0.0/16"),
		DestNetwork: IpNetwork(""),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	},
	Rule2: DenyAll(),
}

// Input data for test-set 4:
var Ts6 = TestSet3To6{ /* multiple ingress rules - only TCP allowed */
	Rule1: &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  IpNetwork(""),
		DestNetwork: IpNetwork("10.10.0.0/16"),
		Protocol:    renderer.TCP,
		SrcPort:     0,
		DestPort:    0,
	},
	Rule2: DenyAll(),
}

// Input data for test-set 5:
type TestSet7 struct {
	Pod1Ingress, Pod1Egress []*renderer.ContivRule
	Pod3Ingress, Pod3Egress []*renderer.ContivRule
}

var Ts7 = TestSet7{ /* combined ingress with egress */
	Pod1Ingress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork(""),
			DestNetwork: IpNetwork("10.10.0.0/16"),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    80,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork(""),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    161,
		},
		DenyAll(),
	},
	Pod1Egress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork("10.0.0.0/8"),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    53,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork("192.168.0.0/16"),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    514,
		},
		DenyAll(),
	},
	Pod3Ingress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork(""),
			DestNetwork: IpNetwork("10.10.1.1/32"),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    0,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork(""),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    22,
		},
		DenyAll(),
	},
	Pod3Egress: []*renderer.ContivRule{
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork("10.0.0.0/8"),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    80,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork("10.0.0.0/8"),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    443,
		},
		{
			Action:      renderer.ActionPermit,
			SrcNetwork:  IpNetwork(""),
			DestNetwork: IpNetwork(""),
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    67,
		},
		DenyAll(),
	},
}

// Helper methods

func IpNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, _ := net.ParseCIDR(addr)
	return network
}

func AllowAll() *renderer.ContivRule {
	ruleTCPAny := &renderer.ContivRule{
		Action:      renderer.ActionPermit,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.ANY,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleTCPAny
}

func DenyAll() *renderer.ContivRule {
	ruleTCPNone := &renderer.ContivRule{
		Action:      renderer.ActionDeny,
		SrcNetwork:  &net.IPNet{},
		DestNetwork: &net.IPNet{},
		Protocol:    renderer.ANY,
		SrcPort:     0,
		DestPort:    0,
	}
	return ruleTCPNone
}
