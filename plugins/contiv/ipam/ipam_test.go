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

// Package ipam_test is responsible for testing of IP addresses management
package ipam_test

import (
	"testing"

	"github.com/ligato/cn-infra/logging/logrus"
	. "github.com/onsi/gomega"

	"fmt"
	"net"
	"strconv"

	"github.com/contiv/vpp/plugins/contiv/ipam"
)

//TODO maybe check multiple hosts IPAMs for no interconnection between them and that hostID is not hardwired into them somehow

const (
	b10000000 = 1 << 7
	b11000000 = 1<<7 + 1<<6
	b11000010 = 1<<7 + 1<<6 + 1<<1
	b10100001 = 1<<7 + 1<<5 + 1
	b10100101 = 1<<7 + 1<<5 + 1<<2 + 1
	b11100101 = 1<<7 + 1<<6 + 1<<5 + 1<<2 + 1

	incorrectHostIDForIPAllocation = ""
)

var (
	logger = logrus.DefaultLogger()

	hostID1                        uint8 = b10100001
	hostID2                        uint8 = b10100101
	podID                                = "podID"
	expectedPodNetwork                   = network("1.2." + str(b10000000+int(hostID1>>5)) + "." + str(int(hostID1<<3)) + "/29")
	expectedVSwitchNetwork               = network("2.3." + str(b11000000+int(hostID1>>6)) + "." + str(int(hostID1<<2)) + "/30")
	expectedPodNetworkZeroEndingIP       = net.IPv4(1, 2, b10000000+hostID1>>5, hostID1<<3).To4()
	expectedPodNetworkGatewayIP          = net.IPv4(1, 2, b10000000+hostID1>>5, (hostID1<<3)+1).To4()
)

func newDefaultConfig() *ipam.Config {
	return &ipam.Config{
		PodIfIPCIDR:             "10.2.1.0/24",
		PodSubnetCIDR:           "1.2." + str(b10000000) + ".2/17",
		PodNetworkPrefixLen:     29, // 3 bits left -> 6 free IP addresses (gateway IP + zero ending IP is reserved)
		VPPHostSubnetCIDR:       "2.3." + str(b11000000) + ".2/18",
		VPPHostNetworkPrefixLen: 30, // 2 bit left -> 3 free IP addresses (zero ending IP is reserved)
		NodeInterconnectCIDR:    "3.4.5." + str(b11000010) + "/26",
		VxlanCIDR:               "4.5.6." + str(b11000010) + "/26",
	}
}

func setup(t *testing.T, cfg *ipam.Config) *ipam.IPAM {
	RegisterTestingT(t)

	i, err := ipam.New(logrus.DefaultLogger(), uint8(hostID1), cfg, nil)
	Expect(err).To(BeNil())
	return i
}

// TestStaticGetters tests exposed IPAM API that provides data that doesn't change in time (and are not dynamically
// recomputed based on new input in form of API function parameters)
func TestStaticGetters(t *testing.T) {
	i := setup(t, newDefaultConfig())
	Expect(i.NodeID()).To(BeEquivalentTo(hostID1))

	// pods addresses IPAM API
	Expect(*i.PodSubnet()).To(BeEquivalentTo(network("1.2." + str(b10000000) + ".0/17")))
	Expect(*i.PodNetwork()).To(BeEquivalentTo(expectedPodNetwork))
	Expect(expectedPodNetwork.Contains(i.PodGatewayIP())).To(BeTrue(), "Pod Gateway IP is not in range of network for pods for given host.")

	// vSwitch addresses IPAM API
	Expect(*i.VPPHostNetwork()).To(BeEquivalentTo(expectedVSwitchNetwork))
	Expect(expectedVSwitchNetwork.Contains(i.VEthHostEndIP())).To(BeTrue(), "VEthHostEndIP is not in range of vSwitch network for given host.")
	Expect(expectedVSwitchNetwork.Contains(i.VEthVPPEndIP())).To(BeTrue(), "VEthVPPEndIP is not in range of vSwitch network for given host.")
}

// TestDynamicGetters tests proper working IMAP API that provides data based on new input (func parameters)
func TestDynamicGetters(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.NodeIPAddress(hostID2)
	Expect(err).To(BeNil())
	Expect(ip).To(BeEquivalentTo(net.IPv4(3, 4, 5, b11100101).To4()))

	ipNet, err := i.NodeIPWithPrefix(hostID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(ipWithNetworkMask("3.4.5." + str(b11100101) + "/26")))

	ipNet, err = i.VxlanIPWithPrefix(hostID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(ipWithNetworkMask("4.5.6." + str(b11100101) + "/26")))

	ipNet, err = i.OtherNodePodNetwork(hostID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(network("1.2." + str(b10000000+int(hostID2>>5)) + "." + str(int(hostID2<<3)) + "/29")))

	ipNet, err = i.OtherNodeVPPHostNetwork(hostID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(network("2.3." + str(b11000000+int(hostID2>>6)) + "." + str(int(hostID2<<2)) + "/30")))
}

// TestBasicAllocateReleasePodAddress test simple happy path scenario for getting 1 pod address and releasing it
func TestBasicAllocateReleasePodAddress(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.NextPodIP(podID)
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(i.PodNetwork().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	err = i.ReleasePodIP(podID)
	Expect(err).To(BeNil())
}

// TestAssigniningIncrementalIPs test whether released IPs are reused only once all the range is exhausted
func TestAssigniningIncrementalIPs(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.NextPodIP(podID)
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(ip.String()).To(BeEquivalentTo("1.2.133.10"))
	Expect(i.PodNetwork().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	second, err := i.NextPodIP(podID + "2")
	Expect(err).To(BeNil())
	Expect(second).NotTo(BeNil())
	Expect(second.String()).To(BeEquivalentTo("1.2.133.11"))
	Expect(i.PodNetwork().Contains(second)).To(BeTrue(), "Pod IP address is not from pod network")

	err = i.ReleasePodIP(podID + "2")
	Expect(err).To(BeNil())

	// check that second is not reused
	third, err := i.NextPodIP(podID + "3")
	Expect(err).To(BeNil())
	Expect(third).NotTo(BeNil())
	Expect(third.String()).To(BeEquivalentTo("1.2.133.12"))
	Expect(i.PodNetwork().Contains(third)).To(BeTrue(), "Pod IP address is not from pod network")

	// exhaust the range
	for j := 0; j < 3; j++ {
		assigned, err := i.NextPodIP(podID + "n" + fmt.Sprint(j))
		Expect(err).To(BeNil())
		Expect(assigned).NotTo(BeNil())
		Expect(i.PodNetwork().Contains(assigned)).To(BeTrue(), "Pod IP address is not from pod network")
	}

	// expect released ip to be reused
	reused, err := i.NextPodIP(podID + "2")
	Expect(err).To(BeNil())
	Expect(reused).NotTo(BeNil())
	Expect(i.PodNetwork().Contains(reused)).To(BeTrue(), "Pod IP address is not from pod network")
	Expect(reused.String()).To(BeEquivalentTo("1.2.133.11"))

}

// TestBadInputForIPAllocation tests expected failure of IP allocation caused by bad input
func TestBadInputForIPAllocation(t *testing.T) {
	i := setup(t, newDefaultConfig())
	_, err := i.NextPodIP(incorrectHostIDForIPAllocation)
	Expect(err).NotTo(BeNil())
}

// TestIgnoringOfBadInputForIPRelease tests special case of ignored bad input for pod IP release that happens by kubernetes restart
func TestIgnoringOfBadInputForIPRelease(t *testing.T) {
	i := setup(t, newDefaultConfig())
	err := i.ReleasePodIP(incorrectHostIDForIPAllocation)
	Expect(err).To(BeNil())
}

// TestDistinctAllocations test whether all pod IP addresses are distinct to each other until exhaustion of the whole IP address pool
func TestDistinctAllocations(t *testing.T) {
	i := setup(t, newDefaultConfig())
	assertAllocationOfAllIPAddresses(i, 6, expectedPodNetwork)
	assertCorrectIPExhaustion(i, 6)
}

// TestReleaseOfAllIPAddresses tests proper releasing of pod IP addresses by allocating them again. If any pod IP
// address is not properly released then additional allocation of all pod IP addresses will fail (either
// ipam.NextPodIP(...) will fail by providing all ip addresses or one ip addresses will be allocated twice)
func TestReleaseOfAllIPAddresses(t *testing.T) {
	i := setup(t, newDefaultConfig())
	exhaustPodIPAddresses(i, 6)
	releaseAllPodAddresses(i, 6)
	assertAllocationOfAllIPAddresses(i, 6, expectedPodNetwork)
}

// TestReleaseOfSomeIPAddresses is variation of TestReleaseOfAllIPAddresses test. Releasing of all pod IP addresses and
// allocating them again is special case and IPAM can handle it differently. Distinct case (not so special) is to release
// only portion of pod IP addresses and assert their reallocation.
func TestReleaseOfSomeIPAddresses(t *testing.T) {
	i := setup(t, newDefaultConfig())
	addresses, podids := exhaustPodIPAddresses(i, 6)
	releaseSomePodAddresses(i, podids[3:])
	assertAllocationOfIPAddresses(i, addresses[3:], expectedPodNetwork)
	assertCorrectIPExhaustion(i, 6)
}

// Test8bitPodIPPoolSize tests pod IP allocation for nice-looking distinct case when subnet/network is aligned to IP Address bytes
func Test8bitPodIPPoolSize(t *testing.T) {
	customConfig := newDefaultConfig()
	customConfig.PodSubnetCIDR = "1.2.3.4/16"
	customConfig.PodNetworkPrefixLen = 24
	i := setup(t, customConfig)

	podNetwork := network("1.2." + str(int(hostID1)) + ".0/24")
	maxIPCount := 256 - 2 //2 IPs are reserved

	assertAllocationOfAllIPAddresses(i, maxIPCount, podNetwork)
	assertCorrectIPExhaustion(i, maxIPCount)
}

// TestBiggerThan8bitPodIPPoolSize tests pod IP allocation for more than 256 IP Addresses (mare then 8-bit allocated for IP addresses)
func TestBiggerThan8bitPodIPPoolSize(t *testing.T) {
	customConfig := newDefaultConfig()
	customConfig.PodSubnetCIDR = "1.4.1.2/14"
	customConfig.PodNetworkPrefixLen = 22
	i := setup(t, customConfig)

	b00000100 := 1 << 2
	podNetwork := network("1." + str(b00000100+int(hostID1>>6)) + "." + str(int(hostID1<<2)) + ".0/22")
	maxIPCount := 256*4 - 2 //2 IPs are reserved

	assertAllocationOfAllIPAddresses(i, maxIPCount, podNetwork)
	assertCorrectIPExhaustion(i, maxIPCount)
}

// TestHostIDtrimming test IPAM ability to properly create IP address part corresponding to host ID. More precise the
// case when 8-bit hostID doesn't fit into less-then-8bit IP Part.
func TestHostIDtrimming(t *testing.T) {
	customConfig := newDefaultConfig()
	customConfig.PodSubnetCIDR = "1.2.3.4/19"
	customConfig.PodNetworkPrefixLen = 24
	i := setup(t, customConfig)

	Expect(*i.PodNetwork()).To(BeEquivalentTo(network("1.2." + str(int(hostID1&(1<<5-1))) + ".0/24")))
}

// TestConfigWithBadCIDR test if IPAM detects incorrect unparsable CIDR string and handles it correctly (initialization returns error)
func TestConfigWithBadCIDR(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.PodSubnetCIDR = "1.2.3./19"
	_, err := ipam.New(logrus.DefaultLogger(), uint8(hostID1), customConfig, nil)
	Expect(err).NotTo(BeNil(), "Pod subnet CIDR is unparsable, but IPAM initialization didn't fail")

	customConfig = newDefaultConfig()
	customConfig.VPPHostSubnetCIDR = "1.2.3./19"
	_, err = ipam.New(logrus.DefaultLogger(), uint8(hostID1), customConfig, nil)
	Expect(err).NotTo(BeNil(), "VSwitch subnet CIDR is unparsable, but IPAM initialization didn't fail")

	customConfig = newDefaultConfig()
	customConfig.NodeInterconnectCIDR = "1.2.3./19"
	_, err = ipam.New(logrus.DefaultLogger(), uint8(hostID1), customConfig, nil)
	Expect(err).NotTo(BeNil(), "Host subnet CIDR is unparsable, but IPAM initialization didn't fail")
}

// TestConfigWithBadPrefixSizes tests if IPAM detects incorrect prefix length of subnet and network
func TestConfigWithBadPrefixSizes(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.PodSubnetCIDR = "1.2.3.4/19"
	customConfig.PodNetworkPrefixLen = 18
	_, err := ipam.New(logrus.DefaultLogger(), uint8(hostID1), customConfig, nil)
	Expect(err).NotTo(BeNil())

	customConfig = newDefaultConfig()
	customConfig.VPPHostSubnetCIDR = "1.2.3.4/19"
	customConfig.VPPHostNetworkPrefixLen = 18
	_, err = ipam.New(logrus.DefaultLogger(), uint8(hostID1), customConfig, nil)
	Expect(err).NotTo(BeNil())
}

func exhaustPodIPAddresses(i *ipam.IPAM, maxIPCount int) (allocatedIPs []string, allocatedPodIDS []string) {
	for j := 1; j <= maxIPCount; j++ {
		podID := strconv.Itoa(j)
		ip, _ := i.NextPodIP(podID)
		allocatedIPs = append(allocatedIPs, ip.To4().String())
		allocatedPodIDS = append(allocatedPodIDS, podID)
	}
	return
}

func releaseSomePodAddresses(i *ipam.IPAM, toRelease []string) {
	for _, nodeID := range toRelease {
		i.ReleasePodIP(nodeID)
	}
}

func releaseAllPodAddresses(i *ipam.IPAM, ipCount int) {
	for j := 1; j <= ipCount; j++ {
		i.ReleasePodIP(strconv.Itoa(j))
	}
}

func assertCorrectIPExhaustion(i *ipam.IPAM, maxIPCount int) {
	_, err := i.NextPodIP(strconv.Itoa(maxIPCount + 1))
	Expect(err).NotTo(BeNil(), "Pool of free IP addresses should be empty, but IPAM allocation function didn't fail")
}

func assertAllocationOfIPAddresses(i *ipam.IPAM, expectedIPs []string, network net.IPNet) {
	freeIPsCount := len(expectedIPs)
	for j := 1; j <= freeIPsCount; j++ {
		ip, err := i.NextPodIP(strconv.Itoa(j) + "-secondAllocation")
		Expect(err).To(BeNil(), "Can't successfully allocate %v. IP address", j)
		assertAllocationOfIPAddress(ip, network)
		Expect(expectedIPs).To(ContainElement(ip.String()), "Allocated IP is not from given IP slice")
	}
}

func assertAllocationOfAllIPAddresses(i *ipam.IPAM, maxIPCount int, network net.IPNet) {
	allocated := make(map[string]bool, maxIPCount)
	for j := 1; j <= maxIPCount; j++ {
		ip, err := i.NextPodIP(strconv.Itoa(j))
		Expect(err).To(BeNil(), "Can't successfully allocate %v. IP address out of %v possible IP addresses", j, maxIPCount)
		Expect(allocated[ip.String()]).To(BeFalse(), "IP address %v is allocated second time", ip)
		assertAllocationOfIPAddress(ip, network)
		allocated[ip.String()] = true
	}
}

func assertAllocationOfIPAddress(ip net.IP, network net.IPNet) {
	Expect(network.Contains(ip)).To(BeTrue(), fmt.Sprintf("Allocated IP %v is not in range of network %v.", ip, network))
	Expect(ip).NotTo(BeEquivalentTo(expectedPodNetworkZeroEndingIP), "Network IP address (range part filled with zeroes) should not be assignable pod IP address")
	Expect(ip).NotTo(BeEquivalentTo(expectedPodNetworkGatewayIP), "GateWay IP should not be assignable pod IP address")
}

func network(networkCIDR string) net.IPNet {
	_, result, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		logger.Errorf("Network can't be parsed from string \"%v\" due to error: %v", networkCIDR, err)
		return net.IPNet{} //dummy network that will fail any test
	}
	return *result
}

func ipWithNetworkMask(ipWithMaskCIDR string) net.IPNet {
	ip, result, err := net.ParseCIDR(ipWithMaskCIDR)
	if err != nil {
		logger.Errorf("IpWithNetworkMask can't be parsed from string \"%v\" due to error: %v", ipWithMaskCIDR, err)
		return net.IPNet{} //dummy IpWithNetworkMask that will fail any test
	}
	result.IP = ip.To4()
	return *result
}

func str(i int) string {
	return strconv.Itoa(i)
}
