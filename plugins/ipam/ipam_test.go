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

package ipam

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/servicelabel"

	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	"bytes"
	"github.com/contiv/vpp/plugins/contivconf"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
)

//TODO maybe check multiple hosts IPAMs for no interconnection between them and that hostID is not hardwired into them somehow

const (
	b10000000 = 1 << 7
	b11000000 = 1<<7 + 1<<6
	b11000101 = 1<<7 + 1<<6 + 1<<2 + 1
	b00000101 = 1<<2 + 1
)

var (
	logger = logrus.DefaultLogger()

	nodeName        = "node"
	nodeID1  uint32 = 1
	nodeID2  uint32 = b00000101

	podID = []podmodel.ID{
		{Namespace: "default", Name: "pod1"},
		{Namespace: "default", Name: "pod2"},
		{Namespace: "kube-system", Name: "pod3"},
		{Namespace: "default", Name: "pod4"},
	}

	expectedPodSubnetThisNode             = network("1.2." + str(b10000000+int(nodeID1>>5)) + "." + str(int(nodeID1<<3)) + "/29")
	expectedVSwitchNetwork                = network("2.3." + str(b11000000+int(nodeID1>>6)) + "." + str(int(nodeID1<<2)) + "/30")
	expectedPodSubnetThisNodeZeroEndingIP = net.IPv4(1, 2, byte(b10000000+nodeID1>>5), byte(nodeID1<<3)).To4()
	expectedPodSubnetThisNodeGatewayIP    = net.IPv4(1, 2, byte(b10000000+nodeID1>>5), byte((nodeID1<<3)+1)).To4()
)

func newDefaultConfig() *contivconf.Config {
	return &contivconf.Config{
		IPAMConfig: contivconf.IPAMConfigForJSON{
			PodSubnetCIDR:                 "1.2." + str(b10000000) + ".0/17",
			PodSubnetOneNodePrefixLen:     29, // 3 bits left -> 4 free IP addresses (gateway IP + NAT-loopback IP + network addr + broadcast are reserved)
			VPPHostSubnetCIDR:             "2.3." + str(b11000000) + ".0/18",
			VPPHostSubnetOneNodePrefixLen: 30, // 2 bit left -> 3 free IP addresses (zero ending IP is reserved)
			NodeInterconnectCIDR:          "3.4.5." + str(b11000000) + "/26",
			VxlanCIDR:                     "4.5.6." + str(b11000000) + "/26",
		},
	}
}

func setup(t *testing.T, cfg *contivconf.Config) *IPAM {
	RegisterTestingT(t)
	i, err := newIPAM(cfg, nodeID1)
	Expect(err).To(BeNil())
	return i
}

func newIPAM(cfg *contivconf.Config, nodeID uint32) (i *IPAM, err error) {
	datasync := NewMockDataSync()
	resyncEv, _ := datasync.ResyncEvent(podmodel.KeyPrefix())

	// service label
	serviceLabel := NewMockServiceLabel()
	serviceLabel.SetAgentLabel(nodeName)

	// nodesync mock plugin
	nodeSync := NewMockNodeSync(nodeName)
	nodeSync.UpdateNode(&nodesync.Node{
		ID:   nodeID,
		Name: nodeName,
	})

	// contivConf real plugin
	conf := &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: serviceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: cfg,
			},
		},
	}
	err = conf.Init()
	if err != nil {
		return nil, err
	}
	err = conf.Resync(resyncEv, resyncEv.KubeState, 1, nil)
	if err != nil {
		return nil, err
	}

	// IPAM real plugin
	i = &IPAM{
		Deps: Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("ipam"),
			},
			NodeSync:   nodeSync,
			ContivConf: conf,
		},
	}
	err = i.Init()
	if err != nil {
		return nil, err
	}
	err = i.Resync(resyncEv, resyncEv.KubeState, 1, nil)
	if err != nil {
		return nil, err
	}
	return i, nil
}

// TestStaticGetters tests exposed IPAM API that provides data that doesn't change in time (and are not dynamically
// recomputed based on new input in form of API function parameters)
func TestStaticGetters(t *testing.T) {
	i := setup(t, newDefaultConfig())

	// pods addresses IPAM API
	Expect(*i.PodSubnetAllNodes()).To(BeEquivalentTo(network("1.2." + str(b10000000) + ".0/17")))
	Expect(*i.PodSubnetThisNode()).To(BeEquivalentTo(expectedPodSubnetThisNode))
	Expect(expectedPodSubnetThisNode.Contains(i.PodGatewayIP())).To(BeTrue(), "Pod Gateway IP is not in range of network for pods for given host.")

	// vSwitch addresses IPAM API
	Expect(*i.HostInterconnectSubnetThisNode()).To(BeEquivalentTo(expectedVSwitchNetwork))
	Expect(expectedVSwitchNetwork.Contains(i.HostInterconnectIPInLinux())).To(BeTrue(), "HostInterconnectIPInLinux is not in range of vSwitch network for given host.")
	Expect(expectedVSwitchNetwork.Contains(i.HostInterconnectIPInVPP())).To(BeTrue(), "HostInterconnectIPInVPP is not in range of vSwitch network for given host.")
}

// TestDynamicGetters tests proper working IMAP API that provides data based on new input (func parameters)
func TestDynamicGetters(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, _, err := i.NodeIPAddress(nodeID2)
	Expect(err).To(BeNil())
	Expect(ip).To(BeEquivalentTo(net.IPv4(3, 4, 5, b11000101).To4()))

	ip, ipNet, err := i.NodeIPAddress(nodeID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(ipWithNetworkMask("3.4.5.192/26")))
	Expect(ip.String()).To(BeEquivalentTo("3.4.5.197"))

	ip, ipNet, err = i.VxlanIPAddress(nodeID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(ipWithNetworkMask("4.5.6.192/26")))
	Expect(ip.String()).To(BeEquivalentTo("4.5.6.197"))

	ipNet, err = i.PodSubnetOtherNode(nodeID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(network("1.2." + str(b10000000+int(nodeID2>>5)) + "." + str(int(nodeID2<<3)) + "/29")))

	ipNet, err = i.HostInterconnectSubnetOtherNode(nodeID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(network("2.3." + str(b11000000+int(nodeID2>>6)) + "." + str(int(nodeID2<<2)) + "/30")))
}

// TestBasicAllocateReleasePodAddress test simple happy path scenario for getting 1 pod address and releasing it
func TestBasicAllocateReleasePodAddress(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.AllocatePodIP(podID[0], "", "")
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(i.PodSubnetThisNode().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	err = i.ReleasePodIP(podID[0])
	Expect(err).To(BeNil())
}

// TestAlreadyAllocated tests that repeated allocation for a given podID returns the same IP
func TestAlreadyAllocatedAddress(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.AllocatePodIP(podID[0], "", "")
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(i.PodSubnetThisNode().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	repeated, err := i.AllocatePodIP(podID[0], "", "")
	Expect(err).To(BeNil())
	Expect(repeated).NotTo(BeNil())
	Expect(bytes.Compare(repeated, ip)).To(BeZero())

	err = i.ReleasePodIP(podID[0])
	Expect(err).To(BeNil())
}

// TestAssigniningIncrementalIPs test whether released IPs are reused only once all the range is exhausted
func TestAssigniningIncrementalIPs(t *testing.T) {
	i := setup(t, newDefaultConfig())
	ip, err := i.AllocatePodIP(podID[0], "", "")
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(ip.String()).To(BeEquivalentTo("1.2.128.10"))
	Expect(i.PodSubnetThisNode().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	second, err := i.AllocatePodIP(podID[1], "", "")
	Expect(err).To(BeNil())
	Expect(second).NotTo(BeNil())
	Expect(second.String()).To(BeEquivalentTo("1.2.128.11"))
	Expect(i.PodSubnetThisNode().Contains(second)).To(BeTrue(), "Pod IP address is not from pod network")

	err = i.ReleasePodIP(podID[1])
	Expect(err).To(BeNil())

	// check that second is not reused
	third, err := i.AllocatePodIP(podID[2], "", "")
	Expect(err).To(BeNil())
	Expect(third).NotTo(BeNil())
	Expect(third.String()).To(BeEquivalentTo("1.2.128.12"))
	Expect(i.PodSubnetThisNode().Contains(third)).To(BeTrue(), "Pod IP address is not from pod network")

	// exhaust the range
	assigned, err := i.AllocatePodIP(podID[3], "", "")
	Expect(err).To(BeNil())
	Expect(assigned).NotTo(BeNil())
	Expect(i.PodSubnetThisNode().Contains(assigned)).To(BeTrue(), "Pod IP address is not from pod network")

	// expect released ip to be reused
	reused, err := i.AllocatePodIP(podID[1], "", "")
	Expect(err).To(BeNil())
	Expect(reused).NotTo(BeNil())
	Expect(i.PodSubnetThisNode().Contains(reused)).To(BeTrue(), "Pod IP address is not from pod network")
	Expect(reused.String()).To(BeEquivalentTo("1.2.128.11"))

}

// TestDistinctAllocations test whether all pod IP addresses are distinct to each other until exhaustion of the whole IP address pool
func TestDistinctAllocations(t *testing.T) {
	i := setup(t, newDefaultConfig())
	assertAllocationOfAllIPAddresses(i, 4, expectedPodSubnetThisNode)
	assertCorrectIPExhaustion(i, 4)
}

// TestReleaseOfAllIPAddresses tests proper releasing of pod IP addresses by allocating them again. If any pod IP
// address is not properly released then additional allocation of all pod IP addresses will fail (either
// ipam.AllocatePodIP(...) will fail by providing all ip addresses or one ip addresses will be allocated twice)
func TestReleaseOfAllIPAddresses(t *testing.T) {
	i := setup(t, newDefaultConfig())
	exhaustPodIPAddresses(i, 4)
	releaseAllPodAddresses(i, 4)
	assertAllocationOfAllIPAddresses(i, 4, expectedPodSubnetThisNode)
}

// TestReleaseOfSomeIPAddresses is variation of TestReleaseOfAllIPAddresses test. Releasing of all pod IP addresses and
// allocating them again is special case and IPAM can handle it differently. Distinct case (not so special) is to release
// only portion of pod IP addresses and assert their reallocation.
func TestReleaseOfSomeIPAddresses(t *testing.T) {
	i := setup(t, newDefaultConfig())
	addresses, podids := exhaustPodIPAddresses(i, 4)
	releaseSomePodAddresses(i, podids[2:])
	assertAllocationOfIPAddresses(i, addresses[2:], expectedPodSubnetThisNode)
	assertCorrectIPExhaustion(i, 4)
}

// Test8bitPodIPPoolSize tests pod IP allocation for nice-looking distinct case when subnet/network is aligned to IP Address bytes
func Test8bitPodIPPoolSize(t *testing.T) {
	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.2.3.4/16"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 24
	i := setup(t, customConfig)

	podNetwork := network("1.2." + str(int(nodeID1)) + ".0/24")
	maxIPCount := 256 - 4 // 2 IPs are reserved, 2 are not unicast

	assertAllocationOfAllIPAddresses(i, maxIPCount, podNetwork)
	assertCorrectIPExhaustion(i, maxIPCount)
}

// TestBiggerThan8bitPodIPPoolSize tests pod IP allocation for more than 256 IP Addresses (mare then 8-bit allocated for IP addresses)
func TestBiggerThan8bitPodIPPoolSize(t *testing.T) {
	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.4.1.2/14"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 22
	i := setup(t, customConfig)

	b00000100 := 1 << 2
	podNetwork := network("1." + str(b00000100+int(nodeID1>>6)) + "." + str(int(nodeID1<<2)) + ".0/22")
	maxIPCount := 256*4 - 4 // 2 IPs are reserved, 2 are not unicast

	assertAllocationOfAllIPAddresses(i, maxIPCount, podNetwork)
	assertCorrectIPExhaustion(i, maxIPCount)
}

// TestPodSubnetThisNodeSubnets verifies that the pod subnet corresponding to the last valid nodeID uses the first valid pod subnet
func TestPodSubnetThisNodeSubnets(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.4.1.0/24"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 28

	var firstID uint32 = 1
	var lastID uint32 = 16
	var outOfRangeID uint32 = 17

	first, err := newIPAM(customConfig, firstID)
	Expect(err).To(BeNil())
	Expect(first).NotTo(BeNil())
	Expect(first.PodSubnetThisNode().String()).To(BeEquivalentTo("1.4.1.16/28"))
	firstNodeIP, _, err := first.NodeIPAddress(firstID)
	Expect(err).To(BeNil())
	Expect(firstNodeIP.String()).To(BeEquivalentTo("3.4.5.193"))

	// the biggest NodeID uses the podNetwork zero-ending
	last, err := newIPAM(customConfig, 16)
	Expect(err).To(BeNil())
	Expect(last).NotTo(BeNil())
	Expect(last.PodSubnetThisNode().String()).To(BeEquivalentTo("1.4.1.0/28"))
	lastNodeIP, _, err := last.NodeIPAddress(lastID)
	Expect(err).To(BeNil())
	Expect(lastNodeIP.String()).To(BeEquivalentTo("3.4.5.208"))

	outOfRange, err := newIPAM(customConfig, outOfRangeID)
	Expect(err).NotTo(BeNil())
	Expect(outOfRange).To(BeNil())
}

// TestMoreThan256Node verifies that IPAM support nodeID that is bigger than 8-bit value
func TestMoreThan256Node(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.4.0.0/17"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 28
	customConfig.IPAMConfig.VxlanCIDR = "2.2.128.0/17"
	customConfig.IPAMConfig.NodeInterconnectCIDR = "1.1.128.0/17"

	last, err := newIPAM(customConfig, 257)
	Expect(err).To(BeNil())
	Expect(last).NotTo(BeNil())

	fmt.Println(last.PodSubnetThisNode().String())

	nodeIP, _, err := last.NodeIPAddress(257)
	fmt.Println(nodeIP)
	Expect(err).To(BeNil())

	vxlanIP, _, err := last.VxlanIPAddress(257)
	fmt.Println(vxlanIP)
	Expect(err).To(BeNil())

}

// TestExceededVxlanRange tests the scenario where vxlan IP range is exceeded, whereas the pod subnet is valid for the given nodeID
func TestExceededVxlanRange(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.4.1.0/17"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 28
	customConfig.IPAMConfig.VxlanCIDR = "2.2.2.128/28"

	// valid nodID from pod subnet perspective, however it doesn't fit into vxlan range
	last, err := newIPAM(customConfig, 17)
	Expect(err).To(BeNil())
	Expect(last).NotTo(BeNil())

	_, _, err = last.VxlanIPAddress(16)
	fmt.Println(err)
	Expect(err).NotTo(BeNil())

	_, _, err = last.VxlanIPAddress(17)
	fmt.Println(err)
	Expect(err).NotTo(BeNil())

}

// TestExceededVxlanRange tests the scenario where node IP range is exceeded, whereas the pod subnet is valid for the given nodeID
func TestExceededNodeIPRange(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.4.1.0/17"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 28
	customConfig.IPAMConfig.VxlanCIDR = "2.2.2.128/25"
	customConfig.IPAMConfig.NodeInterconnectCIDR = "3.3.3.0/28"

	// valid nodID from pod subnet perspective, however it doesn't fit into nodeIP range
	last, err := newIPAM(customConfig, 17)
	Expect(err).To(BeNil())
	Expect(last).NotTo(BeNil())

	_, _, err = last.NodeIPAddress(16)
	fmt.Println(err)
	Expect(err).NotTo(BeNil())

	_, _, err = last.NodeIPAddress(17)
	fmt.Println(err)
	Expect(err).NotTo(BeNil())

}

func TestNodeCIDRIPv6(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.NodeInterconnectCIDR = "fe10:f00d::/90"

	i, err := newIPAM(customConfig, 1)
	Expect(err).To(BeNil())
	Expect(i).NotTo(BeNil())

	ip, net, err := i.NodeIPAddress(1)

	Expect(err).To(BeNil())
	Expect(ip.String()).To(BeEquivalentTo("fe10:f00d::1"))
	Expect(net.String()).To(BeEquivalentTo("fe10:f00d::/90"))

}

// TestConfigWithBadCIDR test if IPAM detects incorrect unparsable CIDR string and handles it correctly (initialization returns error)
func TestConfigWithBadCIDR(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.2.3./19"
	_, err := newIPAM(customConfig, nodeID1)
	Expect(err).NotTo(BeNil(), "Pod subnet CIDR is unparsable, but IPAM initialization didn't fail")

	customConfig = newDefaultConfig()
	customConfig.IPAMConfig.VPPHostSubnetCIDR = "1.2.3./19"
	_, err = newIPAM(customConfig, nodeID1)
	Expect(err).NotTo(BeNil(), "VSwitch subnet CIDR is unparsable, but IPAM initialization didn't fail")

	customConfig = newDefaultConfig()
	customConfig.IPAMConfig.NodeInterconnectCIDR = "1.2.3./19"
	_, err = newIPAM(customConfig, nodeID1)
	Expect(err).NotTo(BeNil(), "Host subnet CIDR is unparsable, but IPAM initialization didn't fail")
}

// TestConfigWithBadPrefixSizes tests if IPAM detects incorrect prefix length of subnet and network
func TestConfigWithBadPrefixSizes(t *testing.T) {
	RegisterTestingT(t)

	customConfig := newDefaultConfig()
	customConfig.IPAMConfig.PodSubnetCIDR = "1.2.3.4/19"
	customConfig.IPAMConfig.PodSubnetOneNodePrefixLen = 18
	_, err := newIPAM(customConfig, nodeID1)
	Expect(err).NotTo(BeNil())

	customConfig = newDefaultConfig()
	customConfig.IPAMConfig.VPPHostSubnetCIDR = "1.2.3.4/19"
	customConfig.IPAMConfig.VPPHostSubnetOneNodePrefixLen = 18
	_, err = newIPAM(customConfig, nodeID1)
	Expect(err).NotTo(BeNil())
}

func TestExcludeGateway(t *testing.T) {
	RegisterTestingT(t)

	// nodeInterconnect is configure to 3.4.5.192/26

	gw := net.IPv4(3, 4, 5, 194).To4()

	excluded := []net.IP{gw}
	customConfig := newDefaultConfig()
	customConfig.NodeConfig = append(customConfig.NodeConfig, contivconf.NodeConfig{
		NodeName: nodeName,
		NodeConfigSpec: nodeconfigcrd.NodeConfigSpec{
			Gateway: gw.String(),
		},
	})
	ipam, err := newIPAM(customConfig, nodeID1)
	Expect(err).To(BeNil())

	first, _, err := ipam.NodeIPAddress(1)
	Expect(err).To(BeNil())

	second, _, err := ipam.NodeIPAddress(2)
	Expect(err).To(BeNil())

	third, _, err := ipam.NodeIPAddress(3)
	Expect(err).To(BeNil())

	fmt.Println(first, second, third)

	Expect(excluded).NotTo(ContainElement(first))
	Expect(excluded).NotTo(ContainElement(second))
	Expect(excluded).NotTo(ContainElement(third))

}

func exhaustPodIPAddresses(i *IPAM, maxIPCount int) (allocatedIPs []string, allocatedPodIDS []podmodel.ID) {
	for j := 1; j <= maxIPCount; j++ {
		podID := podmodel.ID{Namespace: "default", Name: "pod" + strconv.Itoa(j)}
		ip, _ := i.AllocatePodIP(podID, "", "")
		allocatedIPs = append(allocatedIPs, ip.To4().String())
		allocatedPodIDS = append(allocatedPodIDS, podID)
	}
	return
}

func releaseSomePodAddresses(i *IPAM, toRelease []podmodel.ID) {
	for _, nodeID := range toRelease {
		i.ReleasePodIP(nodeID)
	}
}

func releaseAllPodAddresses(i *IPAM, ipCount int) {
	for j := 1; j <= ipCount; j++ {
		podID := podmodel.ID{Namespace: "default", Name: "pod" + strconv.Itoa(j)}
		i.ReleasePodIP(podID)
	}
}

func assertCorrectIPExhaustion(i *IPAM, maxIPCount int) {
	podID := podmodel.ID{Namespace: "default", Name: "pod" + strconv.Itoa(maxIPCount+1)}
	_, err := i.AllocatePodIP(podID, "", "")
	Expect(err).NotTo(BeNil(), "Pool of free IP addresses should be empty, but IPAM allocation function didn't fail")
}

func assertAllocationOfIPAddresses(i *IPAM, expectedIPs []string, network net.IPNet) {
	freeIPsCount := len(expectedIPs)
	for j := 1; j <= freeIPsCount; j++ {
		podID := podmodel.ID{Namespace: "default", Name: "pod" + strconv.Itoa(j) + "-secondAllocation"}
		ip, err := i.AllocatePodIP(podID, "", "")
		Expect(err).To(BeNil(), "Can't successfully allocate %v. IP address", j)
		assertAllocationOfIPAddress(ip, network)
		Expect(expectedIPs).To(ContainElement(ip.String()), "Allocated IP is not from given IP slice")
	}
}

func assertAllocationOfAllIPAddresses(i *IPAM, maxIPCount int, network net.IPNet) {
	allocated := make(map[string]bool, maxIPCount)
	for j := 1; j <= maxIPCount; j++ {
		podID := podmodel.ID{Namespace: "default", Name: "pod" + strconv.Itoa(j)}
		ip, err := i.AllocatePodIP(podID, "", "")
		Expect(err).To(BeNil(), "Can't successfully allocate %v. IP address out of %v possible IP addresses", j, maxIPCount)
		Expect(allocated[ip.String()]).To(BeFalse(), "IP address %v is allocated second time", ip)
		assertAllocationOfIPAddress(ip, network)
		allocated[ip.String()] = true
	}
}

func assertAllocationOfIPAddress(ip net.IP, network net.IPNet) {
	Expect(network.Contains(ip)).To(BeTrue(), fmt.Sprintf("Allocated IP %v is not in range of network %v.", ip, network))
	Expect(ip).NotTo(BeEquivalentTo(expectedPodSubnetThisNodeZeroEndingIP), "Network IP address (range part filled with zeroes) should not be assignable pod IP address")
	Expect(ip).NotTo(BeEquivalentTo(expectedPodSubnetThisNodeGatewayIP), "GateWay IP should not be assignable pod IP address")
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
