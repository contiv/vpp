// Package ipam_test is responsible for testing of IP addresses management
package ipam_test

import (
	"github.com/ligato/cn-infra/logging/logroot"
	. "github.com/onsi/gomega"
	"testing"

	"github.com/contiv/vpp/plugins/contiv/ipam"
	"net"
	"strconv"
)

/*
TODO extended tests for pod ip allocating and releasing:
    -allocation all ip addresses just once(no ip address allocated twice) and then exhaustion
	-exhaust(no check) -> release all(no error check) -> exhaust again(no ip address allocated twice check) (checking proper releasing of all ip addresses)
	-exhaust(no check) -> release half of ip address(no error check) -> exhaust again (check collision with 1-phase allocated ip addresses) (checking proper releasing of only those addresses that we want to release)
	-check <8-bit,=8-bit,>8-bit pool allocation
TODO test bad config values
TODO test host ip part to be < 8-bits (check if host id trimming is working)
TODO check multiple hosts IPAMs for no interconnection between them and that hostID is not hardwired into them somehow
*/

const (
	b10000000 = 1 << 7
	b11000000 = 1<<7 + 1<<6
	b11000010 = 1<<7 + 1<<6 + 1<<1
	b10100001 = 1<<7 + 1<<5 + 1
	b10100101 = 1<<7 + 1<<5 + 1<<2 + 1
	b11100101 = 1<<7 + 1<<6 + 1<<5 + 1<<2 + 1
)

var (
	hostID1 uint8 = b10100001
	hostID2 uint8 = b10100101

	podID = "podID"

	config = ipam.Config{
		PodSubnetCIDR:           "1.2." + str(b10000000) + ".2/17",
		PodNetworkPrefixLen:     29, // 3 bits left -> 6 free IP addresses (gateway IP + zero ending IP is reserved)
		VSwitchSubnetCIDR:       "2.3." + str(b11000000) + ".2/18",
		VSwitchNetworkPrefixLen: 30, // 2 bit left -> 3 free IP addresses (zero ending IP is reserved)
		HostNodeSubnetCidr:      "3.4.5." + str(b11000010) + "/26",
	}
)

// TestStaticGetters tests exposed IPAM API that provides data that doesn't change in time (and are not dynamically
// recomputed based on new input in form of API function parameters)
func TestStaticGetters(t *testing.T) {
	RegisterTestingT(t)

	i, err := ipam.New(logroot.StandardLogger(), uint8(hostID1), &config)
	Expect(err).To(BeNil())
	Expect(i.HostID()).To(BeEquivalentTo(hostID1))

	// pods addresses IPAM API
	Expect(*i.PodSubnet()).To(BeEquivalentTo(network("1.2." + str(b10000000) + ".0/17")))
	expectedPodNetwork := network("1.2." + str(b10000000+int(hostID1>>5)) + "." + str(int(hostID1<<3)) + "/29")
	Expect(*i.PodNetwork()).To(BeEquivalentTo(expectedPodNetwork))
	Expect(expectedPodNetwork.Contains(i.PodGatewayIP())).To(BeTrue(), "Pod Gateway IP is not in range of network for pods for given host.")

	// vSwitch addresses IPAM API
	expectedVSwitchNetwork := network("2.3." + str(b11000000+int(hostID1>>6)) + "." + str(int(hostID1<<2)) + "/30")
	Expect(*i.VSwitchNetwork()).To(BeEquivalentTo(expectedVSwitchNetwork))
	Expect(expectedVSwitchNetwork.Contains(i.VEthHostEndIP())).To(BeTrue(), "VEthHostEndIP is not in range of vSwitch network for given host.")
	Expect(expectedVSwitchNetwork.Contains(i.VEthVPPEndIP())).To(BeTrue(), "VEthVPPEndIP is not in range of vSwitch network for given host.")
}

// TestDynamicGetters tests proper working IMAP API that provides data based on new input (func parameters)
func TestDynamicGetters(t *testing.T) {
	RegisterTestingT(t)

	i, err := ipam.New(logroot.StandardLogger(), uint8(hostID1), &config)
	Expect(err).To(BeNil())

	ip, err := i.HostIPAddress(hostID2)
	Expect(err).To(BeNil())
	Expect(ip).To(BeEquivalentTo(net.IPv4(3, 4, 5, b11100101).To4()))

	ipNet, err := i.HostIPNetwork(hostID2)
	Expect(err).To(BeNil())
	Expect(*ipNet).To(BeEquivalentTo(ipWithNetworkMask("3.4.5." + str(b11100101) + "/26")))
}

// TestBasicAllocateReleasePodAddress test simple happy path scenario for getting 1 pod address and releasing it
func TestBasicAllocateReleasePodAddress(t *testing.T) {
	RegisterTestingT(t)

	i, err := ipam.New(logroot.StandardLogger(), uint8(hostID1), &config)
	Expect(err).To(BeNil())

	ip, err := i.NextPodIP(podID)
	Expect(err).To(BeNil())
	Expect(ip).NotTo(BeNil())
	Expect(i.PodNetwork().Contains(ip)).To(BeTrue(), "Pod IP address is not from pod network")

	err = i.ReleasePodIP(podID)
	Expect(err).To(BeNil())

}

func network(networkCIDR string) net.IPNet {
	_, result, err := net.ParseCIDR(networkCIDR)
	Expect(err).To(BeNil())
	return *result
}

func ipWithNetworkMask(ipWithMaskCIDR string) net.IPNet {
	ip, result, err := net.ParseCIDR(ipWithMaskCIDR)
	Expect(err).To(BeNil())
	result.IP = ip.To4()
	return *result
}

func str(i int) string {
	return strconv.Itoa(i)
}
