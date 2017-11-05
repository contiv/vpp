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
TODO test bad config values
TODO test host ip part to be < 8-bits (check if host id trimming is working)
TODO hostipaddress/hostipnetwork functions
TODO pod ip allocating and releasing:
	-basic happy path (1 allocated, 1 released->no errors and expected values ranges)
    -allocation all ip addresses just once(no ip address allocated twice) and then exhaustion
	-exhaust(no check) -> release all(no error check) -> exhaust again(no ip address allocated twice check) (checking proper releasing of all ip addresses)
	-exhaust(no check) -> release half of ip address(no error check) -> exhaust again (check collision with 1-phase allocated ip addresses) (checking proper releasing of only those addresses that we want to release)
	-check <8-bit,=8-bit,>8-bit pool allocation
TODO check multiple hosts IPAMs for no interconnection between them and that hostID is not hardwired into them somehow
*/

const (
	b10000000 = 1 << 7
	b11000000 = 1<<7 + 1<<6
	b11000010 = 1<<7 + 1<<6 + 1<<1
	b10100001 = 1<<7 + 1<<5 + 1
)

var (
	hostID uint8 = b10100001
	config       = ipam.Config{
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

	i, err := ipam.New(logroot.StandardLogger(), uint8(hostID), &config)
	logroot.StandardLogger().Info("1.2." + str(b11000000) + ".0/16")
	Expect(err).To(BeNil())
	Expect(i.HostID()).To(BeEquivalentTo(hostID))

	// pods addresses IPAM API
	Expect(*i.PodSubnet()).To(BeEquivalentTo(network("1.2." + str(b10000000) + ".0/17")))
	expectedPodNetwork := network("1.2." + str(b10000000+int(hostID>>5)) + "." + str(int(hostID<<3)) + "/29")
	Expect(*i.PodNetwork()).To(BeEquivalentTo(expectedPodNetwork))
	Expect(expectedPodNetwork.Contains(i.PodGatewayIP())).To(BeTrue(), "Pod Gateway IP is not in range of network for pods for given host.")

	// vSwitch addresses IPAM API
	expectedVSwitchNetwork := network("2.3." + str(b11000000+int(hostID>>6)) + "." + str(int(hostID<<2)) + "/30")
	Expect(*i.VSwitchNetwork()).To(BeEquivalentTo(expectedVSwitchNetwork))
	Expect(expectedVSwitchNetwork.Contains(i.VEthHostEndIP())).To(BeTrue(), "VEthHostEndIP is not in range of vSwitch network for given host.")
	Expect(expectedVSwitchNetwork.Contains(i.VEthVPPEndIP())).To(BeTrue(), "VEthVPPEndIP is not in range of vSwitch network for given host.")
}

func network(networkCIDR string) net.IPNet {
	_, result, err := net.ParseCIDR(networkCIDR)
	Expect(err).To(BeNil())
	return *result
}

func str(i int) string {
	return strconv.Itoa(i)
}
