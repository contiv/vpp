package main

import (
	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/acl"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/nat"
)

/*****************************************************
 * After Resync (apart from Contiv config)           *
 *                                                   *
 *  +---------------------------------------------+  *
 *  |                                             |  *
 *  +-----------+           +---------------------+  *
 *  | tap1      |           |  memif1             |  *
 *  | DISABLED  |      +--> |  MASTER             |  *
 *  +-----------+      |    |  IP: 192.168.1.1/24 |  *
 *  |                  |    +---------------------+  *
 *  |  +-----------+   |                          |  *
 *  |  | loopback1 |   +                          |  *
 *  |  +-----------+   route for 192.168.2.1      |  *
 *  |                                             |  *
 *  +---------------------------------------------+  *
 *                                                   *
 *****************************************************/

/********************************************************
 * After Data Change Request (apart from Contiv config) *
 *                                                      *
 *  +------------------------------------------------+  *
 *  |                                                |  *
 *  +---------+ +------+                  +----------+  *
 *  | tap1    |-| acl1 |-+         +------| memif1   |  *
 *  | ENABLED | +------+ |         |      | SLAVE    |  *
 *  | nat-out |          |         |      +----------+  *
 *  +---------+        Bridge   xconnect             |  *
 *  |                  domain      |      +----------+  *
 *  |                    |         |      | memif2   |  *
 *  |  +------------+    |         +------| SLAVE    |  *
 *  |  | loopback1  |----+                +----------|  *
 *  |  +------------+                                |  *
 *  |                                                |  *
 *  +------------------------------------------------+  *
 *                                                      *
 ********************************************************/

var (
	// memif1AsMaster is an example of a memory interface configuration. (Master=true, with IPv4 address).
	memif1AsMaster = vpp_interfaces.Interface{
		Name:    "memif1",
		Type:    vpp_interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Memif{
			Memif: &vpp_interfaces.MemifLink{
				Id:             1,
				Master:         true,
				SocketFilename: "/tmp/memif1.sock",
			},
		},
		Mtu:         1500,
		IpAddresses: []string{"192.168.1.1/24"},
	}

	// memif1AsSlave is the original memif1 turned into slave and stripped of the IP address.
	memif1AsSlave = vpp_interfaces.Interface{
		Name:    "memif1",
		Type:    vpp_interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Memif{
			Memif: &vpp_interfaces.MemifLink{
				Id:             1,
				Master:         false,
				SocketFilename: "/tmp/memif1.sock",
			},
		},
		Mtu: 1500,
	}

	// Memif2 is a slave memif without IP address and to be xconnected with memif1.
	memif2 = vpp_interfaces.Interface{
		Name:    "memif2",
		Type:    vpp_interfaces.Interface_MEMIF,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Memif{
			Memif: &vpp_interfaces.MemifLink{
				Id:             2,
				Master:         false,
				SocketFilename: "/tmp/memif2.sock",
			},
		},
		Mtu: 1500,
	}
	// XConMemif1ToMemif2 defines xconnect between memifs.
	XConMemif1ToMemif2 = vpp_l2.XConnectPair{
		ReceiveInterface:  memif1AsSlave.GetName(),
		TransmitInterface: memif2.GetName(),
	}

	// tap1Disabled is a disabled tap interface.
	tap1Disabled = vpp_interfaces.Interface{
		Name:    "tap1",
		Type:    vpp_interfaces.Interface_TAP,
		Enabled: false,
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{
				Version: 1,
			},
		},
		Mtu: 1500,
	}

	// tap1Enabled is an enabled tap1 interface.
	tap1Enabled = vpp_interfaces.Interface{
		Name:    "tap1",
		Type:    vpp_interfaces.Interface_TAP,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Tap{
			Tap: &vpp_interfaces.TapLink{
				Version: 1,
			},
		},
		Mtu: 1500,
	}

	tap1LinuxSide = linux_interfaces.Interface{
		Name:       "linux-tap1",
		Type:       linux_interfaces.Interface_TAP_TO_VPP,
		Enabled:    true,
		HostIfName: "tap-to-vpp",
		Link: &linux_interfaces.Interface_Tap{
			Tap: &linux_interfaces.TapLink{
				VppTapIfName: tap1Enabled.GetName(),
			},
		},
		Mtu: 1500,
	}

	acl1 = vpp_acl.ACL{
		Name: "acl1",
		Rules: []*vpp_acl.ACL_Rule{
			{
				Action: vpp_acl.ACL_Rule_DENY,
				IpRule: &vpp_acl.ACL_Rule_IpRule{
					Ip: &vpp_acl.ACL_Rule_IpRule_Ip{
						DestinationNetwork: "10.1.1.0/24",
						SourceNetwork:      "10.1.2.0/24",
					},
					Tcp: &vpp_acl.ACL_Rule_IpRule_Tcp{
						DestinationPortRange: &vpp_acl.ACL_Rule_IpRule_PortRange{
							LowerPort: 50,
							UpperPort: 150,
						},
						SourcePortRange: &vpp_acl.ACL_Rule_IpRule_PortRange{
							LowerPort: 1000,
							UpperPort: 2000,
						},
					},
				},
			},
		},
		Interfaces: &vpp_acl.ACL_Interfaces{
			Egress: []string{tap1Enabled.GetName()},
		},
	}

	// loopback1 is an example of a loopback interface configuration (without IP address assigned).
	loopback1 = vpp_interfaces.Interface{
		Name:    "loopback1",
		Type:    vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled: true,
		Mtu:     1500,
	}

	// loopback1WithAddr extends loopback1 definition with an IP address.
	loopback1WithAddr = vpp_interfaces.Interface{
		Name:        "loopback1",
		Type:        vpp_interfaces.Interface_SOFTWARE_LOOPBACK,
		Enabled:     true,
		Mtu:         1500,
		IpAddresses: []string{"10.0.0.1/24"},
	}

	// BDLoopback1ToTap1 is a bridge domain with tap1 and loopback1 interfaces in it.
	// Loopback is set to be BVI.
	BDLoopback1ToTap1 = vpp_l2.BridgeDomain{
		Name:                "br1",
		Flood:               false,
		UnknownUnicastFlood: false,
		Forward:             true,
		Learn:               true,
		ArpTermination:      false,
		MacAge:              0, /* means disable aging */
		Interfaces: []*vpp_l2.BridgeDomain_Interface{
			{
				Name:                    loopback1.GetName(),
				BridgedVirtualInterface: true,
			}, {
				Name:                    tap1Enabled.GetName(),
				BridgedVirtualInterface: false,
			},
		},
	}

	// this gets merged with the Contiv's NAT global configuration
	natGlobal = vpp_nat.Nat44Global{
		NatInterfaces: []*vpp_nat.Nat44Global_Interface{
			{
				Name:     tap1Enabled.GetName(),
				IsInside: false,
			},
		},
	}

	// routeThroughMemif1 is an example route configuration, with memif1 being the next hop.
	routeThroughMemif1 = vpp_l3.Route{
		VrfId:       0,
		DstNetwork:  "192.168.2.1/32",
		NextHopAddr: "192.168.1.1", // Memif1AsMaster
		Weight:      5,
	}
)
