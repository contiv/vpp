package cache

import (
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
)

type validatorTestVars struct {
	log   *logrus.Logger
	cache *ContivTelemetryCache

	// Mock data
	nodesData []nodeData
}

type nodeData struct {
	ID       uint32
	nodeName string
	IPAdr    string
	ManIPAdr string

	liveness   *NodeLiveness
	interfaces nodeInterfaces
	bds        nodeBridgeDomains
	l2FibTable nodeL2FibTable
	arpTable   nodeIPArpTable
}

var vtv validatorTestVars

func TestValidator(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	vtv.log = logrus.DefaultLogger()
	vtv.log.SetLevel(logging.ErrorLevel)

	vtv.initTestData()

	// Initialize the cache
	vtv.cache = &ContivTelemetryCache{
		Deps: Deps{
			Log: vtv.log,
		},
		Synced: false,
	}
	vtv.cache.Init()

	// Populate cache data
	for _, node := range vtv.nodesData {
		vtv.cache.AddNode(node.ID, node.nodeName, node.IPAdr, node.ManIPAdr)
		vtv.cache.Cache.SetNodeLiveness(node.nodeName, node.liveness)
		vtv.cache.Cache.SetNodeInterfaces(node.nodeName, node.interfaces)
		vtv.cache.Cache.SetNodeBridgeDomain(node.nodeName, node.bds)
		vtv.cache.Cache.SetNodeL2Fibs(node.nodeName, node.l2FibTable)
		vtv.cache.Cache.SetNodeIPARPs(node.nodeName, node.arpTable)
	}
}

func (v *validatorTestVars) initTestData() {
	v.nodesData = []nodeData{}

	// Initialize k8s-master
	k8sMaster := nodeData{
		ID:       3,
		nodeName: "k8s-master",
		IPAdr:    "192.168.16.3/24",
		ManIPAdr: "10.20.0.2",

		liveness: &NodeLiveness{
			BuildVersion: "v1.2-alpha-179-g4e2d712",
			BuildDate:    "2018-07-19T09:54+00:00",
			State:        1,
			StartTime:    1532891958,
			LastChange:   1532891971,
			LastUpdate:   1532997235,
			CommitHash:   "v1.2-alpha-179-g4e2d712",
		},
		interfaces: nodeInterfaces{
			0: {
				VppInternalName: "local0",
				Name:            "local0",
			},
			1: {
				VppInternalName: "GigabitEthernet0/8",
				Name:            "GigabitEthernet0/8",
				IfType:          1,
				Enabled:         true,
				PhysAddress:     "08:00:27:c1:dd:42",
				Mtu:             9202,
				IPAddresses:     []string{"192.168.16.3/24"},
			},
			2: {
				VppInternalName: "tap0",
				Name:            "tap-vpp2",
				IfType:          3,
				Enabled:         true,
				PhysAddress:     "01:23:45:67:89:42",
				Mtu:             1500,
				IPAddresses:     []string{"172.30.3.1/24"},
				Tap:             tap{Version: 2},
			},
			3: {
				VppInternalName: "tap1",
				Name:            "tap3aa4d77d27d0bf3",
				IfType:          3,
				Enabled:         true,
				PhysAddress:     "02:fe:fc:07:21:82",
				Mtu:             1500,
				IPAddresses:     []string{"10.2.1.7/32"},
				Tap:             tap{Version: 2},
			},
			4: {
				VppInternalName: "loop0",
				Name:            "vxlanBVI",
				Enabled:         true,
				PhysAddress:     "1a:2b:3c:4d:5e:03",
				Mtu:             1500,
				IPAddresses:     []string{"192.168.30.3/24"},
			},
			5: {
				VppInternalName: "vxlan_tunnel0",
				Name:            "vxlan1",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.3",
					DstAddress: "192.168.16.1",
					Vni:        10,
				},
			},
			6: {
				VppInternalName: "vxlan_tunnel1",
				Name:            "vxlan2",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.3",
					DstAddress: "192.168.16.2",
					Vni:        10,
				},
			},
		},
		bds: nodeBridgeDomains{
			1: {
				Name:       "vxlanBD",
				Forward:    true,
				Interfaces: []bdinterfaces{},
			},
			2: {
				Name:    "vxlanBD",
				Forward: true,
				Interfaces: []bdinterfaces{
					{SwIfIndex: 4},
					{SwIfIndex: 5},
					{SwIfIndex: 6},
				},
			},
		},
		l2FibTable: nodeL2FibTable{
			"1a:2b:3c:4d:5e:01": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 5,
				PhysAddress:              "1a:2b:3c:4d:5e:01",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:02": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 6,
				PhysAddress:              "1a:2b:3c:4d:5e:02",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:03": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 4,
				PhysAddress:              "1a:2b:3c:4d:5e:03",
				StaticConfig:             true,
				BridgedVirtualInterface:  true,
			},
		},
		arpTable: nodeIPArpTable{
			{
				Interface:  4,
				IPAddress:  "192.168.30.1",
				MacAddress: "1a:2b:3c:4d:5e:01",
				Static:     true,
			},
			{
				Interface:  4,
				IPAddress:  "192.168.30.2",
				MacAddress: "1a:2b:3c:4d:5e:02",
				Static:     true,
			},
			{
				Interface:  2,
				IPAddress:  "172.30.3.2",
				MacAddress: "96:ff:16:6e:60:6f",
				Static:     true,
			},
			{
				Interface:  3,
				IPAddress:  "10.1.3.7",
				MacAddress: "00:00:00:00:00:02",
				Static:     true,
			},
		},
	}
	v.nodesData = append(v.nodesData, k8sMaster)

	// Initialize k8s-worker1
	k8sWorker1 := nodeData{
		ID:       2,
		nodeName: "k8s-worker1",
		IPAdr:    "192.168.16.2/24",
		ManIPAdr: "10.20.0.10",

		liveness: &NodeLiveness{
			BuildVersion: "v1.2-alpha-179-g4e2d712",
			BuildDate:    "2018-07-19T09:54+00:00",
			State:        1,
			StartTime:    1532649516,
			LastChange:   1532649517,
			LastUpdate:   1533335002,
			CommitHash:   "v1.2-alpha-179-g4e2d712",
		},
		interfaces: nodeInterfaces{
			0: {
				VppInternalName: "local0",
			},
			1: {
				VppInternalName: "GigabitEthernet0/8",
				Name:            "GigabitEthernet0/8",
				IfType:          1,
				Enabled:         true,
				PhysAddress:     "08:00:27:11:e4:c4",
				Mtu:             9202,
				IPAddresses:     []string{"192.168.16.1/24"},
			},
			2: {
				VppInternalName: "tap0",
				Name:            "tap-vpp2",
				IfType:          3,
				Enabled:         true,
				PhysAddress:     "01:23:45:67:89:42",
				Mtu:             1500,
				IPAddresses:     []string{"172.30.1.1/24"},
				Tap:             tap{Version: 2},
			},
			3: {
				VppInternalName: "loop0",
				Name:            "vxlanBVI",
				Enabled:         true,
				PhysAddress:     "1a:2b:3c:4d:5e:01",
				Mtu:             1500,
				IPAddresses:     []string{"192.168.30.1/24"},
			},
			4: {
				VppInternalName: "vxlan_tunnel0",
				Name:            "vxlan1",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.2",
					DstAddress: "192.168.16.1",
					Vni:        10,
				},
			},
			5: {
				VppInternalName: "vxlan_tunnel1",
				Name:            "vxlan3",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.2",
					DstAddress: "192.168.16.3",
					Vni:        10,
				},
			},
		},
		bds: nodeBridgeDomains{
			1: {
				Name:       "vxlanBD",
				Forward:    true,
				Interfaces: []bdinterfaces{},
			},
			2: {
				Name:    "vxlanBD",
				Forward: true,
				Interfaces: []bdinterfaces{
					{SwIfIndex: 3},
					{SwIfIndex: 4},
					{SwIfIndex: 5},
				},
			},
		},
		l2FibTable: nodeL2FibTable{
			"1a:2b:3c:4d:5e:01": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 4,
				PhysAddress:              "1a:2b:3c:4d:5e:01",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:02": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 3,
				PhysAddress:              "1a:2b:3c:4d:5e:02",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:03": {
				BridgeDomainIdx:          2,
				OutgoingInterfaceSwIfIdx: 5,
				PhysAddress:              "1a:2b:3c:4d:5e:03",
				StaticConfig:             true,
				BridgedVirtualInterface:  true,
			},
		},
		arpTable: nodeIPArpTable{
			{
				Interface:  3,
				IPAddress:  "192.168.30.1",
				MacAddress: "1a:2b:3c:4d:5e:01",
				Static:     true,
			},
			{
				Interface:  3,
				IPAddress:  "192.168.30.3",
				MacAddress: "1a:2b:3c:4d:5e:03",
				Static:     true,
			},
		},
	}
	v.nodesData = append(v.nodesData, k8sWorker1)

	// Initialize k8s-worker2
	k8sWorker2 := nodeData{
		ID:       1,
		nodeName: "k8s-worker2",
		IPAdr:    "192.168.16.1/24",
		ManIPAdr: "10.20.0.11",

		liveness: &NodeLiveness{
			BuildVersion: "v1.2-alpha-179-g4e2d712",
			BuildDate:    "2018-07-19T09:54+00:00",
			State:        1,
			StartTime:    1532727081,
			LastChange:   1532727082,
			LastUpdate:   1533336124,
			CommitHash:   "v1.2-alpha-179-g4e2d712",
		},
		interfaces: nodeInterfaces{
			0: {
				VppInternalName: "local0",
			},
			1: {
				VppInternalName: "GigabitEthernet0/8",
				Name:            "GigabitEthernet0/8",
				IfType:          1,
				Enabled:         true,
				PhysAddress:     "08:00:27:1b:02:8c",
				Mtu:             9202,
				IPAddresses:     []string{"192.168.16.2/24"},
			},
			2: {
				VppInternalName: "tap0",
				Name:            "tap-vpp2",
				IfType:          3,
				Enabled:         true,
				PhysAddress:     "01:23:45:67:89:42",
				Mtu:             1500,
				IPAddresses:     []string{"172.30.3.1/24"},
				Tap:             tap{Version: 2},
			},
			3: {
				VppInternalName: "loop0",
				Name:            "vxlanBVI",
				Enabled:         true,
				PhysAddress:     "1a:2b:3c:4d:5e:02",
				Mtu:             1500,
				IPAddresses:     []string{"192.168.30.2/24"},
			},
			4: {
				VppInternalName: "vxlan_tunnel0",
				Name:            "vxlan2",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.1",
					DstAddress: "192.168.16.2",
					Vni:        10,
				},
			},
			5: {
				VppInternalName: "vxlan_tunnel1",
				Name:            "vxlan3",
				IfType:          5,
				Enabled:         true,
				Vxlan: vxlan{
					SrcAddress: "192.168.16.1",
					DstAddress: "192.168.16.3",
					Vni:        10,
				},
			},
		},
		bds: nodeBridgeDomains{
			1: {
				Name:    "vxlanBD",
				Forward: true,
				Interfaces: []bdinterfaces{
					{SwIfIndex: 3},
					{SwIfIndex: 4},
					{SwIfIndex: 5},
				},
			},
		},
		l2FibTable: nodeL2FibTable{
			"1a:2b:3c:4d:5e:01": {
				BridgeDomainIdx:          1,
				OutgoingInterfaceSwIfIdx: 3,
				PhysAddress:              "1a:2b:3c:4d:5e:01",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:02": {
				BridgeDomainIdx:          1,
				OutgoingInterfaceSwIfIdx: 4,
				PhysAddress:              "1a:2b:3c:4d:5e:02",
				StaticConfig:             true,
			},
			"1a:2b:3c:4d:5e:03": {
				BridgeDomainIdx:          1,
				OutgoingInterfaceSwIfIdx: 5,
				PhysAddress:              "1a:2b:3c:4d:5e:03",
				StaticConfig:             true,
				BridgedVirtualInterface:  true,
			},
		},
		arpTable: nodeIPArpTable{
			{
				Interface:  3,
				IPAddress:  "192.168.30.2",
				MacAddress: "1a:2b:3c:4d:5e:02",
				Static:     true,
			},
			{
				Interface:  3,
				IPAddress:  "192.168.30.3",
				MacAddress: "1a:2b:3c:4d:5e:03",
				Static:     true,
			},
		},
	}
	v.nodesData = append(v.nodesData, k8sWorker2)
}
