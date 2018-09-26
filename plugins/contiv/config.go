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

package contiv

import (
	"fmt"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"
	"math/big"
	"net"

	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/ksr"

	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	nodeconfigcrd "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
)

// Config represents configuration for the Contiv plugin.
// It can be injected or loaded from external config file. Injection has priority to external config. To use external
// config file, add `-contiv-config="<path to config>` argument when running the contiv-agent.
type Config struct {
	TCPChecksumOffloadDisabled  bool
	TCPstackDisabled            bool
	UseL2Interconnect           bool
	UseTAPInterfaces            bool
	TAPInterfaceVersion         uint8
	TAPv2RxRingSize             uint16
	TAPv2TxRingSize             uint16
	MTUSize                     uint32
	StealFirstNIC               bool
	StealInterface              string
	STNSocketFile               string
	NatExternalTraffic          bool   // if enabled, traffic with cluster-outside destination is SNATed on node output (for all nodes)
	CleanupIdleNATSessions      bool   // if enabled, the agent will periodically check for idle NAT sessions and delete inactive ones
	TCPNATSessionTimeout        uint32 // NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on
	OtherNATSessionTimeout      uint32 // NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on
	ScanIPNeighbors             bool   // if enabled, periodically scans and probes IP neighbors to maintain the ARP table
	IPNeighborScanInterval      uint8
	IPNeighborStaleThreshold    uint8
	MainVRFID                   uint32
	PodVRFID                    uint32
	ServiceLocalEndpointWeight  uint8
	DisableNATVirtualReassembly bool // if true, NAT plugin will drop fragmented packets
	IPAMConfig                  ipam.Config
	NodeConfig                  []NodeConfig
}

// NodeConfig represents configuration specific to a given node.
type NodeConfig struct {
	NodeName string // name of the node, should match with the hostname
	nodeconfigcrd.NodeConfigSpec
}

// KVBrokerFactory is used to generalize different means of accessing KV-store
// for the purpose of reading CRD-defined node configuration.
type KVBrokerFactory interface {
	NewBroker(keyPrefix string) keyval.ProtoBroker
}

// ApplyDefaults stores default values to undefined configuration fields.
func (cfg *Config) ApplyDefaults() {
	// use tap version 2 as default in case that TAPs are enabled
	if cfg.TAPInterfaceVersion == 0 {
		cfg.TAPInterfaceVersion = 2
	}

	// By default connections are equally distributed between service endpoints.
	if cfg.ServiceLocalEndpointWeight == 0 {
		cfg.ServiceLocalEndpointWeight = 1
	}
}

// ApplyDefaults populates the Config struct with the calculated subnets
func (cfg *Config) ApplyIPAMConfig() {
	// set default ContivCIDR if not defined by user
	if cfg.IPAMConfig.ContivCIDR == "" {
		cfg.IPAMConfig.ContivCIDR = "10.0.0.0/14"
	}
	_, contivNetwork, _ := net.ParseCIDR(cfg.IPAMConfig.ContivCIDR)
	maskSize, _ := contivNetwork.Mask.Size()
	subnetPrefixLength := 23 - maskSize

	// podSubnetCIDR has a requriement of minimum 65K pod ip addresses
	podSubnetCIDR, _ := subnet(contivNetwork, 2, 0)
	podNetworkPrefixLen := uint8(25)

	// vppHostSubnetCIDR has a requriement of minimum 65K pod ip addresses
	vppHostSubnetCIDR, _ := subnet(contivNetwork, 2, 1)
	vppHostNetworkPrefixLen := uint8(25)

	// use a /23 mask for the requirement of 500 nodes
	nodeInterconnectCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 256)
	podIfIPCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 257)
	vxlanCIDR, _ := subnet(contivNetwork, subnetPrefixLength, 258)

	cfg.IPAMConfig = ipam.Config{
		PodIfIPCIDR:             podIfIPCIDR.String(),
		PodSubnetCIDR:           podSubnetCIDR.String(),
		PodNetworkPrefixLen:     podNetworkPrefixLen,
		VPPHostSubnetCIDR:       vppHostSubnetCIDR.String(),
		VPPHostNetworkPrefixLen: vppHostNetworkPrefixLen,
		VxlanCIDR:               vxlanCIDR.String(),
	}

	if cfg.IPAMConfig.NodeInterconnectDHCP != true {
		cfg.IPAMConfig.NodeInterconnectCIDR = nodeInterconnectCIDR.String()
	}
}

// GetNodeConfig returns configuration specific to a given node, or nil if none was found.
func (cfg *Config) GetNodeConfig(nodeName string) *NodeConfig {
	for _, nodeConfig := range cfg.NodeConfig {
		if nodeConfig.NodeName == nodeName {
			return &nodeConfig
		}
	}
	return nil
}

// LoadNodeConfigFromCRD loads node configuration defined via CRD, which was reflected
// into a remote kv-store by contiv-crd and mirrored into local kv-store by the agent.
func LoadNodeConfigFromCRD(nodeName string, remoteDB, localDB KVBrokerFactory, log logging.Logger) *NodeConfig {
	var (
		nodeConfigProto *nodeconfig.NodeConfig
		err             error
	)
	// try remote kv-store first
	if remoteDB != nil {
		nodeConfigProto, err = loadNodeConfigFromKVStore(nodeName, remoteDB)
		if err != nil {
			log.WithField("err", err).Warn("Failed to read node configuration from remote KV-store")
		}
		if err == nil {
			// mirror the config into the local kv-store
			// TODO: remove once all kubernetes state data are reflected into local KV-store by the Aggregator
			boltBroker := localDB.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
			if nodeConfigProto != nil {
				err = boltBroker.Put(nodeconfig.Key(nodeName), nodeConfigProto)
			} else {
				_, err = boltBroker.Delete(nodeconfig.Key(nodeName))
			}
			if err != nil {
				log.WithField("err", err).Warn("Failed to mirror node configuration from remote to local KV-store")
				err = nil // ignore error
			}
		}
	}

	if (remoteDB == nil || err != nil) && localDB != nil {
		// try the local mirror of the kv-store
		nodeConfigProto, err = loadNodeConfigFromKVStore(nodeName, localDB)
		if err != nil {
			log.WithField("err", err).Warn("Failed to read node configuration from local KV-store")
		}
	}

	if nodeConfigProto == nil {
		log.Debug("Node configuration is not provided via CRD")
		return nil
	}

	nodeConfig := nodeConfigFromProto(nodeConfigProto)
	log.Debug("Node configuration loaded from CRD")
	return nodeConfig
}

// loadNodeConfigFromKVStore loads node configuration defined via CRD and mirrored into a given KV-store.
func loadNodeConfigFromKVStore(nodeName string, db KVBrokerFactory) (*nodeconfig.NodeConfig, error) {
	kvBroker := db.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
	nodeConfigProto := &nodeconfig.NodeConfig{}
	found, _, err := kvBroker.GetValue(nodeconfig.Key(nodeName), nodeConfigProto)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return nodeConfigProto, nil
}

// nodeConfigFromProto converts node configuration from protobuf to an instance of NodeConfig structure.
func nodeConfigFromProto(nodeConfigProto *nodeconfig.NodeConfig) (nodeConfig *NodeConfig) {
	nodeConfig = &NodeConfig{
		NodeName: nodeConfigProto.NodeName,
		NodeConfigSpec: nodeconfigcrd.NodeConfigSpec{
			StealInterface:     nodeConfigProto.StealInterface,
			Gateway:            nodeConfigProto.Gateway,
			NatExternalTraffic: nodeConfigProto.NatExternalTraffic,
		},
	}
	if nodeConfigProto.MainVppInterface != nil {
		nodeConfig.MainVPPInterface = nodeconfigcrd.InterfaceConfig{
			InterfaceName: nodeConfigProto.MainVppInterface.InterfaceName,
			IP:            nodeConfigProto.MainVppInterface.Ip,
			UseDHCP:       nodeConfigProto.MainVppInterface.UseDhcp,
		}
	}
	for _, otherVPPInterface := range nodeConfigProto.OtherVppInterfaces {
		nodeConfig.OtherVPPInterfaces = append(nodeConfig.OtherVPPInterfaces,
			nodeconfigcrd.InterfaceConfig{
				InterfaceName: otherVPPInterface.InterfaceName,
				IP:            otherVPPInterface.Ip,
				UseDHCP:       otherVPPInterface.UseDhcp,
			})
	}
	return nodeConfig
}

// subnet takes a CIDR range and creates a subnet from it
// base: parent CIDR range
// newBits: number of additional prefix bits
// num: given network number.
//
// Example: 10.1.0.0/16, with additional 8 bits and a network number of 5
// result = 10.1.5.0/24
func subnet(base *net.IPNet, newBits int, num int) (*net.IPNet, error) {
	ip := base.IP
	mask := base.Mask

	baseLength, addressLength := mask.Size()
	newPrefixLen := baseLength + newBits

	// check if there is sufficient address space to extend the network prefix
	if newPrefixLen > addressLength {
		return nil, fmt.Errorf("not enought space to extend prefix of %d by %d", baseLength, newBits)
	}

	// calculate the maximum network number
	maxNetNum := uint64(1<<uint64(newBits)) - 1
	if uint64(num) > maxNetNum {
		return nil, fmt.Errorf("prefix extension of %d does not accommodate a subnet numbered %d", newBits, num)
	}

	return &net.IPNet{
		IP:   insertNetworkNumIntoIP(ip, num, newPrefixLen),
		Mask: net.CIDRMask(newPrefixLen, addressLength),
	}, nil
}

// ipToInt is simple utility function for conversion between IPv4/IPv6 and int.
func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32
	} else if len(ip) == net.IPv6len {
		return val, 128
	} else {
		return nil, 0
	}
}

// intToIP is simple utility function for conversion between int and IPv4/IPv6.
func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	val := make([]byte, bits/8)

	// big.Int.Bytes() removes front zero padding.
	// IP bytes packed at the end of the return array,
	for i := 1; i <= len(ipBytes); i++ {
		val[len(val)-i] = ipBytes[len(ipBytes)-i]
	}

	return net.IP(val)
}

func insertNetworkNumIntoIP(ip net.IP, num int, prefixLen int) net.IP {
	ipInt, totalBits := ipToInt(ip)
	bigNum := big.NewInt(int64(num))
	bigNum.Lsh(bigNum, uint(totalBits-prefixLen))
	ipInt.Or(ipInt, bigNum)

	return intToIP(ipInt, totalBits)
}
