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
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

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
			}
		}
	}

	if nodeConfigProto == nil && localDB != nil {
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
