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

package cache

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging"
	"github.com/pkg/errors"
	"sort"
	"sync"
)

// here goes different cache types
//Update this whenever a new DTO type is added.
const numDTOs = 5

//VppCache holds various maps which all take different keys but point to the same underlying value.
type VppCache struct {
	lock       *sync.Mutex
	nMap       map[string]*telemetrymodel.Node
	loopIPMap  map[string]*telemetrymodel.Node
	gigEIPMap  map[string]*telemetrymodel.Node
	loopMACMap map[string]*telemetrymodel.Node
	hostIPMap  map[string]*telemetrymodel.Node
	logger     logging.Logger
}

func (vc *VppCache) logErrAndAppendToNodeReport(nodeName string, errString string) {
	vc.nMap[nodeName].Report = append(vc.nMap[nodeName].Report, errString)
	vc.logger.Errorf(errString)
}

// retrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vc *VppCache) retrieveNode(key string) (n *telemetrymodel.Node, err error) {
	if node, ok := vc.nMap[key]; ok {
		return node, nil
	}
	err = errors.Errorf("value with given key not found: %s", key)
	return nil, err
}

// CreateNode will add a node to the node cache with the given parameters,
// making sure there are no duplicates.
func (vc *VppCache) CreateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	n := &telemetrymodel.Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}

	n.PodMap = make(map[string]*telemetrymodel.Pod)
	_, err := vc.retrieveNode(nodeName)
	if err == nil {
		err = errors.Errorf("duplicate key found: %s", nodeName)
		vc.logErrAndAppendToNodeReport(nodeName, err.Error())
		return err
	}
	vc.nMap[nodeName] = n
	vc.gigEIPMap[IPAdr] = n
	vc.logger.Debugf("Success adding node %+vc to ctc.ContivTelemetryCache %+vc", nodeName, vc)
	return nil
}

// RetrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vc *VppCache) RetrieveNode(key string) (n *telemetrymodel.Node, err error) {
	vc.lock.Lock()
	defer vc.lock.Unlock()
	return vc.retrieveNode(key)
}

func (vc *VppCache) DeleteNode(key string) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(key)
	if err != nil {
		vc.logger.Error(err)
		return err
	}

	for _, intf := range node.NodeInterfaces {
		if intf.VppInternalName == "loop0" {
			delete(vc.loopMACMap, intf.PhysAddress)
			for _, ip := range intf.IPAddresses {
				delete(vc.loopIPMap, ip)
			}
		}

	}
	delete(vc.nMap, node.Name)
	delete(vc.gigEIPMap, node.IPAdr)
	return nil
}

//RetrieveAllNodes returns an ordered slice of all nodes in a database organized by name.
func (vc *VppCache) RetrieveAllNodes() []*telemetrymodel.Node {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	var str []string
	for k := range vc.nMap {
		str = append(str, k)
	}
	var nList []*telemetrymodel.Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := vc.retrieveNode(v)
		nList = append(nList, n)
	}
	return nList
}

func (vc *VppCache) UpdateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, ok := vc.nMap[nodeName]

	if !ok {
		return errors.Errorf("Node with name %+vc not found in vpp cache", nodeName)
	}
	node.IPAdr = IPAdr
	node.ID = ID
	node.ManIPAdr = ManIPAdr
	return nil
}

//ClearCache with clear all vpp cache data except for the base nMap that contains
// the discovered nodes..
func (vc *VppCache) ClearCache() {

	// Clear collected data for each node
	for _, node := range vc.nMap {
		node.NodeInterfaces = nil
		node.NodeBridgeDomains = nil
		node.NodeL2Fibs = nil
		node.NodeLiveness = nil
		node.NodeTelemetry = nil
		node.NodeIPArp = nil
		node.Report = []string{}
	}
	// Clear secondary index maps
	vc.gigEIPMap = make(map[string]*telemetrymodel.Node)
	vc.loopMACMap = make(map[string]*telemetrymodel.Node)
	vc.loopIPMap = make(map[string]*telemetrymodel.Node)
}

// ReinitializeCache completely re-initializes the cache, clearing all
// data including  the discovered nodes.
func (vc *VppCache) ReinitializeCache() {
	vc.ClearCache()
	vc.nMap = make(map[string]*telemetrymodel.Node)
}

//NewVppCache returns a pointer to a new node cache
func NewVppCache(logger logging.Logger) (n *VppCache) {
	return &VppCache{
		lock:       &sync.Mutex{},
		nMap:       make(map[string]*telemetrymodel.Node),
		loopIPMap:  make(map[string]*telemetrymodel.Node),
		gigEIPMap:  make(map[string]*telemetrymodel.Node),
		loopMACMap: make(map[string]*telemetrymodel.Node),
		hostIPMap:  make(map[string]*telemetrymodel.Node),
		logger:     logger,
	}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (vc *VppCache) SetNodeLiveness(name string, nLive *telemetrymodel.NodeLiveness) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	vc.logger.Debugf("Received Liveness %+vc for node %+vc", nLive, name)
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (vc *VppCache) SetNodeInterfaces(name string, nInt map[int]telemetrymodel.NodeInterface) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	vc.logger.Debugf("Received Interfaces %+vc for node %+vc", nInt, name)
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (vc *VppCache) SetNodeBridgeDomain(name string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	vc.logger.Debugf("Received Bridge domain %+vc for node %+vc", nBridge, name)
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (vc *VppCache) SetNodeL2Fibs(name string, nL2F map[string]telemetrymodel.NodeL2FibEntry) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	vc.logger.Debugf("Received L2Fibs %+vc for node %+vc", nL2F, name)
	node.NodeL2Fibs = nL2F
	return nil
}

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (vc *VppCache) SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	node.NodeTelemetry = nTele
	return nil
}

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (vc *VppCache) SetNodeIPARPs(name string, nArps []telemetrymodel.NodeIPArpEntry) error {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	node, err := vc.retrieveNode(name)
	if err != nil {
		return err
	}
	vc.logger.Debugf("Received IPARPS %+vc for node %+vc", nArps, name)
	node.NodeIPArp = nArps
	return nil

}

//Small helper function that returns the loop interface of a node
func (vc *VppCache) getNodeLoopIFInfo(node *telemetrymodel.Node) (telemetrymodel.NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.VppInternalName == "loop0" {
			return ifs, nil
		}
	}
	err := errors.Errorf("Node %s does not have a loop interface", node.Name)
	vc.logErrAndAppendToNodeReport(node.Name, err.Error())
	return telemetrymodel.NodeInterface{}, err
}
