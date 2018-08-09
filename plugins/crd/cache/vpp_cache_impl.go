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
)

// here goes different cache types
//Update this whenever a new DTO type is added.
const numDTOs = 5

//VppCache holds various maps which all take different keys but point to the same underlying value.
type VppCache struct {
	nMap       map[string]*telemetrymodel.Node
	loopIPMap  map[string]*telemetrymodel.Node
	gigEIPMap  map[string]*telemetrymodel.Node
	loopMACMap map[string]*telemetrymodel.Node
	hostIPMap  map[string]*telemetrymodel.Node
	logger     logging.Logger
}

func (c *VppCache) logErrAndAppendToNodeReport(nodeName string, errString string) {
	c.nMap[nodeName].Report = append(c.nMap[nodeName].Report, errString)
	c.logger.Errorf(errString)
}

//addNode will add a node to the node cache with the given parameters, making sure there are no duplicates.
func (c *VppCache) addNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	n := &telemetrymodel.Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}

	n.PodMap = make(map[string]*telemetrymodel.Pod)
	_, err := c.RetrieveNode(nodeName)
	if err == nil {
		err = errors.Errorf("duplicate key found: %s", nodeName)
		c.logErrAndAppendToNodeReport(nodeName, err.Error())
		return err
	}
	c.nMap[nodeName] = n
	c.gigEIPMap[IPAdr] = n
	c.logger.Debugf("Success adding node %+v to ctc.ContivTelemetryCache %+v", nodeName, c)
	return nil
}

//ClearCache with clear all cache data except for the base nMap that contains
// the discovered nodes..
func (ctc *ContivTelemetryCache) ClearCache() {
	// Clear collected data for each node
	for _, node := range ctc.VppCache.nMap {
		node.NodeInterfaces = nil
		node.NodeBridgeDomains = nil
		node.NodeL2Fibs = nil
		node.NodeLiveness = nil
		node.NodeTelemetry = nil
		node.NodeIPArp = nil
	}
	// Clear secondary index maps
	ctc.VppCache.gigEIPMap = make(map[string]*telemetrymodel.Node)
	ctc.VppCache.loopMACMap = make(map[string]*telemetrymodel.Node)
	ctc.VppCache.loopIPMap = make(map[string]*telemetrymodel.Node)

}

// ReinitializeCache completely re-initializes the cache, clearing all
// data including  the discovered nodes.
func (ctc *ContivTelemetryCache) ReinitializeCache() {
	ctc.ClearCache()
	ctc.VppCache.nMap = make(map[string]*telemetrymodel.Node)
}

//NewVppCache returns a pointer to a new node cache
func NewVppCache(logger logging.Logger) (n *VppCache) {
	return &VppCache{
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		logger,

	}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (c *VppCache) SetNodeLiveness(name string, nLive *telemetrymodel.NodeLiveness) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Liveness %+v for node %+v", nLive, name)
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (c *VppCache) SetNodeInterfaces(name string, nInt map[int]telemetrymodel.NodeInterface) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Interfaces %+v for node %+v", nInt, name)
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (c *VppCache) SetNodeBridgeDomain(name string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Bridge domain %+v for node %+v", nBridge, name)
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (c *VppCache) SetNodeL2Fibs(name string, nL2F map[string]telemetrymodel.NodeL2FibEntry) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received L2Fibs %+v for node %+v", nL2F, name)
	node.NodeL2Fibs = nL2F
	return nil
}

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (c *VppCache) SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	node.NodeTelemetry = nTele
	return nil
}

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (c *VppCache) SetNodeIPARPs(name string, nArps []telemetrymodel.NodeIPArpEntry) error {
	node, err := c.RetrieveNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received IPARPS %+v for node %+v", nArps, name)
	node.NodeIPArp = nArps
	return nil

}

//RetrieveNode returns a pointer to a node for the given key.
//Returns an error if that key is not found.
func (c *VppCache) RetrieveNode(key string) (n *telemetrymodel.Node, err error) {
	if node, ok := c.nMap[key]; ok {
		return node, nil
	}
	err = errors.Errorf("value with given key not found: %s", key)
	return nil, err
}

func (c *VppCache) deleteNode(key string) error {
	node, err := c.RetrieveNode(key)
	if err != nil {
		c.logger.Error(err)
		return err
	}
	delete(c.nMap, node.Name)
	delete(c.gigEIPMap, node.IPAdr)
	for _, intf := range node.NodeInterfaces {
		if intf.VppInternalName == "loop0" {
			delete(c.loopMACMap, intf.PhysAddress)
			for _, ip := range intf.IPAddresses {
				delete(c.loopIPMap, ip)
			}
		}

	}
	return nil
}

//RetrieveAllNodes returns an ordered slice of all nodes in a database organized by name.
func (c *VppCache) RetrieveAllNodes() []*telemetrymodel.Node {
	var str []string
	for k := range c.nMap {
		str = append(str, k)
	}
	var nList []*telemetrymodel.Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := c.RetrieveNode(v)
		nList = append(nList, n)
	}
	return nList
}



//Small helper function that returns the loop interface of a node
func (c *VppCache) getNodeLoopIFInfo(node *telemetrymodel.Node) (telemetrymodel.NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.VppInternalName == "loop0" {
			return ifs, nil
		}
	}
	err := errors.Errorf("Node %s does not have a loop interface", node.Name)
	c.logErrAndAppendToNodeReport(node.Name, err.Error())
	return telemetrymodel.NodeInterface{}, err
}


