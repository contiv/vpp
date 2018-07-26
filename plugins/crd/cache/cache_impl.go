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
//

package cache

import (
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/pkg/errors"
	"sort"
)

// ContivTelemetryCache is used for a in-memory storage of K8s State data
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
type ContivTelemetryCache struct {
	Deps
	Synced bool
	// todo - here add the maps you have in your db implementation
	Cache      *Cache
	k8sNodeMap map[string]*nodemodel.Node
	Processor  *ContivTelemetryProcessor
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	// todo - here initialize your maps
	ctc.Cache = NewCache(ctc.Log)
	ctc.k8sNodeMap = make(map[string]*nodemodel.Node)
	ctc.Log.Infof("Cache has been initialized")
	return nil
}

// Update processes a datasync change event associated with K8s State data.
// The change is applied into the cache and all subscribed watchers are
// notified.
// The function will forward any error returned by a watcher.
func (ctc *ContivTelemetryCache) Update(dataChngEv datasync.ChangeEvent) error {
	err := ctc.changePropagateEvent(dataChngEv)
	if err != nil {
		return err
	}

	return nil
}

// Resync processes a datasync resync event associated with K8s State data.
// The cache content is full replaced with the received data.
func (ctc *ContivTelemetryCache) Resync(resyncEv datasync.ResyncEvent) error {
	return ctc.processResyncEvent(resyncEv)
}

// ListAllNodes returns node data for all nodes in the cache.
func (ctc *ContivTelemetryCache) ListAllNodes() []*Node {
	nodeList := ctc.Cache.GetAllNodes()
	return nodeList
}

// LookupNode return node data for nodes that match a node name passed
// to the function in the nodenames slice.
func (ctc *ContivTelemetryCache) LookupNode(nodenames []string) []*Node {
	nodeslice := make([]*Node, 0)
	for _, name := range nodenames {
		node := ctc.Cache.nMap[name]
		nodeslice = append(nodeslice, node)
	}
	return nodeslice
}

// DeleteNode deletes from the cache those nodes that match a node name passed
// to the function in the nodenames slice.
func (ctc *ContivTelemetryCache) DeleteNode(nodenames []string) {
	for _, str := range nodenames {
		node, err := ctc.Cache.GetNode(str)
		if err != nil {
			ctc.Log.Error(err)
		}
		delete(ctc.Cache.nMap, node.Name)
		delete(ctc.Cache.gigEIPMap, node.IPAdr)
		for _, intf := range node.NodeInterfaces {
			if intf.VppInternalName == "loop0" {
				delete(ctc.Cache.loopMACMap, intf.PhysAddress)
				for _, ip := range intf.IPAddresses {
					delete(ctc.Cache.loopIPMap, ip)
				}
			}

		}
	}

}
//AddNode will add a node to the Contiv Telemetry cache with the given parameters.
func (ctc *ContivTelemetryCache) AddNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	n := &Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}
	_, err := ctc.Cache.GetNode(nodeName)
	if err == nil {
		err = errors.Errorf("duplicate key found: %s", nodeName)
		return err
	}
	ctc.Cache.nMap[nodeName] = n
	ctc.Cache.gigEIPMap[IPAdr] = n
	ctc.Log.Debugf("Success adding node %+v to ctc.Cache %+v", nodeName, ctc.Cache)
	return nil
}

//Clear cache with delete all the values in each of the individual cache maps.
func (ctc *ContivTelemetryCache) ClearCache() {
	for _, node := range ctc.Cache.nMap {
		delete(ctc.Cache.nMap, node.Name)
		delete(ctc.Cache.gigEIPMap, node.IPAdr)
		for _, intf := range node.NodeInterfaces {
			if intf.VppInternalName == "loop0" {
				delete(ctc.Cache.loopMACMap, intf.PhysAddress)
				for _, ip := range intf.IPAddresses {
					delete(ctc.Cache.loopIPMap, ip)
				}
			}
		}
	}
}

//NewCache returns a pointer to a new node cache
func NewCache(logger logging.Logger) (n *Cache) {
	return &Cache{
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string][]string),
		logger}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (c *Cache) SetNodeLiveness(name string, nLive *NodeLiveness) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Recevied Liveness %+v for node %+v", nLive, name)
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (c *Cache) SetNodeInterfaces(name string, nInt map[int]NodeInterface) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Recevied Interfaces %+v for node %+v", nInt, name)
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (c *Cache) SetNodeBridgeDomain(name string, nBridge map[int]NodeBridgeDomains) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Recevied Bridge domain %+v for node %+v", nBridge, name)
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (c *Cache) SetNodeL2Fibs(name string, nL2F map[string]NodeL2Fib) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Recevied L2Fibs %+v for node %+v", nL2F, name)
	node.NodeL2Fibs = nL2F
	return nil
}

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (c *Cache) SetNodeTelemetry(name string, nTele map[string]NodeTelemetry) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeTelemetry = nTele
	return nil
}

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (c *Cache) SetNodeIPARPs(name string, nArps []NodeIPArp) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Recevied IPARPS %+v for node %+v", nArps, name)
	node.NodeIPArp = nArps
	return nil

}

//GetNode returns a pointer to a node for the given key.
//Returns an error if that key is not found.
func (c *Cache) GetNode(key string) (n *Node, err error) {
	if node, ok := c.nMap[key]; ok {
		return node, nil
	}
	err = errors.Errorf("value with given key not found: %s", key)
	return nil, err
}

//addNode adds a new node with the given information.
//Returns an error if the node is already in the database

//GetAllNodes returns an ordered slice of all nodes in a database organized by name.
func (c *Cache) GetAllNodes() []*Node {
	var str []string
	for k := range c.nMap {
		str = append(str, k)
	}
	var nList []*Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := c.GetNode(v)
		nList = append(nList, n)
	}
	return nList
}

//PopulateNodeMaps populates two of the node maps: the ip and mac address map
//It also checks to make sure that there are no duplicate addresses within the map.
func (c *Cache) PopulateNodeMaps(node *Node) {

	loopIF, err := c.getNodeLoopIFInfo(node)
	if err != nil {
		c.logger.Error(err)
	}
	for i := range loopIF.IPAddresses {
		if ip, ok := c.loopIPMap[loopIF.IPAddresses[i]]; !ok && ip != nil {
			//TODO: Report an error back to the controller; store it somewhere, report it at the end of the function
			c.logger.Errorf("Duplicate IP found: %s", ip)
		} else {
			for i := range loopIF.IPAddresses {
				c.loopIPMap[loopIF.IPAddresses[i]] = node
			}
		}
	}
	if mac, ok := c.loopMACMap[loopIF.PhysAddress]; !ok && mac != nil {
		c.logger.Errorf("Duplicate MAC address found: %s", mac)
	} else {
		c.loopMACMap[loopIF.PhysAddress] = node
	}
}

//Small helper function that returns the loop interface of a node
func (c *Cache) getNodeLoopIFInfo(node *Node) (NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.VppInternalName == "loop0" {
			return ifs, nil
		}
	}
	err := errors.Errorf("Node %s does not have a loop interface")
	return NodeInterface{}, err
}

/*ValidateLoopIFAddresses validates the the entries of node ARP tables to make sure that
the number of entries is correct as well as making sure that each entry's
ip address and mac address correspond to the correct node in the network.*/
func (c *Cache) ValidateLoopIFAddresses()  {
	nodelist := c.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range c.nMap {
		nodemap[key] = true
	}
	for _, node := range nodelist {
		nLoopIF, err := c.getNodeLoopIFInfo(node)
		if err != nil {
			c.logger.Error(err)
			c.logger.Errorf("Cannot process node ARP Table because loop interface info is missing.")
			continue
		}
		for _, arp := range node.NodeIPArp {
			if node.NodeInterfaces[int(arp.Interface)].VppInternalName != "loop0" {
				continue
			}

			nLoopIFTwo, ok := node.NodeInterfaces[int(arp.Interface)]
			if !ok {
				c.logger.Errorf("Loop Interface in ARP Table not found: %d", arp.Interface)
			}
			if nLoopIF.VppInternalName != nLoopIFTwo.VppInternalName {
				continue
			}
			macNode, ok := c.loopMACMap[arp.MacAddress]
			addressNotFound := false
			if !ok {
				c.logger.Errorf("Node for MAC Address %s not found", arp.MacAddress)
				addressNotFound = true
			}
			ipNode, ok := c.loopIPMap[arp.IPAddress+"/24"]

			if !ok {
				c.logger.Errorf("Node %s could not find Node with IP Address %s", node.Name, arp.IPAddress)
				addressNotFound = true
			}
			if addressNotFound {
				continue
			}
			if macNode.Name != ipNode.Name {
				c.logger.Errorf("MAC and IP point to different nodes: %s and %s in ARP Table %+v",
					macNode.Name, ipNode.Name, arp)

			}
			delete(nodemap, node.Name)
		}
	}
	if len(nodemap) > 0 {
		for node := range nodemap {
			c.logger.Errorf("No MAC entry found for %+v", node)
			delete(nodemap, node)
		}
	}
}
