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
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/pkg/errors"
	"sort"
)

const subnetmask = "/24"
const vppVNI = 10

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
	ctc.Log.Infof("ContivTelemetryCache has been initialized")
	return nil
}

// ListAllNodes returns node data for all nodes in the cache.
func (ctc *ContivTelemetryCache) ListAllNodes() []*Node {
	nodeList := ctc.Cache.GetAllNodes()
	return nodeList
}

// LookupNode return node data for nodes that match a node name passed
// to the function in the node names slice.
func (ctc *ContivTelemetryCache) LookupNode(nodenames []string) []*Node {
	nodeslice := make([]*Node, 0)
	for _, name := range nodenames {
		node := ctc.Cache.nMap[name]
		nodeslice = append(nodeslice, node)
	}
	return nodeslice
}

// DeleteNode deletes from the cache those nodes that match a node name passed
// to the function in the node names slice.
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
		ctc.Cache.nMap[nodeName].report = append(ctc.Cache.nMap[nodeName].report, errors.Errorf(
			"duplicate key found: %s", nodeName).Error())
		return err
	}
	ctc.Cache.nMap[nodeName] = n
	ctc.Cache.gigEIPMap[IPAdr] = n
	ctc.Log.Debugf("Success adding node %+v to ctc.ContivTelemetryCache %+v", nodeName, ctc.Cache)
	return nil
}

//AddNode will add a node to the Contiv Telemetry cache with the given parameters.
func (c *Cache) AddNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	n := &Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}
	_, err := c.GetNode(nodeName)
	if err == nil {
		err = errors.Errorf("duplicate key found: %s", nodeName)
		c.nMap[nodeName].report = append(c.nMap[nodeName].report, err.Error())
		return err
	}
	c.nMap[nodeName] = n
	c.gigEIPMap[IPAdr] = n
	c.logger.Debugf("Success adding node %+v to ctc.ContivTelemetryCache %+v", nodeName, c)
	return nil
}

//ClearCache with delete all the values in each of the individual cache maps.
func (ctc *ContivTelemetryCache) ClearCache() {
	for _, node := range ctc.Cache.nMap {
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
		make([]string, 0),
		logger}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (c *Cache) SetNodeLiveness(name string, nLive *NodeLiveness) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Liveness %+v for node %+v", nLive, name)
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (c *Cache) SetNodeInterfaces(name string, nInt map[int]NodeInterface) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Interfaces %+v for node %+v", nInt, name)
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (c *Cache) SetNodeBridgeDomain(name string, nBridge map[int]NodeBridgeDomains) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Bridge domain %+v for node %+v", nBridge, name)
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (c *Cache) SetNodeL2Fibs(name string, nL2F map[string]NodeL2Fib) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received L2Fibs %+v for node %+v", nL2F, name)
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
	c.logger.Debugf("Received IPARPS %+v for node %+v", nArps, name)
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
		if loopIF.IPAddresses[i] == "" {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report,
				"Detected an empty IP address for node %+v", node.Name)
		} else {

			if ip, ok := c.loopIPMap[loopIF.IPAddresses[i]]; ok {
				//TODO: Report an error back to the controller; store it somewhere, report it at the end of the function
				c.logger.Errorf("Duplicate IP found: %s", ip)
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Duplicate IP found: %s", ip).Error())
			} else {
				for i := range loopIF.IPAddresses {
					c.loopIPMap[loopIF.IPAddresses[i]] = node
				}

			}
		}
	}
	if loopIF.PhysAddress == "" {
		c.nMap[node.Name].report = append(c.nMap[node.Name].report,
			"Detected empty MAC address for node %+v", node.Name)
	} else {
		if mac, ok := c.loopMACMap[loopIF.PhysAddress]; ok {
			c.logger.Errorf("Duplicate MAC address found: %s", mac)
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Duplicate MAC address found: %s", mac).Error())
		} else {
			c.loopMACMap[loopIF.PhysAddress] = node
		}
		c.nMap[node.Name] = node
		c.gigEIPMap[node.IPAdr] = node
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
	c.nMap[node.Name].report = append(c.nMap[node.Name].report, err.Error())
	return NodeInterface{}, err
}

/*ValidateLoopIFAddresses validates the the entries of node ARP tables to make sure that
the number of entries is correct as well as making sure that each entry's
ip address and mac address correspond to the correct node in the network.*/
func (c *Cache) ValidateLoopIFAddresses() {
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
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, err.Error())
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Cannot process node ARP Table because loop interface info is missing.").Error())
			continue
		}
		for _, arp := range node.NodeIPArp {
			if node.NodeInterfaces[int(arp.Interface)].VppInternalName != "loop0" {
				continue
			}

			nLoopIFTwo, ok := node.NodeInterfaces[int(arp.Interface)]
			if !ok {
				c.logger.Errorf("Loop Interface in ARP Table not found: %d", arp.Interface)
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Loop Interface in ARP Table not found: %d", arp.Interface).Error())
			}
			if nLoopIF.VppInternalName != nLoopIFTwo.VppInternalName {
				continue
			}
			macNode, ok := c.loopMACMap[arp.MacAddress]
			addressNotFound := false
			if !ok {
				c.logger.Errorf("Node for MAC Address %s not found", arp.MacAddress)
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Node for MAC Address %s not found", arp.MacAddress).Error())
				addressNotFound = true
			}
			ipNode, ok := c.loopIPMap[arp.IPAddress+"/24"]

			if !ok {
				c.logger.Errorf("Node %s could not find Node with IP Address %s", node.Name, arp.IPAddress)
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Node %s could not find Node with IP Address %s",
					node.Name,
					arp.IPAddress).Error())
				addressNotFound = true
			}
			if addressNotFound {
				continue
			}
			if macNode.Name != ipNode.Name {
				c.logger.Errorf("MAC and IP point to different nodes: %s and %s in ARP Table %+v",
					macNode.Name, ipNode.Name, arp)
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"MAC and IP point to different nodes: %s and %s in ARP Table %+v",
					macNode.Name, ipNode.Name, arp).Error())

			}
			delete(nodemap, node.Name)
		}

	}
	if len(nodemap) == 0 {
		c.report = append(c.report, "Success validating node IP ARP table")
	}
	if len(nodemap) > 0 {
		for node := range nodemap {
			c.logger.Errorf("No MAC entry found for %+v", node)
			c.report = append(c.report, errors.Errorf("No MAC entry found for %+v", node).Error())
			delete(nodemap, node)
		}
	}
}

//ValidateL2Connections makes sure that each node in the cache has the right amount of vxlan_tunnels for the number of
//nodes as well as checking that each vxlan_tunnel points to a node that has a corresponding but opposite tunnel itself.
func (c *Cache) ValidateL2Connections() {
	nodelist := c.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range c.nMap {
		nodemap[key] = true
	}
	//For each node in the cache
	for _, node := range nodelist {
		nodevxlanmap := make(map[string]bool)
		for key := range c.nMap {
			nodevxlanmap[key] = true
		}
		bdhasLoopIF := false
		hasVXLanBD := false
		var vxLanBD NodeBridgeDomains
		//Make sure there is a bridge domain with the name vxlanBD
		vxlanBDCount := 0
		for _, bdomain := range node.NodeBridgeDomains {
			if bdomain.Name == "vxlanBD" {
				vxLanBD = bdomain
				hasVXLanBD = true
				vxlanBDCount++
			}
		}
		if vxlanBDCount > 1 {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Node %+v has multiple vxlanBD bridge domains", node.Name).Error())
			continue
		}
		//if there is not then report an error and move on.
		if !hasVXLanBD {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Node %+v does not have a vxlan BD", node.Name).Error())
			continue
		}
		//Create a list with each of the indices of the xvlanBD.
		bDomainidxs := make([]uint32, 0)
		for _, intf := range vxLanBD.Interfaces {
			bDomainidxs = append(bDomainidxs, intf.SwIfIndex)
		}

		i := 0
		//for each index in the vxlanBD
		for _, intfidx := range bDomainidxs {
			//check if one of the indices point to the loop interface
			//if it does, increment a counter and set a boolean to true
			if node.NodeInterfaces[int(intfidx)].IfType == interfaces.InterfaceType_SOFTWARE_LOOPBACK {
				bdhasLoopIF = true
				i++
				str := node.NodeInterfaces[int(intfidx)].PhysAddress
				delete(nodevxlanmap, c.loopMACMap[str].Name)
				continue
			}
			//check if one of the indices points to a vxlan_tunnel interface
			if node.NodeInterfaces[int(intfidx)].IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
				if node.NodeInterfaces[int(intfidx)].Vxlan.Vni != vppVNI {
					c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
						"unexpected VNI: got %+v expected %+v",
						node.NodeInterfaces[int(intfidx)].Vxlan.Vni, vppVNI).Error())
					continue

				}
				vxlantun := node.NodeInterfaces[int(intfidx)]
				srcipNode, ok := c.gigEIPMap[vxlantun.Vxlan.SrcAddress+subnetmask]

				//try to find node with src ip address of the tunnel and make sure it is the same as the current node.
				if !ok {
					c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
						"Error finding node with src IP %+v",
						vxlantun.Vxlan.SrcAddress).Error())
					continue
				}
				if srcipNode.Name != node.Name {
					c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
						"vxljan_tunnel %+v has source ip %v which points "+
							"to different node than %+v.", vxlantun, vxlantun.Vxlan.SrcAddress, node.Name).Error())
					continue
				}

				//try to find node with dst ip address in tunnel and validate it has a vxlan_tunnel that is the opposite
				//of the current vxlan_tunnel and increment the counter if it does.
				dstipNode, ok := c.gigEIPMap[vxlantun.Vxlan.DstAddress+subnetmask]
				if !ok {
					c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
						"Node with dst ip %+v in vxlan_tunnel %+v not found",
						vxlantun.Vxlan.DstAddress, vxlantun).Error())
					continue
				}
				matchingTunnelFound := false
				for _, dstIntf := range dstipNode.NodeInterfaces {
					if dstIntf.IfType == vxlantun.IfType {
						if dstIntf.Vxlan.DstAddress == vxlantun.Vxlan.SrcAddress {
							matchingTunnelFound = true
						}
					}
				}
				if !matchingTunnelFound {
					c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
						"no matching vxlan_tunnel found for vxlan %+v",
						vxlantun).Error())
					continue
				}
				i++
				str := node.NodeInterfaces[int(intfidx)].Vxlan.DstAddress
				delete(nodevxlanmap, c.gigEIPMap[str+subnetmask].Name)

			}
		}
		//checks if there are an unequal amount vxlan tunnels for the current node versus the total number of nodes
		if i != len(nodelist) {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"number of vxlan tunnels for node %+v does "+
					"not match number of nodes on network\n", node.Name).Error())
		}

		if !bdhasLoopIF {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"bridge domain %+v has no loop interface",
				node.NodeBridgeDomains).Error())
			continue
		}
		if len(nodevxlanmap) > 0 {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Missing vxlan entries for node %+v:", node.Name).Error())
			for node := range nodevxlanmap {
				c.nMap[node].report = append(c.nMap[node].report, node)
			}
		}

		delete(nodemap, node.Name)

	}
	//make sure that each node has been successfully validated
	if len(nodemap) > 0 {
		for node := range nodemap {
			c.report = append(c.report, errors.Errorf("error validating BD info for node %+v\n", node).Error())
		}
	} else {
		c.report = append(c.report, "Success validating L2 connections")
	}

}

//ValidateFibEntries will validate that each nodes fib entries ip address point to the right loop interface and the
//mac addresses match
func (c *Cache) ValidateFibEntries() {
	nodelist := c.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range c.nMap {
		nodemap[key] = true
	}

	for _, node := range nodelist {
		nodefibmap := make(map[string]bool)
		for key := range c.nMap {
			nodefibmap[key] = true
		}
		fibhasLoopIF := false
		if len(node.NodeL2Fibs) != len(nodelist) {
			c.nMap[node.Name].report = c.nMap[node.Name].report //error not right amount of entries
			continue
		}
		loopIf, err := c.getNodeLoopIFInfo(node)
		if err != nil {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, err.Error())
			continue
		}

		fibcount := 0
		var vxLanBD int
		for bdomainidx, bdomain := range node.NodeBridgeDomains {
			if bdomain.Name == "vxlanBD" {
				vxLanBD = bdomainidx
				break
			}
		}
		for _, fib := range node.NodeL2Fibs {
			if int(fib.BridgeDomainIdx) != vxLanBD {
				continue
			}
			if fib.PhysAddress == loopIf.PhysAddress {
				fibhasLoopIF = true
				fibcount++
				delete(nodefibmap, c.loopMACMap[fib.PhysAddress].Name)
				continue
			}
			intf := node.NodeInterfaces[int(fib.OutgoingInterfaceSwIfIdx)]
			macnode := c.gigEIPMap[intf.Vxlan.DstAddress+subnetmask]
			remoteloopif, err := c.getNodeLoopIFInfo(macnode)
			if err != nil {
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, err.Error()) //err no loop interface for the node
				continue
			}
			if remoteloopif.PhysAddress == fib.PhysAddress {
				delete(nodefibmap, c.loopMACMap[fib.PhysAddress].Name)
				fibcount++
				continue
			} else {
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Fib MAC %+v is different than actual MAC "+
						"%+v", fib.PhysAddress, remoteloopif.PhysAddress).Error())
			}
			if len(nodefibmap) > 0 {
				c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
					"Missing Fib entries for node %+v", node.Name).Error())
				for node := range nodefibmap {
					c.nMap[node].report = append(c.nMap[node].report, node)
				}
			}
		}

		if !fibhasLoopIF {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Fib for node %+v loop interface missing",
				node.Name).Error()) //error fib for loop if missing
			continue
		}

		if fibcount != len(nodelist) {
			c.nMap[node.Name].report = append(c.nMap[node.Name].report, errors.Errorf(
				"Unequal amount of fib entries for node %+v",
				node.Name).Error())
		}
		delete(nodemap, node.Name)
	}

	if len(nodemap) > 0 {
		for node := range nodemap {
			c.nMap[node].report = append(c.nMap[node].report, errors.Errorf(
				"Error processing fib for node %+v", node).Error())
		}

	} else {
		c.report = append(c.report, "Success validating Fib entries")
	}

}
