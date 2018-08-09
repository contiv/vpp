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
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
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
	logger     logging.Logger
	hostIPMap  map[string]*telemetrymodel.Node
}

func (c *VppCache) logErrAndAppendToNodeReport(nodeName string, errString string) {
	c.nMap[nodeName].Report = append(c.nMap[nodeName].Report, errString)
	c.logger.Errorf(errString)
}

//addNode will add a node to the node cache with the given parameters, making sure there are no duplicates.
func (c *VppCache) addNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	n := &telemetrymodel.Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}

	n.PodMap = make(map[string]*telemetrymodel.Pod)
	_, err := c.GetNode(nodeName)
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

//NewVPPCache returns a pointer to a new node cache
func NewVPPCache(logger logging.Logger) (n *VppCache) {
	return &VppCache{
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		make(map[string]*telemetrymodel.Node),
		logger,
		make(map[string]*telemetrymodel.Node),
	}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (c *VppCache) SetNodeLiveness(name string, nLive *telemetrymodel.NodeLiveness) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Liveness %+v for node %+v", nLive, name)
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (c *VppCache) SetNodeInterfaces(name string, nInt map[int]telemetrymodel.NodeInterface) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Interfaces %+v for node %+v", nInt, name)
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (c *VppCache) SetNodeBridgeDomain(name string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received Bridge domain %+v for node %+v", nBridge, name)
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (c *VppCache) SetNodeL2Fibs(name string, nL2F map[string]telemetrymodel.NodeL2FibEntry) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	c.logger.Debugf("Received L2Fibs %+v for node %+v", nL2F, name)
	node.NodeL2Fibs = nL2F
	return nil
}

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (c *VppCache) SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error {
	node, err := c.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeTelemetry = nTele
	return nil
}

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (c *VppCache) SetNodeIPARPs(name string, nArps []telemetrymodel.NodeIPArpEntry) error {
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
func (c *VppCache) GetNode(key string) (n *telemetrymodel.Node, err error) {
	if node, ok := c.nMap[key]; ok {
		return node, nil
	}
	err = errors.Errorf("value with given key not found: %s", key)
	return nil, err
}

func (c *VppCache) deleteNode(key string) error {
	node, err := c.GetNode(key)
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

//GetAllNodes returns an ordered slice of all nodes in a database organized by name.
func (c *VppCache) GetAllNodes() []*telemetrymodel.Node {
	var str []string
	for k := range c.nMap {
		str = append(str, k)
	}
	var nList []*telemetrymodel.Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := c.GetNode(v)
		nList = append(nList, n)
	}
	return nList
}

//PopulateNodeMaps populates two of the node maps: the ip and mac address map
//It also checks to make sure that there are no duplicate addresses within the map.
func (ctc *ContivTelemetryCache) PopulateNodeMaps(node *telemetrymodel.Node) {
	loopIF, err := ctc.VppCache.getNodeLoopIFInfo(node)
	if err != nil {
		ctc.VppCache.logger.Error(err)
	}
	for i := range loopIF.IPAddresses {
		if loopIF.IPAddresses[i] == "" {
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name,
				fmt.Sprintf("Detected an empty IP address for node %+v", node.Name))
		} else {

			if ip, ok := ctc.VppCache.loopIPMap[loopIF.IPAddresses[i]]; ok {
				errString := fmt.Sprintf("Duplicate IP found: %+v", ip)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			} else {
				ctc.VppCache.loopIPMap[loopIF.IPAddresses[i]] = node
			}
		}
	}
	if loopIF.PhysAddress == "" {
		ctc.VppCache.logErrAndAppendToNodeReport(node.Name,
			fmt.Sprintf("Detected empty MAC address for node %+v", node.Name))
	} else {
		if _, ok := ctc.VppCache.loopMACMap[loopIF.PhysAddress]; ok {
			errString := fmt.Sprintf("Duplicate MAC address found: %s", loopIF.PhysAddress)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
		} else {
			ctc.VppCache.loopMACMap[loopIF.PhysAddress] = node
		}
		ctc.VppCache.gigEIPMap[node.IPAdr] = node
		k8snode, ok := ctc.K8sCache.k8sNodeMap[node.Name]
		nodeHostIP := ""
		if !ok {
			errString := fmt.Sprintf("Could not find k8s node counterpart for node %+v",
				node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
		} else {
			for _, adr := range k8snode.Addresses {
				if adr.Type == 3 {
					ctc.VppCache.hostIPMap[adr.Address] = node
					nodeHostIP = adr.Address
				}
			}
			if nodeHostIP == "" {
				errString := fmt.Sprintf("K8s node %+v does not have a valid type 3 host ip address", k8snode.Name)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			}
		}
		for _, pod := range ctc.K8sCache.podMap {
			if pod.HostIPAddress == nodeHostIP {
				node.PodMap[pod.Name] = pod
			}
		}
	}
	ctc.VppCache.gigEIPMap[node.IPAdr] = node
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

/*ValidateLoopIFAddresses validates the the entries of node ARP tables to make sure that
the number of entries is correct as well as making sure that each entry's
ip address and mac address correspond to the correct node in the network.*/
func (ctc *ContivTelemetryCache) ValidateLoopIFAddresses() {
	nodelist := ctc.VppCache.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range ctc.VppCache.nMap {
		nodemap[key] = true
	}
	for _, node := range nodelist {
		nLoopIF, err := ctc.VppCache.getNodeLoopIFInfo(node)
		if err != nil {
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, err.Error())

			errString := fmt.Sprintf("Cannot process node ARP Table because loop interface info is missing.")
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
		}
		for _, arp := range node.NodeIPArp {
			if node.NodeInterfaces[int(arp.Interface)].VppInternalName != "loop0" {

			}

			nLoopIFTwo, ok := node.NodeInterfaces[int(arp.Interface)]
			if !ok {
				errString := fmt.Sprintf("Loop Interface for ARP Table entry  %d not found", arp.Interface)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				continue
			}
			if nLoopIF.VppInternalName != nLoopIFTwo.VppInternalName {
				continue
			}
			macNode, ok := ctc.VppCache.loopMACMap[arp.MacAddress]
			addressNotFound := false
			if !ok {
				errString := fmt.Sprintf("Node %s cound not find node with MAC Address %s", node.Name, arp.MacAddress)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				addressNotFound = true
			}
			ipNode, ok := ctc.VppCache.loopIPMap[arp.IPAddress+"/24"]

			if !ok {
				errString := fmt.Sprintf("Node %s could not find Node with IP Address %s", node.Name, arp.IPAddress)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				addressNotFound = true
			}
			if addressNotFound {
				continue
			}
			if macNode.Name != ipNode.Name {
				errString := fmt.Sprintf("MAC and IP point to different nodes: %s and %s in ARP Table %+v",
					macNode.Name, ipNode.Name, arp)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)

			}
			delete(nodemap, node.Name)
		}

	}
	if len(nodemap) == 0 {
		ctc.report = append(ctc.report, "Success validating node IP ARP table")
	}
	if len(nodemap) > 0 {
		for node := range nodemap {
			ctc.VppCache.logger.Errorf("No MAC entry found for %+v", node)
			ctc.report = append(ctc.report, errors.Errorf("No MAC entry found for %+v", node).Error())
			delete(nodemap, node)
		}
	}
}

//ValidateL2Connections makes sure that each node in the cache has the right amount of vxlan_tunnels for the number of
//nodes as well as checking that each vxlan_tunnel points to a node that has a corresponding but opposite tunnel itself.
func (ctc *ContivTelemetryCache) ValidateL2Connections() {
	nodelist := ctc.VppCache.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range ctc.VppCache.nMap {
		nodemap[key] = true
	}
	//For each node in the cache
	for _, node := range nodelist {
		nodevxlanmap := make(map[string]bool)
		for key := range ctc.VppCache.nMap {
			nodevxlanmap[key] = true
		}
		bdhasLoopIF := false
		hasVXLanBD := false
		var vxLanBD telemetrymodel.NodeBridgeDomain
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
			errString := fmt.Sprintf("Node %+v has multiple vxlanBD bridge domains", node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}
		//if there is not then report an error and move on.
		if !hasVXLanBD {
			errString := fmt.Sprintf("Node %+v does not have a vxlan BD", node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
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
			intfidxInterface, ok := node.NodeInterfaces[int(intfidx)]
			if !ok {
				errString := fmt.Sprintf("BD index %+v for node %+v does not point to a valid interface.",
					intfidx, node.Name)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				continue

			}
			if intfidxInterface.IfType == interfaces.InterfaceType_SOFTWARE_LOOPBACK {
				bdhasLoopIF = true
				i++
				str := node.NodeInterfaces[int(intfidx)].PhysAddress
				delete(nodevxlanmap, ctc.VppCache.loopMACMap[str].Name)
				continue
			}
			//check if one of the indices points to a vxlan_tunnel interface
			if intfidxInterface.IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
				if node.NodeInterfaces[int(intfidx)].Vxlan.Vni != vppVNI {
					errString := fmt.Sprintf("unexpected VNI for node %+v: got %+v expected %+v",
						node.Name, node.NodeInterfaces[int(intfidx)].Vxlan.Vni, vppVNI)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue

				}
				vxlantun := node.NodeInterfaces[int(intfidx)]
				srcipNode, ok := ctc.VppCache.gigEIPMap[vxlantun.Vxlan.SrcAddress+subnetmask]

				//try to find node with src ip address of the tunnel and make sure it is the same as the current node.
				if !ok {
					errString := fmt.Sprintf("Error finding node with src IP %+v",
						vxlantun.Vxlan.SrcAddress)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue
				}
				if srcipNode.Name != node.Name {
					errString := fmt.Sprintf("vxlan_tunnel %+v has source ip %v which points "+
						"to a different node than %+v.", vxlantun, vxlantun.Vxlan.SrcAddress, node.Name)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue
				}

				//try to find node with dst ip address in tunnel and validate it has a vxlan_tunnel that is the opposite
				//of the current vxlan_tunnel and increment the counter if it does.
				dstipNode, ok := ctc.VppCache.gigEIPMap[vxlantun.Vxlan.DstAddress+subnetmask]
				if !ok {
					errString := fmt.Sprintf("Node with dst ip %+v in vxlan_tunnel %+v not found",
						vxlantun.Vxlan.DstAddress, vxlantun)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
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
					errString := fmt.Sprintf("no matching vxlan_tunnel found for vxlan %+v",
						vxlantun)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue
				}
				i++
				str := node.NodeInterfaces[int(intfidx)].Vxlan.DstAddress
				delete(nodevxlanmap, ctc.VppCache.gigEIPMap[str+subnetmask].Name)

			}
		}
		//checks if there are an unequal amount vxlan tunnels for the current node versus the total number of nodes
		if i != len(nodelist) {
			errString := fmt.Sprintf("number of valid vxlan tunnels for node %+v does "+
				"not match number of nodes on network: got %+v, expected %+v", node.Name, i, len(nodelist))
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
		}

		if !bdhasLoopIF {
			errString := fmt.Sprintf("bridge domain %+v has no loop interface",
				node.NodeBridgeDomains)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}
		if len(nodevxlanmap) > 0 {
			errString := fmt.Sprintf("Missing valid vxlan entries for node %+v:", node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			for node := range nodevxlanmap {
				ctc.VppCache.logErrAndAppendToNodeReport(node, node)
			}
			continue
		}

		delete(nodemap, node.Name)

	}
	//make sure that each node has been successfully validated
	if len(nodemap) > 0 {
		for node := range nodemap {
			ctc.report = append(ctc.report, errors.Errorf("error validating BD info for node %+v", node).Error())
		}
	} else {
		ctc.report = append(ctc.report, "Success validating L2 connections")
		//ctc.logger.Info("Success validating L2 connections.")
	}

}

//ValidateFibEntries will validate that each nodes fib entries ip address point to the right loop interface and the
//mac addresses match
func (ctc *ContivTelemetryCache) ValidateFibEntries() {
	nodelist := ctc.VppCache.GetAllNodes()
	nodemap := make(map[string]bool)
	for key := range ctc.VppCache.nMap {
		nodemap[key] = true
	}

	for _, node := range nodelist {
		nodefibmap := make(map[string]bool)
		for key := range ctc.VppCache.nMap {
			nodefibmap[key] = true
		}
		fibhasLoopIF := false
		if len(node.NodeL2Fibs) != len(nodelist) {
			errString := fmt.Sprintf("Incorrect number of L2 fib entries: %d for node %+v: expecting %d",
				len(node.NodeL2Fibs), node.Name, len(nodelist))
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}
		loopIf, err := ctc.VppCache.getNodeLoopIFInfo(node)
		if err != nil {
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, err.Error())
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
				delete(nodefibmap, ctc.VppCache.loopMACMap[fib.PhysAddress].Name)
				continue
			}
			intf := node.NodeInterfaces[int(fib.OutgoingInterfaceSwIfIdx)]
			macnode, ok := ctc.VppCache.gigEIPMap[intf.Vxlan.DstAddress+subnetmask]
			if !ok {
				errString := fmt.Sprintf("GigE IP address %s does not exist in gigEIPMap", intf.Vxlan.DstAddress)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				continue
			}
			remoteloopif, err := ctc.VppCache.getNodeLoopIFInfo(macnode)
			if err != nil {
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, err.Error())
				continue
			}
			if remoteloopif.PhysAddress == fib.PhysAddress {
				delete(nodefibmap, ctc.VppCache.loopMACMap[fib.PhysAddress].Name)
				fibcount++
				continue
			} else {
				errString := fmt.Sprintf("Fib MAC %+v is different than actual MAC "+
					"%+v", fib.PhysAddress, remoteloopif.PhysAddress)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			}
			if len(nodefibmap) > 0 {
				errString := fmt.Sprintf("Missing Fib entries for node %+v", node.Name)
				ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
				for node := range nodefibmap {
					ctc.VppCache.logErrAndAppendToNodeReport(node, node)
				}
			}
		}

		if !fibhasLoopIF {
			errString := fmt.Sprintf("Fib for node %+v loop interface missing",
				node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		if fibcount != len(nodelist) {
			errString := fmt.Sprintf("Unequal amount of fib entries for node %+v",
				node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
		}
		delete(nodemap, node.Name)
	}

	if len(nodemap) > 0 {
		for node := range nodemap {
			errString := fmt.Sprintf("Error processing fib for node %+v", node)
			ctc.VppCache.logErrAndAppendToNodeReport(node, errString)
		}

	} else {
		ctc.report = append(ctc.report, "Success validating Fib entries")
	}

}

//ValidateK8sNodeInfo will make sure that the cache has the same amount of k8s and etcd nodes and that each node has an
//equal opposite node.
func (ctc *ContivTelemetryCache) ValidateK8sNodeInfo() {
	nodeList := ctc.VppCache.GetAllNodes()
	nodeMap := make(map[string]bool)
	for key := range ctc.VppCache.nMap {
		nodeMap[key] = true
	}
	k8sNodeMap := make(map[string]bool)
	for key := range ctc.K8sCache.k8sNodeMap {
		k8sNodeMap[key] = true
	}
	for _, node := range nodeList {
		k8sNode, ok := ctc.K8sCache.k8sNodeMap[node.Name]
		if !ok {
			errString := fmt.Sprintf("node with name %+v missing in k8s node map",
				node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}
		if node.Name == k8sNode.Name {
			delete(nodeMap, node.Name)
			delete(k8sNodeMap, k8sNode.Name)
		}

	}

	if len(k8sNodeMap) > 0 {
		ctc.report = append(ctc.report, errors.Errorf("Missing nodes for following k8snodes:").Error())
		for node := range k8sNodeMap {
			ctc.report = append(ctc.report, errors.Errorf("node: %+v", node).Error())
		}
	}
	if len(nodeMap) > 0 {
		ctc.report = append(ctc.report, errors.Errorf("Missing nodes for following nodes:").Error())
		for node := range k8sNodeMap {
			ctc.report = append(ctc.report, errors.Errorf("node: %+v", node).Error())
		}

	}

}

//ValidatePodInfo will check to see that each pod has a valid host ip address node and that the information correctly
//correlates between the nodes and the pods.
func (ctc *ContivTelemetryCache) ValidatePodInfo() {

	podMap := make(map[string]bool)
	for key := range ctc.K8sCache.podMap {
		podMap[key] = true
	}
	for _, pod := range ctc.K8sCache.podMap {
		node, ok := ctc.VppCache.hostIPMap[pod.HostIPAddress]
		if !ok {
			ctc.report = append(ctc.report, errors.Errorf("Error finding node for host ip %+v from pod %+v",
				pod.HostIPAddress, pod.Name).Error())
			continue
		}
		podPtr, ok := node.PodMap[pod.Name]
		if !ok {
			ctc.report = append(ctc.report, errors.Errorf("pod %+v in node %+v podMap not found",
				pod.Name, node.Name).Error())
			continue
		}
		if pod != podPtr {
			errString := fmt.Sprintf("node podmap pod %+v is not the same as cache podmap pod %+v",
				podPtr.Name, pod.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}
		k8snode, ok := ctc.K8sCache.k8sNodeMap[node.Name]

		if !ok {
			errString := fmt.Sprintf("cannot find k8snode in k8sNodeMap for node with name %+v",
				node.Name)
			ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		i := 0
		for _, adr := range k8snode.Addresses {
			if adr.Type == 3 {
				if adr.Address != pod.HostIPAddress {
					errString := fmt.Sprintf("pod host ip %+v does not match with k8snode ip %+v",
						pod.HostIPAddress, adr.Address)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue
				}
				i++
			}
			if adr.Type == 1 {
				if adr.Address != node.Name {
					errString := fmt.Sprintf("pod host name %+v does not match node name %+v",
						adr.Address, node.Name)
					ctc.VppCache.logErrAndAppendToNodeReport(node.Name, errString)
					continue
				}
				i++
			}
		}
		if i != 2 {
			continue
		}
		delete(podMap, pod.Name)
	}

	if len(podMap) > 0 {
		for p := range podMap {
			ctc.report = append(ctc.report, errors.Errorf("error processing pod %+v", p).Error())
		}

	} else {
		ctc.report = append(ctc.report, "Success validating pod info.")
	}

}
