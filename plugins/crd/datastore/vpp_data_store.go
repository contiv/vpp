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

package datastore

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/pkg/errors"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//VppDataStore holds various maps which all take different keys but point to the same underlying value.
type VppDataStore struct {
	lock *sync.Mutex

	NodeMap    map[string]*telemetrymodel.Node
	LoopIPMap  map[string]*telemetrymodel.Node
	GigEIPMap  map[string]*telemetrymodel.Node
	LoopMACMap map[string]*telemetrymodel.Node
	HostIPMap  map[string]*telemetrymodel.Node
}

// CreateNode will add a node to the node cache with the given parameters,
// making sure there are no duplicates.
func (vds *VppDataStore) CreateNode(ID uint32, nodeName, IPAddr string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	if _, ok := vds.retrieveNode(nodeName); ok {
		return fmt.Errorf("node %s already exists", nodeName)
	}

	n := &telemetrymodel.Node{
		NodeInfo: &telemetrymodel.NodeInfo{IPAddr: IPAddr, ID: ID, Name: nodeName},
	}
	n.PodMap = make(map[string]*telemetrymodel.Pod)
	vds.NodeMap[nodeName] = n

	if IPAddr != "" {
		ipa := strings.Split(IPAddr, "/")
		vds.GigEIPMap[ipa[0]] = n
	}

	return nil
}

// RetrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vds *VppDataStore) RetrieveNode(nodeName string) (n *telemetrymodel.Node, err error) {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if ok {
		return node, nil
	}
	return nil, fmt.Errorf("node %s not found", nodeName)
}

// DeleteNode handles node deletions from the cache. The delete callback
// actually hands off to us the node ID in a string format, so we have
// to first find the node by its ID, not its name. If the nodeName parameter
// is invalid, or it does not identify a node that is present in the cache,
// we return an error.
func (vds *VppDataStore) DeleteNode(nodeName string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	nodeID, err := strconv.Atoi(nodeName)
	if err != nil {
		return fmt.Errorf("invalid nodeId %s", nodeName)
	}

	for _, node := range vds.NodeMap {
		if node.ID == uint32(nodeID) {
			for _, intf := range node.NodeInterfaces {
				if intf.IfMeta.VppInternalName == "loop0" {
					delete(vds.LoopMACMap, intf.If.PhysAddress)
					for _, ip := range intf.If.IPAddresses {
						delete(vds.LoopIPMap, ip)
					}
				}
			}

			delete(vds.NodeMap, node.Name)
			delete(vds.GigEIPMap, node.IPAddr)

			return nil
		}
	}

	return fmt.Errorf("node %s does not exist", nodeName)
}

//RetrieveAllNodes returns an ordered slice of all nodes in a database organized by name.
func (vds *VppDataStore) RetrieveAllNodes() []*telemetrymodel.Node {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	var str []string
	for k := range vds.NodeMap {
		str = append(str, k)
	}

	var nList []*telemetrymodel.Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := vds.retrieveNode(v)
		nList = append(nList, n)
	}

	return nList
}

// UpdateNode handles updates of node data in the cache. If the node identified
// by 'nodeName' exists, its data is updated and nil error is returned.
// otherwise, an error is returned.
func (vds *VppDataStore) UpdateNode(ID uint32, nodeName, IPAddr string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.NodeMap[nodeName]

	if !ok {
		return errors.Errorf("Node with name %+vds not found in vpp cache", nodeName)
	}
	node.IPAddr = IPAddr
	node.ID = ID

	if IPAddr != "" {
		ipa := strings.Split(IPAddr, "/")
		vds.GigEIPMap[ipa[0]] = node
	}

	return nil
}

//ClearCache with clear all vpp cache data except for the base NodeMap that contains
// the discovered nodes..
func (vds *VppDataStore) ClearCache() {

	// Clear collected data for each node
	for _, node := range vds.NodeMap {
		node.NodeInterfaces = nil
		node.NodeBridgeDomains = nil
		node.NodeL2Fibs = nil
		node.NodeLiveness = nil
		node.NodeTelemetry = nil
		node.NodeIPArp = nil
	}

	// Clear secondary index maps
	vds.LoopMACMap = make(map[string]*telemetrymodel.Node)
	vds.LoopIPMap = make(map[string]*telemetrymodel.Node)
	vds.HostIPMap = make(map[string]*telemetrymodel.Node)
}

// ReinitializeCache completely re-initializes the cache, clearing all
// data including  the discovered nodes.
func (vds *VppDataStore) ReinitializeCache() {
	vds.ClearCache()
	vds.NodeMap = make(map[string]*telemetrymodel.Node)
}

// DumpCache prints basic cache information to the console. The intended
// use of this function is debugging.
func (vds *VppDataStore) DumpCache() {
	fmt.Printf("NodeMap: %+v\n", vds.NodeMap)
	fmt.Printf("LoopMACMap: %+v\n", vds.LoopMACMap)
	fmt.Printf("GigEIPMap: %+v\n", vds.GigEIPMap)
	fmt.Printf("HostIPMap: %+v\n", vds.HostIPMap)
	fmt.Printf("LoopIPMap: %+v\n", vds.LoopIPMap)
}

// NewVppDataStore returns a reference to a new Vpp data store
func NewVppDataStore() (n *VppDataStore) {
	return &VppDataStore{
		lock:       &sync.Mutex{},
		NodeMap:    make(map[string]*telemetrymodel.Node),
		LoopIPMap:  make(map[string]*telemetrymodel.Node),
		GigEIPMap:  make(map[string]*telemetrymodel.Node),
		LoopMACMap: make(map[string]*telemetrymodel.Node),
		HostIPMap:  make(map[string]*telemetrymodel.Node),
	}
}

// SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (vds *VppDataStore) SetNodeLiveness(nodeName string, nLive *telemetrymodel.NodeLiveness) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeLiveness for node %s", nodeName)
	}
	node.NodeLiveness = nLive
	return nil
}

// SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (vds *VppDataStore) SetNodeInterfaces(nodeName string, nInt map[int]telemetrymodel.NodeInterface) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeInterfaces for node %s", nodeName)
	}
	node.NodeInterfaces = nInt
	return nil
}

// SetLinuxInterfaces is a simple function to set a nodes interface given its name.
func (vds *VppDataStore) SetLinuxInterfaces(nodeName string, nInt telemetrymodel.LinuxInterfaces) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeInterfaces for node %s", nodeName)
	}
	node.LinuxInterfaces = nInt
	return nil
}

//SetNodeStaticRoutes is a simple function to set a nodes static routes given its name.
func (vds *VppDataStore) SetNodeStaticRoutes(nodeName string, nSrs []telemetrymodel.NodeIPRoute) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeStaticRoutes for node %s", nodeName)
	}
	node.NodeStaticRoutes = nSrs
	return nil
}

// SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (vds *VppDataStore) SetNodeBridgeDomain(nodeName string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeBridgeDomains for node %s", nodeName)
	}
	node.NodeBridgeDomains = nBridge
	return nil
}

// SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (vds *VppDataStore) SetNodeL2Fibs(nodeName string, nL2F map[string]telemetrymodel.NodeL2FibEntry) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeL2Fibs for node %s", nodeName)
	}
	node.NodeL2Fibs = nL2F
	return nil
}

// SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (vds *VppDataStore) SetNodeTelemetry(nodeName string, nTele map[string]telemetrymodel.NodeTelemetry) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeTelemetry for node %s", nodeName)
	}
	node.NodeTelemetry = nTele
	return nil
}

// SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (vds *VppDataStore) SetNodeIPARPs(nodeName string, nArps []telemetrymodel.NodeIPArpEntry) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeIPArp for node %s", nodeName)
	}
	node.NodeIPArp = nArps
	return nil

}

// SetNodeIPam is a simple function to set the node with the given node name's ipam
func (vds *VppDataStore) SetNodeIPam(nodeName string, nIPam telemetrymodel.IPamEntry) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeIPam for node %s", nodeName)
	}
	node.NodeIPam = &nIPam
	return nil

}

// SetSecondaryNodeIndices populates many of needed node maps for processing
// once all of the information has been retrieved. It also checks to make
// sure that there are no duplicate addresses within the map.
func (vds *VppDataStore) SetSecondaryNodeIndices(node *telemetrymodel.Node) []string {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	// Clear all the date before creating / recreating the maps
	errReport := make([]string, 0)

	loopIF, err := GetNodeLoopIFInfo(node)
	if err != nil {
		errReport = append(errReport, fmt.Sprintf("node %s does not have a loop interface", node.Name))
		return errReport
	}

	if nIP, ok := vds.HostIPMap[node.ManIPAddr]; ok {
		errReport = append(errReport,
			fmt.Sprintf("duplicate Host IP Address %s, hosts %s, %s", node.ManIPAddr, nIP.Name, node.Name))
	} else {
		if node.ManIPAddr != "" {
			vds.HostIPMap[node.ManIPAddr] = node
		}
	}

	for _, ipAddr := range loopIF.If.IPAddresses {
		if ipAddr == "" {
			errReport = append(errReport, fmt.Sprintf("empty IP address for Loop if %s", loopIF.If.Name))
		} else {
			if _, ok := vds.LoopIPMap[ipAddr]; ok {
				errReport = append(errReport,
					fmt.Sprintf("duplicate Loop IP Address %s, interface %s", ipAddr, loopIF.If.Name))
			} else {
				vds.LoopIPMap[ipAddr] = node
			}
		}
	}

	if loopIF.If.PhysAddress == "" {
		errReport = append(errReport, fmt.Sprintf("empty MAC address for Loop if %s", loopIF.If.Name))
	} else {
		if _, ok := vds.LoopMACMap[loopIF.If.PhysAddress]; ok {
			errReport = append(errReport,
				fmt.Sprintf("duplicate Loop MAC Address %s, interface %s", loopIF.If.PhysAddress, loopIF.If.Name))
		} else {
			vds.LoopMACMap[loopIF.If.PhysAddress] = node
		}
	}

	return errReport
}

// RetrieveNodeByHostIPAddr returns a reference to node dat for the specified
// management (host) IP address.
func (vds *VppDataStore) RetrieveNodeByHostIPAddr(ipAddr string) (*telemetrymodel.Node, error) {
	if node, ok := vds.HostIPMap[ipAddr]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Host IP address %s not found", ipAddr)
}

// RetrieveNodeByLoopMacAddr returns a reference to node dat for the specified
// loopback Loop0 MAC address.
func (vds *VppDataStore) RetrieveNodeByLoopMacAddr(macAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.LoopMACMap[macAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Loop MAC address %s not found", macAddress)
}

// RetrieveNodeByLoopIPAddr returns a reference to node dat for the specified
// loopback Loop0 IP address.
func (vds *VppDataStore) RetrieveNodeByLoopIPAddr(ipAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.LoopIPMap[ipAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Loop IP address %s not found", ipAddress)
}

// RetrieveNodeByGigEIPAddr returns a reference to node dat for the specified
// VPP GigE IP address.
func (vds *VppDataStore) RetrieveNodeByGigEIPAddr(ipAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.GigEIPMap[ipAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for GigE IP address %s not found", ipAddress)
}

// GetNodeLoopIFInfo gets the loop interface for the given node
func GetNodeLoopIFInfo(node *telemetrymodel.Node) (*telemetrymodel.NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.IfMeta.VppInternalName == "loop0" {
			return &ifs, nil
		}
	}
	err := errors.Errorf("loop interface not found %s", node.Name)
	return nil, err
}

// retrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vds *VppDataStore) retrieveNode(key string) (*telemetrymodel.Node, bool) {
	node, ok := vds.NodeMap[key]
	return node, ok
}
