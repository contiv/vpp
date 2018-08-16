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
func (vds *VppDataStore) CreateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	if _, ok := vds.retrieveNode(nodeName); ok {
		return fmt.Errorf("node %s already exists", nodeName)
	}

	n := &telemetrymodel.Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}
	n.PodMap = make(map[string]*telemetrymodel.Pod)
	vds.NodeMap[nodeName] = n
	vds.GigEIPMap[IPAdr] = n

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

// DeleteNode handles node deletions from the cache. If the node identified
// by 'nodeName" is present in the cache, it is deleted and nil error is
// returned; otherwise, an error is returned.
func (vds *VppDataStore) DeleteNode(nodeName string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("node %s does not exist", nodeName)
	}

	for _, intf := range node.NodeInterfaces {
		if intf.IfMeta.VppInternalName == "loop0" {
			delete(vds.LoopMACMap, intf.If.PhysAddress)
			for _, ip := range intf.If.IPAddresses {
				delete(vds.LoopIPMap, ip)
			}
		}
	}

	delete(vds.NodeMap, node.Name)
	delete(vds.GigEIPMap, node.IPAdr)

	return nil
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
func (vds *VppDataStore) UpdateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.NodeMap[nodeName]

	if !ok {
		return errors.Errorf("Node with name %+vds not found in vpp cache", nodeName)
	}
	node.IPAdr = IPAdr
	node.ID = ID
	node.ManIPAdr = ManIPAdr
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
		node.Report = []string{}
	}
	// Clear secondary index maps
	vds.GigEIPMap = make(map[string]*telemetrymodel.Node)
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

//NewVppDataStore returns a reference to a new Vpp data store
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

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
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

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
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

//SetNodeStaticRoutes is a simple function to set a nodes static routes given its name.
func (vds *VppDataStore) SetNodeStaticRoutes(nodeName string, nSrs []telemetrymodel.NodeStaticRoute) error {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	node, ok := vds.retrieveNode(nodeName)
	if !ok {
		return fmt.Errorf("failed to set NodeStaticRoutes for node %s", nodeName)
	}
	node.NodeStaticRoutes = nSrs
	return nil
}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
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

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
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

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
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

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
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

// SetSecondaryNodeIndices populates many of needed node maps for processing
// once all of the information has been retrieved. It also checks to make
// sure that there are no duplicate addresses within the map.
func (vds *VppDataStore) SetSecondaryNodeIndices(node *telemetrymodel.Node) []string {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	errReport := make([]string, 0)

	loopIF, err := GetNodeLoopIFInfo(node)
	if err != nil {
		errReport = append(errReport, "node %s does not have a loop interface", node.Name)
		return errReport
	}

	if nIP, ok := vds.HostIPMap[node.ManIPAdr]; ok {
		errReport = append(errReport,
			fmt.Sprintf("duplicate Host IP Address %s, hosts %s, %s", node.ManIPAdr, nIP.Name, node.Name))
	} else {
		vds.HostIPMap[node.ManIPAdr] = node
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
	vds.GigEIPMap[node.IPAdr] = node
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
	err := errors.Errorf("node %s does not have a loop interface", node.Name)
	return nil, err
}

// retrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vds *VppDataStore) retrieveNode(key string) (*telemetrymodel.Node, bool) {
	node, ok := vds.NodeMap[key]
	return node, ok
}
