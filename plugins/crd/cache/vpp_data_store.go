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
	"github.com/pkg/errors"
	"sort"
	"sync"
)

// VppCache defines the operations on the VPP node data store.
type VppCache interface {
	CreateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error
	RetrieveNode(nodeName string) (*telemetrymodel.Node, error)
	UpdateNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error
	DeleteNode(nodeName string) error

	RetrieveNodeByHostIPAddr(ipAddr string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopMacAddr(macAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByLoopIPAddr(ipAddress string) (*telemetrymodel.Node, error)
	RetrieveNodeByGigEIPAddr(ipAddress string) (*telemetrymodel.Node, error)

	RetrieveAllNodes() []*telemetrymodel.Node

	SetNodeLiveness(name string, nL *telemetrymodel.NodeLiveness) error
	SetNodeInterfaces(name string, nInt map[int]telemetrymodel.NodeInterface) error
	SetNodeBridgeDomain(name string, nBridge map[int]telemetrymodel.NodeBridgeDomain) error
	SetNodeL2Fibs(name string, nL2f map[string]telemetrymodel.NodeL2FibEntry) error
	SetNodeTelemetry(name string, nTele map[string]telemetrymodel.NodeTelemetry) error
	SetNodeIPARPs(name string, nArps []telemetrymodel.NodeIPArpEntry) error

	SetSecondaryNodeIndices(node *telemetrymodel.Node) []string

	ClearCache()
	ReinitializeCache()
}

// here goes different cache types
//Update this whenever a new DTO type is added.
const numDTOs = 5

//VppDataStore holds various maps which all take different keys but point to the same underlying value.
type VppDataStore struct {
	lock *sync.Mutex

	nMap       map[string]*telemetrymodel.Node
	loopIPMap  map[string]*telemetrymodel.Node
	gigEIPMap  map[string]*telemetrymodel.Node
	loopMACMap map[string]*telemetrymodel.Node
	hostIPMap  map[string]*telemetrymodel.Node
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
	vds.nMap[nodeName] = n
	vds.gigEIPMap[IPAdr] = n

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

// DeleteVppNode handles node deletions from the cache. If the node identified
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
		if intf.VppInternalName == "loop0" {
			delete(vds.loopMACMap, intf.PhysAddress)
			for _, ip := range intf.IPAddresses {
				delete(vds.loopIPMap, ip)
			}
		}
	}

	delete(vds.nMap, node.Name)
	delete(vds.gigEIPMap, node.IPAdr)

	return nil
}

//RetrieveAllNodes returns an ordered slice of all nodes in a database organized by name.
func (vds *VppDataStore) RetrieveAllNodes() []*telemetrymodel.Node {
	vds.lock.Lock()
	defer vds.lock.Unlock()

	var str []string
	for k := range vds.nMap {
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

	node, ok := vds.nMap[nodeName]

	if !ok {
		return errors.Errorf("Node with name %+vds not found in vpp cache", nodeName)
	}
	node.IPAdr = IPAdr
	node.ID = ID
	node.ManIPAdr = ManIPAdr
	return nil
}

//ClearCache with clear all vpp cache data except for the base nMap that contains
// the discovered nodes..
func (vds *VppDataStore) ClearCache() {

	// Clear collected data for each node
	for _, node := range vds.nMap {
		node.NodeInterfaces = nil
		node.NodeBridgeDomains = nil
		node.NodeL2Fibs = nil
		node.NodeLiveness = nil
		node.NodeTelemetry = nil
		node.NodeIPArp = nil
		node.Report = []string{}
	}
	// Clear secondary index maps
	vds.gigEIPMap = make(map[string]*telemetrymodel.Node)
	vds.loopMACMap = make(map[string]*telemetrymodel.Node)
	vds.loopIPMap = make(map[string]*telemetrymodel.Node)
	vds.hostIPMap = make(map[string]*telemetrymodel.Node)
}

// ReinitializeCache completely re-initializes the cache, clearing all
// data including  the discovered nodes.
func (vds *VppDataStore) ReinitializeCache() {
	vds.ClearCache()
	vds.nMap = make(map[string]*telemetrymodel.Node)
}

//NewVppDataStore returns a reference to a new Vpp data store
func NewVppDataStore() (n *VppDataStore) {
	return &VppDataStore{
		lock:       &sync.Mutex{},
		nMap:       make(map[string]*telemetrymodel.Node),
		loopIPMap:  make(map[string]*telemetrymodel.Node),
		gigEIPMap:  make(map[string]*telemetrymodel.Node),
		loopMACMap: make(map[string]*telemetrymodel.Node),
		hostIPMap:  make(map[string]*telemetrymodel.Node),
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

	if nIp, ok := vds.hostIPMap[node.ManIPAdr]; ok {
		errReport = append(errReport,
			fmt.Sprintf("duplicate Host IP Address %s, hosts %s, %s", node.ManIPAdr, nIp.Name, node.Name))
	} else {
		vds.hostIPMap[node.ManIPAdr] = node
	}

	for _, ipAddr := range loopIF.IPAddresses {
		if ipAddr == "" {
			errReport = append(errReport, fmt.Sprintf("empty IP address for Loop if %s", loopIF.Name))
		} else {
			if _, ok := vds.loopIPMap[ipAddr]; ok {
				errReport = append(errReport,
					fmt.Sprintf("duplicate Loop IP Address %s, interfqce %s", ipAddr, loopIF.Name))
			} else {
				vds.loopIPMap[ipAddr] = node
			}
		}
	}

	if loopIF.PhysAddress == "" {
		errReport = append(errReport, fmt.Sprintf("empty MAC address for Loop if %d", loopIF.Name))
	} else {
		if _, ok := vds.loopMACMap[loopIF.PhysAddress]; ok {
			errReport = append(errReport,
				fmt.Sprintf("duplicate Loop MAC Address %s, interface %s", loopIF.PhysAddress, loopIF.Name))
		} else {
			vds.loopMACMap[loopIF.PhysAddress] = node
		}
	}
	vds.gigEIPMap[node.IPAdr] = node
	return errReport
}

// RetrieveNodeByHostIPAddr returns a reference to node dat for the specified
// management (host) IP address.
func (vds *VppDataStore) RetrieveNodeByHostIPAddr(ipAddr string) (*telemetrymodel.Node, error) {
	if node, ok := vds.hostIPMap[ipAddr]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for IP address %s not found", ipAddr)
}

// RetrieveNodeByLoopMacAddr returns a reference to node dat for the specified
// loopback Loop0 MAC address.
func (vds *VppDataStore) RetrieveNodeByLoopMacAddr(macAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.loopMACMap[macAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Loop MAC address %s not found", macAddress)
}

// RetrieveNodeByLoopIPAddr returns a reference to node dat for the specified
// loopback Loop0 IP address.
func (vds *VppDataStore) RetrieveNodeByLoopIPAddr(ipAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.loopIPMap[ipAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Loop MAC address %s not found", ipAddress)
}

// RetrieveNodeByGigEIPAddr returns a reference to node dat for the specified
// VPP GigE IP address.
func (vds *VppDataStore) RetrieveNodeByGigEIPAddr(ipAddress string) (*telemetrymodel.Node, error) {
	if node, ok := vds.gigEIPMap[ipAddress]; ok {
		return node, nil
	}
	return nil, fmt.Errorf("node for Loop MAC address %s not found", ipAddress)
}

// retrieveNode returns a pointer to a node for the given key.
// Returns an error if that key is not found.
func (vds *VppDataStore) retrieveNode(key string) (*telemetrymodel.Node, bool) {
	node, ok := vds.nMap[key]
	return node, ok
}
