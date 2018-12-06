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

//go:generate protoc -I ./vppnode --gogo_out=plugins=grpc:./vppnode ./vppnode/vppnode.proto

package nodesync

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/servicelabel"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ksr"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/nodesync/vppnode"
	"github.com/gogo/protobuf/proto"
	"sync"
)

const (
	// maximum attempts NodeSync will make to allocate node ID.
	maxAllocationAttempts = 10
)

// NodeSync plugin implements synchronization between Kubernetes nodes running
// VPP vswitch using a key-value database (by default etcd). Specifically,
// it allocates the first free positive integer, starting with 1, as a cluster-wide
// node identifier, primarily used for IP allocations for endpoints inside this node
// that will not collide with other nodes.
// Furthermore, NodeSync publishes allocations/changes of the VPP-side of node IP
// address(es) - information that is not known to Kubernetes.
type NodeSync struct {
	Deps

	nodes Nodes // node name -> node info

	thisNode       *Node      // used for quick access to this node info
	thisNodeIDLock sync.Mutex // lock only protects thisNode pointer and thisNode.ID
}

// Deps lists dependencies of NodeSync.
type Deps struct {
	infra.PluginDeps

	ServiceLabel servicelabel.ReaderAPI
	EventLoop    controller.EventLoop
	DB           ClusterWideDB
}

// ClusterWideDB defines API that a DB client must provide for NodeSync to be able
// to allocate node IP and to publish node IPs to other nodes.
type ClusterWideDB interface {
	// OnConnect registers callback to be triggered once the (first) connection
	// to DB is established. If the connection is already established, the callback
	// should be called immediately (synchronously).
	OnConnect(callback func() error)
	// NewBroker creates a new instance of DB broker prefixing all keys with the
	// given prefix.
	NewBroker(prefix string) keyval.ProtoBroker
	// PutIfNotExists atomically puts given key-value pair into DB if there
	// is no value set for the key.
	PutIfNotExists(key string, value []byte) (succeeded bool, err error)
	// Close closes connection to DB and releases all allocated resources.
	Close() error
}

const allocationErrPrefix = "unable to allocate node ID: %v"

// errors thrown by NodeSync (not all of them):
var (
	errMissingDep         = fmt.Errorf("missing mandatory dependency")
	errWithoutDB          = fmt.Errorf(allocationErrPrefix, "database is not provided")
	errNoConnection       = fmt.Errorf(allocationErrPrefix, "database is not connected")
	errAllocLimitExceeded = fmt.Errorf(allocationErrPrefix, "max. attempt limit reached")
)

// Init checks the dependencies.
func (ns *NodeSync) Init() error {
	if ns.ServiceLabel == nil {
		return errMissingDep
	}
	return nil
}

// GetNodeID returns the integer ID allocated for this node.
// The method is thread-safe, but should not be called before the startup resync.
func (ns *NodeSync) GetNodeID() uint32 {
	ns.thisNodeIDLock.Lock()
	defer ns.thisNodeIDLock.Unlock()
	if ns.thisNode == nil {
		return 0
	}
	return ns.thisNode.ID
}

// PublishNodeIPs can be used to publish update about currently assigned
// node IPs of the given IP version on the VPP-side.
// The method is efficient enough that it can be called during every resync
// - only if something has really changed an update will be sent.
// The method should be called only from within the main event loop (not thread
// safe) and not before the startup resync.
func (ns *NodeSync) PublishNodeIPs(addresses []*IPWithNetwork, version IPVersion) error {
	// do not publish if db is not connected
	dbIsConnected := false
	ns.DB.OnConnect(func() error {
		dbIsConnected = true
		return nil
	})
	if !dbIsConnected {
		return errNoConnection
	}

	// build the list of addresses after the update
	var newAddrs []*IPWithNetwork

	// keep addresses of the other IP version intact
	for _, addr := range ns.thisNode.VppIPAddresses {
		var addrVersion IPVersion
		if addr.Address.To4() != nil {
			addrVersion = IPv4
		} else {
			addrVersion = IPv6
		}
		if addrVersion != version {
			newAddrs = append(newAddrs, addr)
		}
	}

	for _, addr := range addresses {
		newAddrs = append(newAddrs, addr)
	}

	if equalAddrsWithNetworks(newAddrs, ns.thisNode.VppIPAddresses) {
		// no change
		return nil
	}

	// update
	ns.thisNode.VppIPAddresses = newAddrs
	vppNode := nodeToProto(ns.thisNode)
	broker := ns.newBroker()
	ns.Log.Infof("Publishing update of node's VPP IP addresses: %s", vppNode.String())
	err := broker.Put(vppnode.Key(ns.thisNode.ID), vppNode)
	if err != nil {
		// error treated as warning - if remote DB is momentarily not available,
		// the list of VPP IP addresses will be refreshed later during run-time
		// resync triggered by connection re-establishment.
		ns.Log.Warnf("Failed to publish node's VPP IP addresses: %v", err)
	}
	return nil
}

// GetAllNodes returns information about all nodes in the cluster.
// Methods should not be called before the startup resync.
// The method should be called only from within the main event loop (not thread
// safe) and not before the startup resync.
func (ns *NodeSync) GetAllNodes() Nodes {
	nodes := make(Nodes)
	for _, node := range ns.nodes {
		if node.ID == 0 {
			continue
		}
		nodes[node.Name] = node
	}
	return ns.nodes
}

// HandlesEvent selects database events - specifically DB entries related to node
// information.
func (ns *NodeSync) HandlesEvent(event controller.Event) bool {
	if _, isDBResync := event.(*controller.DBResync); isDBResync {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case nodemodel.NodeKeyword:
			// interested in the event only if management IP addresses have changed
			return !equalAddresses(
				ns.nodeMgmtAddresses(ksChange.PrevValue),
				ns.nodeMgmtAddresses(ksChange.NewValue))
		case vppnode.Keyword:
			// only interested in VppNode of other nodes
			return ksChange.Key != vppnode.Key(ns.thisNode.ID)
		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	// unhandled event
	return false
}

// Resync during startup phase allocates or retrieves already allocated ID for this node.
// In the runtime, only status of other nodes is re-synchronized.
func (ns *NodeSync) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, _ controller.ResyncOperations) error {

	var err error

	// refresh the internal view of node states
	ns.nodes = make(Nodes)

	// collect IDs and VPP IP addresses
	for _, vppNodeProto := range kubeStateData[vppnode.Keyword] {
		vppNode := vppNodeProto.(*vppnode.VppNode)
		node := &Node{
			ID:   vppNode.Id,
			Name: vppNode.Name,
		}
		node.VppIPAddresses = ns.nodeVPPAddresses(vppNode)
		ns.nodes[node.Name] = node
	}

	// collect management IP addresses
	for _, k8sNodeProto := range kubeStateData[nodemodel.NodeKeyword] {
		k8sNode := k8sNodeProto.(*nodemodel.Node)
		if _, hasOtherNode := ns.nodes[k8sNode.Name]; !hasOtherNode {
			ns.nodes[k8sNode.Name] = &Node{Name: k8sNode.Name}
		}
		node := ns.nodes[k8sNode.Name]
		node.MgmtIPAddresses = ns.nodeMgmtAddresses(k8sNode)
	}

	// allocate ID for this node if it is not already
	nodeName := ns.ServiceLabel.GetAgentLabel()
	if _, hasThisNode := ns.nodes[nodeName]; !hasThisNode {
		// ID not yet known (update may come later)
		ns.nodes[nodeName] = &Node{Name: nodeName}
	}

	ns.thisNodeIDLock.Lock()
	defer ns.thisNodeIDLock.Unlock()
	ns.thisNode = ns.nodes[nodeName]

	if ns.thisNode.ID == 0 {
		err = ns.allocateID()
		if err != nil {
			return controller.NewFatalError(err)
		}
	}

	ns.Log.Infof("ID of the node is %v", ns.thisNode.ID)
	ns.Log.Infof("NodeSync after resync: %s", ns.nodes.String())
	return nil
}

// nodeMgmtAddresses returns a list of node management addresses.
func (ns *NodeSync) nodeMgmtAddresses(nodeProto proto.Message) (addresses []net.IP) {
	if nodeProto == nil {
		return
	}
	node := nodeProto.(*nodemodel.Node)
	for _, mgmtAddr := range node.Addresses {
		if mgmtAddr.Type != nodemodel.NodeAddress_NodeInternalIP &&
			mgmtAddr.Type != nodemodel.NodeAddress_NodeExternalIP {
			// unhandled management IP address
			continue
		}
		mgmtIP := net.ParseIP(mgmtAddr.Address)
		if mgmtIP == nil {
			ns.Log.Warnf("Failed to parse management IP address '%s' of the node '%s': %v",
				mgmtAddr, node.Name)
			continue
		}
		addresses = append(addresses, mgmtIP)
	}
	return addresses
}

// nodeVPPAddresses returns a list of node IP addresses on the VPP side.
func (ns *NodeSync) nodeVPPAddresses(vppNode *vppnode.VppNode) (addresses []*IPWithNetwork) {
	var err error
	vppIPs := append(vppNode.IpAddresses, vppNode.IpAddress) // backward compatibility
	for _, vppIPStr := range vppIPs {
		if vppIPStr == "" {
			continue
		}
		vppIP := &IPWithNetwork{}
		vppIP.Address, vppIP.Network, err = net.ParseCIDR(vppIPStr)
		if err != nil {
			ns.Log.Warnf("Failed to parse IP address '%s' of the node '%s': %v",
				vppIPStr, vppNode.Name, err)
			continue
		}
		addresses = append(addresses, vppIP)
	}
	return addresses
}

// allocateID tries to allocate ID for this node
func (ns *NodeSync) allocateID() error {
	if ns.DB == nil {
		return errWithoutDB
	}

	dbIsConnected := false
	ns.DB.OnConnect(func() error {
		dbIsConnected = true
		return nil
	})
	if !dbIsConnected {
		return errNoConnection
	}

	attempts := 0
	broker := ns.newBroker()
	for {
		ids, err := ns.listAllocatedIDs(broker)
		if err != nil {
			return fmt.Errorf(allocationErrPrefix, err)
		}
		sort.Ints(ids)

		attempts++
		ns.thisNode.ID = uint32(findFirstAvailableID(ids))

		success, err := ns.putIfNotExists(nodeToProto(ns.thisNode))
		if err != nil {
			return fmt.Errorf(allocationErrPrefix, err)
		}
		if success {
			break
		}
		if attempts > maxAllocationAttempts {
			return errAllocLimitExceeded
		}
	}
	return nil
}

// listAllocatedIDs returns a slice of already allocated node IDs.
func (ns *NodeSync) listAllocatedIDs(broker keyval.ProtoBroker) (ids []int, err error) {
	it, err := broker.ListKeys(vppnode.KeyPrefix)
	if err != nil {
		return ids, err
	}

	for {
		key, _, stop := it.GetNext()
		if stop {
			break
		}

		id := vppnode.ParseKey(key)
		if id == 0 {
			ns.Log.Warnf("Invalid VppNode key: %s", key)
			continue
		}
		ids = append(ids, int(id))
	}
	return ids, nil
}

// putIfNotExists tries to allocate the given node ID.
func (ns *NodeSync) putIfNotExists(node *vppnode.VppNode) (succeeded bool, err error) {
	encoded, err := json.Marshal(node)
	if err != nil {
		return false, err
	}
	ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
	return ns.DB.PutIfNotExists(ksrPrefix+vppnode.Key(node.Id), encoded)
}

// newBroker creates a new broker for DB access.
func (ns *NodeSync) newBroker() keyval.ProtoBroker {
	return ns.DB.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
}

// Update is called for KubeStateChange.
func (ns *NodeSync) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	kubeStateChange := event.(*controller.KubeStateChange)

	switch kubeStateChange.Resource {
	case nodemodel.NodeKeyword:
		// update of node management IP addresses
		var prev *Node
		mgmtAddrs := ns.nodeMgmtAddresses(kubeStateChange.NewValue)
		nodeName := strings.TrimPrefix(kubeStateChange.Key, nodemodel.KeyPrefix())
		node, hasOtherNode := ns.nodes[nodeName]
		if !hasOtherNode {
			if len(mgmtAddrs) == 0 {
				// no data for the node
				break
			}
			// ID not yet known (update may come later)
			node = &Node{Name: nodeName}
			ns.nodes[nodeName] = node
		} else {
			prevCopy := *node
			prev = &prevCopy
			if node.ID == 0 && len(mgmtAddrs) == 0 {
				// node left the cluster
				node = nil
				delete(ns.nodes, nodeName)
			}
		}
		if node != nil {
			node.MgmtIPAddresses = mgmtAddrs
			if node.ID != 0 {
				ns.EventLoop.PushEvent(&NodeUpdate{
					NodeName:  nodeName,
					PrevState: prev,
					NewState:  node,
				})
			}
		}

	case vppnode.Keyword:
		// other node update
		var (
			nodeName string
			vppNode  *vppnode.VppNode
			prev     *Node
		)
		if kubeStateChange.NewValue != nil {
			vppNode = kubeStateChange.NewValue.(*vppnode.VppNode)
			nodeName = vppNode.Name
		} else {
			nodeName = kubeStateChange.PrevValue.(*vppnode.VppNode).Name
		}
		node, hasOtherNode := ns.nodes[nodeName]
		if !hasOtherNode {
			if vppNode == nil {
				// no data for the node
				break
			}
			node = &Node{Name: nodeName}
			ns.nodes[nodeName] = node
		} else {
			prevCopy := *node
			prev = &prevCopy
			if vppNode == nil {
				// node left the cluster
				node = nil
				delete(ns.nodes, nodeName)
			}
		}
		if node != nil {
			node.ID = vppNode.Id
			node.VppIPAddresses = ns.nodeVPPAddresses(vppNode)
		}
		ns.EventLoop.PushEvent(&NodeUpdate{
			NodeName:  nodeName,
			PrevState: prev,
			NewState:  node,
		})
	}
	return "", nil
}

// Revert is NOOP - plugin handles only BestEffort events.
func (ns *NodeSync) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP
func (ns *NodeSync) Close() error {
	return nil
}

// nodeToProto converts VPP-related subset of Node data to VppNode proto model.
func nodeToProto(node *Node) *vppnode.VppNode {
	vppNode := &vppnode.VppNode{
		Id:   node.ID,
		Name: node.Name,
	}
	for _, vppIP := range node.VppIPAddresses {
		vppIPNet := &net.IPNet{IP: vppIP.Address, Mask: vppIP.Network.Mask}
		vppNode.IpAddresses = append(vppNode.IpAddresses, vppIPNet.String())
	}

	return vppNode
}

// findFirstAvailableID returns the smallest integer that is not present in the
// given slice of already allocated node IDs.
func findFirstAvailableID(ids []int) int {
	res := 1
	for _, v := range ids {
		if res == v {
			res++
		} else {
			break
		}
	}
	return res
}

// equalAddresses compares two slices of IP addresses.
func equalAddresses(addrs1, addrs2 []net.IP) bool {
	if len(addrs1) != len(addrs2) {
		return false
	}
	for _, addr1 := range addrs1 {
		found := false
		for _, addr2 := range addrs2 {
			if addr1.Equal(addr2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// equalAddrsWithNetworks compares two slices of IP addresses with networks.
func equalAddrsWithNetworks(addrs1, addrs2 []*IPWithNetwork) bool {
	if len(addrs1) != len(addrs2) {
		return false
	}
	for _, addr1 := range addrs1 {
		found := false
		for _, addr2 := range addrs2 {
			if addr1.Address.Equal(addr2.Address) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
