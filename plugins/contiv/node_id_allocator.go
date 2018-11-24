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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contiv/model/nodeinfo"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ksr"
)

const (
	maxAttempts = 10
)

var (
	errOutOfSync          = fmt.Errorf("resync must be called first")
	errNoConnection       = fmt.Errorf("database is not connected")
	errInvalidKey         = fmt.Errorf("invalid key for nodeID")
	errUnableToAllocateID = fmt.Errorf("unable to allocate unique id for node (max attempt limit reached)")
	errNoIDallocated      = fmt.Errorf("there is no ID allocated for the node")
)

// NodeIDAllocator describes interface of the allocator for node IDs.
type NodeIDAllocator interface {
	// Resync re-synchronizes the node allocator against a snapshot of Kubernetes state data.
	// Should be called with startup resync before accessing any other method.
	Resync(kubeState controller.KubeStateData)

	// GetOrAllocateNodeID allocates or returns already allocated unique number for the given node.
	// Beware: Resync() has to be called first.
	GetOrAllocateNodeID() (id uint32, err error)

	// ReleaseID returns allocated ID back to the pool.
	ReleaseID() error

	// UpdateIP informs allocator about a change of the node main IP address.
	// The allocator will publish this change to other nodes.
	UpdateIP(newIP *net.IPNet) error

	// UpdateManagementIP informs allocator about a change of a node management IP address.
	// The allocator will publish this change to other nodes.
	// TODO: get rid of management IP
	UpdateManagementIP(newMgmtIP string) error
}

// DB lists methods used by NodeIDAllocator for database access.
type DB interface {
	OnConnect(callback func() error)
	NewBroker(prefix string) keyval.ProtoBroker
	PutIfNotExists(key string, value []byte) (succeeded bool, err error)
	Close() error
}

// nodeIDAllocator manages (de)allocation of unique number identifying a node in
// the k8s cluster.
// The process of allocation leverages atomic Put operation.
// TODO: better description
type nodeIDAllocator struct {
	sync.Mutex
	inSync bool

	db            DB
	dbIsConnected bool

	allocated bool
	nodeID    uint32

	nodeName   string
	nodeIP     *net.IPNet
	nodeMgmtIP string
}

// NewIDAllocator creates new instance of nodeIDAllocator
func NewIDAllocator(db DB, nodeName string, nodeIP *net.IPNet) NodeIDAllocator {
	allocator := &nodeIDAllocator{
		db:       db,
		nodeName: nodeName,
		nodeIP:   nodeIP,
	}
	if db != nil {
		db.OnConnect(allocator.onDBConnect)
	}
	return allocator
}

// Resync re-synchronizes the node allocator against a snapshot of Kubernetes state data.
// Should be called with startup resync before accessing any other method.
func (ia *nodeIDAllocator) Resync(kubeState controller.KubeStateData) {
	ia.Lock()
	defer ia.Unlock()

	ia.allocated = false
	for _, value := range kubeState[nodeinfo.Keyword] {
		info := value.(*nodeinfo.NodeInfo)
		if info.Name == ia.nodeName {
			ia.allocated = true
			ia.nodeID = info.Id
		}
	}
	ia.inSync = true
}

// GetOrAllocateNodeID allocates or returns already allocated unique number for the given node.
// Beware: Resync() has to be called first.
func (ia *nodeIDAllocator) GetOrAllocateNodeID() (id uint32, err error) {
	ia.Lock()
	defer ia.Unlock()

	if ia.inSync == false {
		return 0, errOutOfSync
	}

	if ia.allocated {
		return ia.nodeID, nil
	}

	if !ia.dbIsConnected {
		return 0, errNoConnection
	}

	attempts := 0
	broker := ia.newBroker()
	for {
		ids, err := listAllIDs(broker)
		if err != nil {
			return 0, err
		}
		sort.Ints(ids)

		attempts++
		ia.nodeID = uint32(findFirstAvailableIndex(ids))

		succ, err := ia.writeIfNotExists(ia.nodeID)
		if err != nil {
			return 0, err
		}
		if succ {
			ia.allocated = true
			break
		}

		if attempts > maxAttempts {
			return 0, errUnableToAllocateID
		}
	}

	return ia.nodeID, nil
}

// ReleaseID returns allocated ID back to the pool.
func (ia *nodeIDAllocator) ReleaseID() error {
	ia.Lock()
	defer ia.Unlock()

	if ia.inSync == false {
		return errOutOfSync
	}

	if !ia.allocated {
		return errNoIDallocated
	}

	if !ia.dbIsConnected {
		return errNoConnection
	}

	broker := ia.newBroker()
	_, err := broker.Delete(nodeinfo.Key(ia.nodeID))
	if err == nil {
		ia.allocated = false
	}

	return err
}

// UpdateIP informs allocator about a change of the node main IP address.
// The allocator will publish this change to other nodes.
func (ia *nodeIDAllocator) UpdateIP(newIP *net.IPNet) error {
	return ia.updateDBEntry(newIP, ia.nodeMgmtIP)
}

// UpdateManagementIP informs allocator about a change of a node management IP address.
// The allocator will publish this change to other nodes.
// TODO: get rid of management IP
func (ia *nodeIDAllocator) UpdateManagementIP(newMgmtIP string) error {
	return ia.updateDBEntry(ia.nodeIP, newMgmtIP)
}

// updateDBEntry updates the key-value entry that represents this node ID.
func (ia *nodeIDAllocator) updateDBEntry(newIP *net.IPNet, newManagementIP string) error {
	// make sure that ID is allocated
	_, err := ia.GetOrAllocateNodeID()
	if err != nil {
		return err
	}

	ia.Lock()
	defer ia.Unlock()

	// check if anything has actually changed
	var equalNodeIP bool
	if ia.nodeIP == nil || newIP == nil {
		equalNodeIP = ia.nodeIP == newIP
	} else {
		equalNodeIP = ia.nodeIP.IP.Equal(newIP.IP) && bytes.Equal(ia.nodeIP.Mask, newIP.Mask)
	}
	if equalNodeIP && ia.nodeMgmtIP == newManagementIP {
		return nil
	}

	// db connection is required to update the entry
	if !ia.dbIsConnected {
		return errNoConnection
	}

	// update internal state
	ia.nodeIP = newIP
	ia.nodeMgmtIP = newManagementIP

	// update DB entry representing this node
	value := &nodeinfo.NodeInfo{
		Id:                  ia.nodeID,
		Name:                ia.nodeName,
		IpAddress:           ipNetToString(ia.nodeIP),
		ManagementIpAddress: ia.nodeMgmtIP,
	}
	broker := ia.newBroker()
	return broker.Put(nodeinfo.Key(ia.nodeID), value)
}

// writeIfNotExists tries to allocate given ID for this node.
func (ia *nodeIDAllocator) writeIfNotExists(id uint32) (succeeded bool, err error) {
	value := &nodeinfo.NodeInfo{
		Id:                  id,
		Name:                ia.nodeName,
		IpAddress:           ipNetToString(ia.nodeIP),
		ManagementIpAddress: ia.nodeMgmtIP,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
	return ia.db.PutIfNotExists(ksrPrefix+nodeinfo.Key(id), encoded)
}

// onDBConnect is triggered once connection to DB is available.
func (ia *nodeIDAllocator) onDBConnect() error {
	ia.Lock()
	ia.Unlock()
	ia.dbIsConnected = true
	return nil
}

// newBroker creates a new broker for DB access.
func (ia *nodeIDAllocator) newBroker() keyval.ProtoBroker {
	return ia.db.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
}

// findFirstAvailableIndex returns the smallest int that is not assigned to any node.
func findFirstAvailableIndex(ids []int) int {
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

// listAllIDs returns a slice of already allocated node IDs.
func listAllIDs(broker keyval.ProtoBroker) (ids []int, err error) {
	it, err := broker.ListKeys(nodeinfo.AllocatedIDsKeyPrefix)
	if err != nil {
		return nil, err
	}

	for {
		key, _, stop := it.GetNext()
		if stop {
			break
		}

		id, err := extractIndexFromKey(key)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil

}

func extractIndexFromKey(key string) (int, error) {
	if strings.HasPrefix(key, nodeinfo.AllocatedIDsKeyPrefix) {
		return strconv.Atoi(strings.Replace(key, nodeinfo.AllocatedIDsKeyPrefix, "", 1))

	}
	return 0, errInvalidKey
}
