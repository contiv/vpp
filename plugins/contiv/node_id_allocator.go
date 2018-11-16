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
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"bytes"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/servicelabel"
	"net"
	"strconv"
	"strings"
)

const (
	maxAttempts = 10
)

var (
	errInvalidKey         = fmt.Errorf("invalid key for nodeID")
	errUnableToAllocateID = fmt.Errorf("unable to allocate unique id for node (max attempt limit reached)")
	errNoIDallocated      = fmt.Errorf("there is no ID allocated for the node")
)

// idAllocator manages allocation/deallocation of unique number identifying a node in the k8s cluster.
// Retrieved identifier is used as input of IPAM module for the node.
// (AllocatedID is represented by an entry in ETCD. The process of allocation leverages etcd transaction
// to atomically check if the key exists and if not, a new key-value pair representing
// the allocation is inserted)
type idAllocator struct {
	sync.Mutex
	etcd   *etcd.Plugin
	broker keyval.ProtoBroker

	allocated bool
	ID        uint32

	nodeName string
	nodeIP   *net.IPNet

	// ip used by k8s to access node
	managementIP string
}

// newIDAllocator creates new instance of idAllocator
func newIDAllocator(etcd *etcd.Plugin, nodeName string, nodeIP *net.IPNet) *idAllocator {
	return &idAllocator{
		etcd:     etcd,
		broker:   etcd.NewBroker(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)),
		nodeName: nodeName,
		nodeIP:   nodeIP,
	}
}

// getID returns unique number for the given node
func (ia *idAllocator) getID() (id uint32, err error) {
	ia.Lock()
	defer ia.Unlock()

	if ia.allocated {
		return ia.ID, nil
	}

	// check if there is already assign ID for the serviceLabel
	existingEntry, err := ia.findExistingEntry(ia.broker)
	if err != nil {
		return 0, err
	}

	if existingEntry != nil {
		ia.allocated = true
		ia.ID = existingEntry.Id
		return ia.ID, nil
	}

	attempts := 0
	for {
		ids, err := listAllIDs(ia.broker)
		if err != nil {
			return 0, err
		}
		sort.Ints(ids)

		attempts++
		ia.ID = uint32(findFirstAvailableIndex(ids))

		succ, err := ia.writeIfNotExists(ia.ID)
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

	return ia.ID, nil
}

func (ia *idAllocator) updateIP(newIP *net.IPNet) error {
	return ia.updateEtcdEntry(newIP, ia.managementIP)
}

func (ia *idAllocator) updateManagementIP(newMgmtIP string) error {
	return ia.updateEtcdEntry(ia.nodeIP, newMgmtIP)
}

func (ia *idAllocator) updateEtcdEntry(newIP *net.IPNet, newManagementIP string) error {
	// make sure that ID is allocated
	_, err := ia.getID()
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
	if equalNodeIP && ia.managementIP == newManagementIP {
		return nil
	}

	ia.nodeIP = newIP
	ia.managementIP = newManagementIP

	value := &node.NodeInfo{
		Id:                  ia.ID,
		Name:                ia.nodeName,
		IpAddress:           ipNetToString(ia.nodeIP),
		ManagementIpAddress: ia.managementIP,
	}
	err = ia.broker.Put(createKey(ia.ID), value)

	return err

}

// releaseID returns allocated ID back to the pool
func (ia *idAllocator) releaseID() error {
	ia.Lock()
	defer ia.Unlock()

	if !ia.allocated {
		return errNoIDallocated
	}

	_, err := ia.broker.Delete(createKey(ia.ID))
	if err == nil {
		ia.allocated = false
	}

	return err
}

func (ia *idAllocator) writeIfNotExists(id uint32) (succeeded bool, err error) {

	value := &node.NodeInfo{
		Id:        id,
		Name:      ia.nodeName,
		IpAddress: ipNetToString(ia.nodeIP),
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return false, err
	}

	succeeded, err = ia.etcd.PutIfNotExists(servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)+createKey(id), encoded)

	return succeeded, err

}

// findExistingEntry lists all allocated entries and checks if the etcd contains ID assigned
// to the serviceLabel
func (ia *idAllocator) findExistingEntry(broker keyval.ProtoBroker) (id *node.NodeInfo, err error) {
	var existingEntry *node.NodeInfo
	it, err := broker.ListValues(node.AllocatedIDsKeyPrefix)
	if err != nil {
		return nil, err
	}

	for {
		item := &node.NodeInfo{}
		kv, stop := it.GetNext()

		if stop {
			break
		}

		err := kv.GetValue(item)
		if err != nil {
			return nil, err
		}

		if item.Name == ia.nodeName {
			existingEntry = item
			break
		}
	}

	return existingEntry, nil

}

// findFirstAvailableIndex returns the smallest int that is not assigned to a node
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

// listAllIDs returns slice that contains allocated ids i.e.: ids assigned to a node
func listAllIDs(broker keyval.ProtoBroker) (ids []int, err error) {
	it, err := broker.ListKeys(node.AllocatedIDsKeyPrefix)
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
	if strings.HasPrefix(key, node.AllocatedIDsKeyPrefix) {
		return strconv.Atoi(strings.Replace(key, node.AllocatedIDsKeyPrefix, "", 1))

	}
	return 0, errInvalidKey
}

func createKey(index uint32) string {
	str := strconv.FormatUint(uint64(index), 10)
	return node.AllocatedIDsKeyPrefix + str
}
