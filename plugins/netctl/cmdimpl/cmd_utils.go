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
//

package cmdimpl

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/nodesync/vppnode"
)

type clusterNodeInfo map[string]*oneNodeInfo

type oneNodeInfo struct {
	id            uint32
	name          string
	mgmtIPAddress string
	vppIPAddress  string
}

var (
	nodeInfo clusterNodeInfo
	ipAddrRe = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
)

func getClusterNodeInfo(db *etcd.BytesConnectionEtcd) clusterNodeInfo {
	if len(nodeInfo) == 0 {
		nodeInfo = make(clusterNodeInfo, 0)
		ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)

		// read Name, ID and VPP IP address
		itr, err := db.ListValues(ksrPrefix + vppnode.KeyPrefix)
		if err != nil {
			fmt.Println("Failed to discover nodes in Contiv cluster")
			os.Exit(-1)
		}
		for {
			kv, stop := itr.GetNext()
			if stop {
				break
			}
			buf := kv.GetValue()
			vn := &vppnode.VppNode{}
			if err = json.Unmarshal(buf, vn); err != nil {
				fmt.Printf("failed to decode node info for node %s, error %s\n", kv.GetKey(), err)
				continue
			}
			entry := &oneNodeInfo{
				id:   vn.Id,
				name: vn.Name,
			}
			vppIPs := append(vn.IpAddresses, vn.IpAddress)
			if len(vppIPs) > 0 {
				entry.vppIPAddress = vppIPs[0]
			}
			nodeInfo[vn.Name] = entry

		}

		// read management IP addresses
		itr, err = db.ListValues(ksrPrefix + node.KeyPrefix())
		if err != nil {
			fmt.Println("Failed to read management IP addresses of nodes in Contiv cluster")
			os.Exit(-1)
		}
		for {
			kv, stop := itr.GetNext()
			if stop {
				break
			}
			buf := kv.GetValue()
			ni := &node.Node{}
			if err = json.Unmarshal(buf, ni); err != nil {
				fmt.Printf("failed to decode k8s data for node %s, error %s\n", kv.GetKey(), err)
				continue
			}
			if entry, hasEntry := nodeInfo[ni.Name]; hasEntry {
				var mgmtAddr string
				for _, address := range ni.Addresses {
					if address.Type == node.NodeAddress_NodeInternalIP ||
						address.Type == node.NodeAddress_NodeExternalIP {
						mgmtAddr = address.Address
						break
					}
				}
				entry.mgmtIPAddress = mgmtAddr
			}
		}
	}

	return nodeInfo
}

//resolveNodeOrIP will take in an input string which is either a node name
// or string and return the ip for the nodename or simply return the ip
func resolveNodeOrIP(db *etcd.BytesConnectionEtcd, nodeName string) (ipAdr string) {
	if ipAddrRe.MatchString(nodeName) {
		return nodeName
	}

	for k, v := range getClusterNodeInfo(db) {
		if k == nodeName {
			return v.mgmtIPAddress
		}
	}

	return ""
}

// maskLength2Mask will tank in an int and return the bit mask for the
// number given
func maskLength2Mask(ml int) uint32 {
	var mask uint32
	for i := 0; i < 32-ml; i++ {
		mask = mask << 1
		mask++
	}
	return mask
}

func ip2uint32(ipAddress string) (uint32, error) {
	var ipu uint32
	parts := strings.Split(ipAddress, ".")
	for _, p := range parts {
		// num, _ := strconv.ParseUint(p, 10, 32)
		num, _ := strconv.Atoi(p)
		ipu = (ipu << 8) + uint32(num)
		//fmt.Printf("%d: num: 0x%x, ipu: 0x%x\n", i, num, ipu)
	}
	return ipu, nil
}

func getIPAddressAndMask(ip string) (uint32, uint32, error) {
	addressParts := strings.Split(ip, "/")
	if len(addressParts) != 2 {
		return 0, 0, fmt.Errorf("invalid address")
	}

	maskLen, err := strconv.Atoi(addressParts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid mask")
	}

	address, err := ip2uint32(addressParts[0])
	if err != nil {
		return 0, 0, err
	}
	mask := maskLength2Mask(maskLen)

	return address, mask, nil
}
