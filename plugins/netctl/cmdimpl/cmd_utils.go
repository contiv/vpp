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
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FindIPForNodeName will find an ip address that corresponds to the passed
// in nodeName
func FindIPForNodeName(nodeName string) string {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Error getting values")
		return ""
	}
	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		//key := kv.GetKey()
		//fmt.Printf("Key: %s, value: %s\n", key, string(buf))
		nodeInfo := &node.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		if nodeInfo.Name == nodeName {
			return nodeInfo.ManagementIpAddress
		}
	}
	db.Close()
	return ""
}

//resolveNodeOrIP will take in an input string which is either a node name
// or string and return the ip for the nodename or simply return the ip
func resolveNodeOrIP(input string) (ipAdr string) {
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	if re.MatchString(input) {
		return input
	}
	ip := FindIPForNodeName(input)
	return ip
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
