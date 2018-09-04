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

package nodes

import (
	"encoding/json"
	"fmt"
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
	"text/tabwriter"
	"time"
)

//PrintNodes will print out all of the nodes in a network in a table format.
func PrintNodes() {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Error getting values")
		return
	}
	fmt.Fprintf(w, "id\tname\t\tip_address\t\tman_ip_addr\tbuild_date\t\t\tbuild_version\t\tstart_time\tstate\n")
	w.Flush()
	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		//key := kv.GetKey()
		//fmt.Printf("Key: %s, value: %s\n", key, string(buf))
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		//fmt.Printf("NodeInfo: %+v\n", nodeInfo)
		// Do whatever processing we need to do
		bytes := http.GetNodeInfo(nodeInfo.ManagementIpAddress,"liveness")
		var liveness telemetrymodel.NodeLiveness
		err = json.Unmarshal(bytes,&liveness)
		if err != nil {
			fmt.Println(err)
			liveness.BuildDate = "Not Available"
		}

		fmt.Fprintf(w, "%+v\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			nodeInfo.Id,
			nodeInfo.Name,
			nodeInfo.IpAddress,
			nodeInfo.ManagementIpAddress,
			liveness.BuildDate,
			liveness.BuildVersion,
			liveness.StartTime,
			liveness.State)

		w.Flush()
	}
	db.Close()
}

//FindIPForNodeName will find an ip address that corresponds to the passed in nodeName
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
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		if nodeInfo.Name == nodeName {
			return nodeInfo.ManagementIpAddress
		}
	}
	db.Close()
	return ""
}
//VppCliCmd will receive a nodeName and a vpp cli command and print it out to the console
func VppCliCmd(nodeName string, vppclicmd string) {


	fmt.Printf("vppcli %s %s\n", nodeName, vppclicmd)
	ipAdr := FindIPForNodeName(nodeName)
	if ipAdr == "" {
		fmt.Printf("Unknown node name %s", nodeName)
		return
	}
	cmd := fmt.Sprintf("vpp/command")
	body := fmt.Sprintf("{\"vppclicommand\":\"%s\"}",vppclicmd)
	err := http.SetNodeInfo(ipAdr,cmd,body)
	if err != nil {
		fmt.Println(err)
	}

}
