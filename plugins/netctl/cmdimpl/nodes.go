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
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
	"text/tabwriter"
	"time"
)

//PrintNodes will print out all of the cmdimpl in a network in a table format.
func PrintNodes() {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.FatalLevel)
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logger)
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
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		//fmt.Printf("NodeInfo: %+v\n", nodeInfo)
		// Do whatever processing we need to do
		bytes := http.GetNodeInfo(nodeInfo.ManagementIpAddress, "liveness")
		var liveness telemetrymodel.NodeLiveness
		err = json.Unmarshal(bytes, &liveness)
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
