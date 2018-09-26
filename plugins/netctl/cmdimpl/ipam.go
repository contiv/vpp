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

package cmdimpl

import (
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// PrintAllIpams prints out the ipam information for all the nodes
func PrintAllIpams() {
	etcdCfg := etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{etcdLocation},
		},
		OpTimeout: 1 * time.Second,
	}

	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.ErrorLevel)

	// Create connection to etcd.
	var err error
	var db *etcd.BytesConnectionEtcd
	if db, err = etcd.NewEtcdConnectionWithBytes(etcdCfg, logger); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	itr, err := db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Failed to discover nodes in Contiv cluster")
		return
	}

	w := getTabWriterAndPrintHeader()
	for {
		kv, stop := itr.GetNext()
		if stop {
			fmt.Println()
			break
		}
		buf := kv.GetValue()
		nodeInfo := &node.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		nodeIpamCmd(w, nodeInfo.Name)
	}
	w.Flush()
	db.Close()
}

//NodeIPamCmd prints out the ipam information of a specific node
func NodeIPamCmd(nodeName string) {
	w := getTabWriterAndPrintHeader()
	nodeIpamCmd(w, nodeName)
	w.Flush()
}

func nodeIpamCmd(w *tabwriter.Writer, nodeName string) {
	ip := resolveNodeOrIP(nodeName)

	b, err := http.GetNodeInfo(ip, getIpamDataCmd)
	if err != nil {
		fmt.Println(err)
		return
	}

	ipam := telemetrymodel.IPamEntry{}
	err = json.Unmarshal(b, &ipam)
	if err != nil {
		fmt.Println(err)
		return
	}

	bviIP := "Not Available"
	if b, err = http.GetNodeInfo(ip, getInterfaceDataCmd); err == nil {
		intfs := make(telemetrymodel.NodeInterfaces)
		if err := json.Unmarshal(b, &intfs); err == nil {
			for _, ifc := range intfs {
				if ifc.IfMeta.Tag == "vxlanBVI" {
					bviIP = strings.Split(ifc.If.IPAddresses[0], "/")[0]
				}
			}
		}
	}

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		ipam.NodeID,
		ipam.NodeName,
		ipam.NodeIP,
		bviIP,
		ipam.PodNetwork,
		ipam.VppHostNetwork,
		ipam.Config.PodIfIPCIDR,
		ipam.Config.PodSubnetCIRDR)
}

func getTabWriterAndPrintHeader() *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tVPP-IP\tBVI-IP\tPOD-NET-IP\tVPP-2-HOST-IP\tPOD-IFIP-CIDR\tPOD-SUBNET-CIDR\n")
	return w
}
