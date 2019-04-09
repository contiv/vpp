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
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ligato/cn-infra/db/keyval/etcd"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ipnet"
	ipnetapi "github.com/contiv/vpp/plugins/ipnet/api"
	"github.com/contiv/vpp/plugins/netctl/remote"
	vppifdescr "github.com/ligato/vpp-agent/plugins/vpp/ifplugin/descriptor"
)

// PrintAllIpams prints IPAM information for all nodes
func PrintAllIpams(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd) {
	nodes := make([]string, 0)
	for k := range getClusterNodeInfo(db) {
		nodes = append(nodes, k)
	}
	sort.Strings(nodes)

	w := getTabWriterAndPrintHeader()
	for _, n := range nodes {
		nodeIpamCmd(client, db, w, n)
	}
	w.Flush()
}

// NodeIPamCmd prints out the ipam information of a specific node
func NodeIPamCmd(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd, nodeName string) {
	w := getTabWriterAndPrintHeader()
	nodeIpamCmd(client, db, w, nodeName)
	w.Flush()
}

func nodeIpamCmd(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd, w *tabwriter.Writer, nodeName string) {
	ip := resolveNodeOrIP(db, nodeName)

	b, err := getNodeInfo(client, ip, getIpamDataCmd)
	if err != nil {
		fmt.Println(err)
		return
	}

	ipam := ipnetapi.NodeIPAMInfo{}
	err = json.Unmarshal(b, &ipam)
	if err != nil {
		fmt.Println(err)
		return
	}

	bviIP := "Not Available"
	ifaceDumpCmd := vppDumpCommand(vppifdescr.InterfaceDescriptorName)
	if b, err = getNodeInfo(client, ip, ifaceDumpCmd); err == nil {
		intfs := make(telemetrymodel.NodeInterfaces, 0)
		if err := json.Unmarshal(b, &intfs); err == nil {
			for _, ifc := range intfs {
				if ifc.Value.Name == ipnet.VxlanBVIInterfaceName {
					bviIP = strings.Split(ifc.Value.IpAddresses[0], "/")[0]
				}
			}
		}
	}

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
		ipam.NodeID,
		ipam.NodeName,
		ipam.NodeIP,
		bviIP,
		ipam.PodSubnetThisNode,
		ipam.VppHostNetwork,
		ipam.Config.PodSubnetCIDR)
}

func getTabWriterAndPrintHeader() *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tVPP-IP\tBVI-IP\tPOD-CIDR\tVPP-2-HOST-CIDR\tPOD-CLUSTER-CIDR\n")
	return w
}
