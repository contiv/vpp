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
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/netctl/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// PrintAllIpams prints IPAM information for all nodes
func PrintAllIpams() {
	nodes := make([]string,0)
	for k := range getClusterNodeInfo() {
		nodes = append(nodes, k)
	}
	sort.Strings(nodes)

	w := getTabWriterAndPrintHeader()
	for _, n := range nodes {
		nodeIpamCmd(w, n)
	}
	w.Flush()
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
		ipam.Config.PodSubnetCIDR)
}

func getTabWriterAndPrintHeader() *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tVPP-IP\tBVI-IP\tPOD-NET-CIDR\tVPP-2-HOST-CIDR\tPOD-IFIP-CIDR\tPOD-SUBNET-CIDR\n")
	return w
}
