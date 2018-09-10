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
	"text/tabwriter"
)

//NodeIPamCmd prints out the ipam information of a specific node
func NodeIPamCmd(nodeName string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tNODE-IP\tPOD-NET-IP\tVPP-HOST-IP\tPOD-IFIP-CIDR\tPOD-SUBNET-CIDR\n")

	ip := resolveNodeOrIP(nodeName)
	b := http.GetNodeInfo(ip, "contiv/v1/ipam")
	ipam := telemetrymodel.IPamEntry{}
	err := json.Unmarshal(b, &ipam)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
		ipam.NodeID,
		ipam.NodeName,
		ipam.NodeIP,
		ipam.PodNetwork,
		ipam.VppHostNetwork,
		ipam.Config.PodIfIPCIDR,
		ipam.Config.PodSubnetCIRDR)

	w.Flush()
}
