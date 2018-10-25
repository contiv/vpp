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
	"sort"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/netctl/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

//PrintNodes will print out all of the cmdimpl in a network in a table format.
func PrintNodes() {
	nodes := make([]string, 0)
	for k := range getClusterNodeInfo() {
		nodes = append(nodes, k)
	}
	sort.Strings(nodes)

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tVPP-IP\tHOST-IP\tSTART-TIME\tSTATE\tBUILD-VERSION\tBUILD-DATE\n")

	for _, n := range nodes {
		nodeInfo := nodeInfo[n]
		// Get liveness data which contains image version / build date
		bytes, err := http.GetNodeInfo(nodeInfo.ManagementIpAddress, "liveness")
		if err != nil {
			fmt.Printf("Could not get liveness data for node '%s'\n", nodeInfo.Name)
			return
		}

		// Reformat the image build date to the common format
		buildDate := "Not Available"
		buildVersion := "Not Available"
		var liveness telemetrymodel.NodeLiveness
		if err = json.Unmarshal(bytes, &liveness); err == nil {
			buildVersion = liveness.BuildVersion
			buildDate = liveness.BuildDate
			bd, err1 := time.Parse("2006-01-02T15:04+00:00", buildDate)
			if err1 == nil {
				buildDate = bd.Format(timeLayout)
			}
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			nodeInfo.Id,
			nodeInfo.Name,
			strings.Split(nodeInfo.IpAddress, "/")[0],
			nodeInfo.ManagementIpAddress,
			time.Unix(int64(liveness.StartTime), 0).Format(timeLayout),
			liveness.State,
			buildVersion,
			buildDate)
	}

	w.Flush()
}
