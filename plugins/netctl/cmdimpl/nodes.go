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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/netctl/remote"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"io/ioutil"
	"sort"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// PrintNodes will print out all of the cmdimpl in a network in a table format.
func PrintNodes(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd) {
	nodes := make([]string, 0)
	for k := range getClusterNodeInfo(db) {
		nodes = append(nodes, k)
	}
	sort.Strings(nodes)

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNODE-NAME\tVPP-IP\tHOST-IP\tSTART-TIME\tSTATE\tBUILD-VERSION\tBUILD-DATE\n")

	for _, n := range nodes {
		nodeInfo := nodeInfo[n]
		// Get liveness data which contains image version / build date
		bytes, err := getNodeInfo(client, nodeInfo.mgmtIPAddress, "liveness")
		if err != nil {
			fmt.Printf("Could not get liveness data for node '%s'\n", nodeInfo.name)
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
			nodeInfo.id,
			nodeInfo.name,
			strings.Split(nodeInfo.vppIPAddress, "/")[0],
			nodeInfo.mgmtIPAddress,
			time.Unix(int64(liveness.StartTime), 0).Format(timeLayout),
			liveness.State,
			buildVersion,
			buildDate)
	}

	w.Flush()
}

// getNodeInfo will make an http request for the given command and return an indented slice of bytes.
func getNodeInfo(client *remote.HTTPClient, base string, cmd string) ([]byte, error) {
	res, err := client.Get(base, cmd)
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s Get Error: %s", cmd, err.Error())
		fmt.Printf("http get error: %s ", err.Error())
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", cmd, res.Status)
		fmt.Printf("http get error: %s ", err.Error())
		return nil, err
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

// setNodeInfo will make an http json post request to get the vpp cli command output
func setNodeInfo(client *remote.HTTPClient, base string, cmd string, body string) error {
	res, err := client.Post(base, cmd, body)
	defer res.Body.Close()
	if err != nil {
		err := fmt.Errorf("setNodeInfo: url: %s Get Error: %s", cmd, err.Error())
		return err
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("setNodeInfo: url: %s HTTP res.Status: %s", cmd, res.Status)
		return err
	}

	b, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(b))
	return nil

}
