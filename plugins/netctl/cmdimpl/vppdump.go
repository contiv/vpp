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

package cmdimpl

import (
	"encoding/json"
	"fmt"

	"github.com/contiv/vpp/plugins/netctl/remote"
	"github.com/ligato/cn-infra/db/keyval/etcd"
)

// dumpIndex defines index page for kvscheduler Dump REST API to be un-marshalled
// from JSON data.
type dumpIndex struct {
	Descriptors []string
}

// DumpCmd executes the specified vpp dump operation on the specified node.
// if not operation is specified, it finds the available operations on the
// local node and prints them to the console.
func DumpCmd(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd, nodeName string, dumpType string) {

	if nodeName == "" || dumpType == "" {
		b, err := getNodeInfo(client, "", vppDumpCommand(""))
		if err != nil {
			fmt.Println(err)
			return
		}
		index := dumpIndex{}
		err = json.Unmarshal(b, &index)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Command usage: netctl vppdump %s <cmd>:\n", nodeName)
		for num, txt := range index.Descriptors {
			fmt.Printf("cmd %+v: %s\n", num, txt)
		}
		return
	}

	fmt.Printf("vppdump %s %s\n", nodeName, dumpType)
	ipAdr := resolveNodeOrIP(db, nodeName)
	if ipAdr == "" {
		fmt.Printf("Unknown node name %s", nodeName)
		return
	}

	cmd := vppDumpCommand(dumpType)
	b, err := getNodeInfo(client, ipAdr, cmd)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", b)
}

// VppCliCmd sends a VPP debug CLI command to the specified node's VPP Agent
// and prints the output of the command to console.
func VppCliCmd(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd, nodeName string, vppclicmd string) {

	fmt.Printf("vppcli %s %s\n", nodeName, vppclicmd)

	ipAdr := resolveNodeOrIP(db, nodeName)
	cmd := fmt.Sprintf("vpp/command")
	body := fmt.Sprintf("{\"vppclicommand\":\"%s\"}", vppclicmd)
	err := setNodeInfo(client, ipAdr, cmd, body)
	if err != nil {
		fmt.Println(err)
	}
}
