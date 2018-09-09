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
	"fmt"
	"github.com/contiv/vpp/plugins/netctl/http"
	"strings"
)

// DumpCmd will receive a nodeName and dumpType and finds the desired
// information from the dumpType for the node.
func DumpCmd(nodeName string, dumpType string) {

	if nodeName == "" || dumpType == "" {
		helpText := http.Crawl("localhost:9999")
		fmt.Printf("Command usage: netctl vppdump %s <cmd>:\n", nodeName)
		for num, txt := range helpText {
			txt = strings.TrimPrefix(txt, "/vpp/dump/v1/")
			fmt.Printf("cmd %+v: %s\n", num, txt)
		}
		return
	}
	fmt.Printf("vppdump %s %s\n", nodeName, dumpType)
	ipAdr := resolveNodeOrIP(nodeName)
	if ipAdr == "" {
		fmt.Printf("Unknown node name %s", nodeName)
		return
	}
	cmd := fmt.Sprintf("vpp/dump/v1/%s", dumpType)
	b := http.GetNodeInfo(ipAdr, cmd)
	fmt.Printf("%s", b)
}

// VppCliCmd will receive a nodeName and a vpp cli command and print it out
// to the console
func VppCliCmd(nodeName string, vppclicmd string) {

	fmt.Printf("vppcli %s %s\n", nodeName, vppclicmd)

	ipAdr := resolveNodeOrIP(nodeName)
	cmd := fmt.Sprintf("vpp/command")
	body := fmt.Sprintf("{\"vppclicommand\":\"%s\"}", vppclicmd)
	err := http.SetNodeInfo(ipAdr, cmd, body)
	if err != nil {
		fmt.Println(err)
	}

}
