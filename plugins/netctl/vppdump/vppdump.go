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

package vppdump

import (
	"fmt"
	"github.com/contiv/vpp/plugins/netctl/http"
)

func VppDumpCmd(nodeName string, dumpType string) {
	fmt.Printf("vppdump %s %s\n", nodeName, dumpType)

	switch dumpType {
	case "interfaces":
		b := http.GetNodeInfo(nodeName, "vpp/dump/v1/interfaces")
		fmt.Printf("%s\n", b)
	case "bridgedomains":
		b := http.GetNodeInfo(nodeName, "vpp/dump/v1/bd")
		fmt.Printf("%s\n", b)
		
	default:
		fmt.Printf("Unknown command: %s",dumpType)
	}

}
