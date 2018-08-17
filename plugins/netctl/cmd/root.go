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

package cmd

import (
	"fmt"
	"github.com/contiv/vpp/plugins/netctl/nodes"
	"github.com/contiv/vpp/plugins/netctl/vppdump"
	"github.com/spf13/cobra"
	"os"
)

var cmdNodes = &cobra.Command{
	Use:   "nodes",
	Short: "Shows available nodes from contiv-ksr",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		nodes.PrintNodes()
	},
}

var cmdVppDump = &cobra.Command{
	Use:   "vppdump nodename ",
	Short: "Print anything to the screen",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]
		if len(args) == 2 {
			vppDumpType := args[1]
			vppdump.VppDumpCmd(nodeName, vppDumpType)
		} else {
			vppdump.VppDumpCmd(nodeName, "")
		}
	},
}

//Execute will execute the command netctlcd
func Execute() {
	var rootCmd = &cobra.Command{Use: "netctl"}
	rootCmd.AddCommand(cmdNodes)
	rootCmd.AddCommand(cmdVppDump)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
