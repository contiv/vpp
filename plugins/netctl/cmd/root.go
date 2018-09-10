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
	"github.com/contiv/vpp/plugins/netctl/cmdimpl"
	"github.com/spf13/cobra"
	"os"
)

var cmdNodes = &cobra.Command{
	Use:   "nodes",
	Short: "Shows vswitch information for all nodes in the running Contiv cluster.",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		cmdimpl.PrintNodes()
	},
}
var cmdVppDump = &cobra.Command{
	Use:     "vppdump nodename ",
	Short:   "Print anything to the screen",
	Example: "netctl vppdump k8s-master",
	Args:    cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]
		if len(args) == 2 {
			vppDumpType := args[1]
			cmdimpl.DumpCmd(nodeName, vppDumpType)
		} else {
			cmdimpl.DumpCmd(nodeName, "")
		}
	},
}

var cmdVppCLI = &cobra.Command{
	Use:     "vppcli nodename vpp-cli-command",
	Short:   "Execute the specified VPP debug CLI command on the specified node.",
	Example: "netctl vppcli k8s-master sh int addr",
	Args:    cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]
		if len(args) >= 2 {
			vppCliCmd := ""
			for _, str := range args[1:] {
				vppCliCmd += str + " "
			}
			cmdimpl.VppCliCmd(nodeName, vppCliCmd)
		} else if nodeName == "" {
			fmt.Println("Enter a node name for vppcli: vppcli <nodeName> <cli_cmd>")
		} else {
			fmt.Println("Enter a Vpp CLI Command...")
		}
	},
}

var cmdNodeIPam = &cobra.Command{
	Use:     "ipam <nodename>",
	Short:   "Shows IPAM information for specified node.",
	Example: "netctl ipam k8s-master",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]
		if len(args) < 1 {
			fmt.Println("\nEnter either a node name or an ip to display IPam information...")
		} else {
			cmdimpl.NodeIPamCmd(nodeName)
		}
	},
}

var cmdPodInfo = &cobra.Command{
	Use: "pods nodename",
	Short: "Display network information for pods connected to VPP on the given node. If node is omitted, " +
		"pod data for all nodes is shown.",
	Example: "netctl pods k8-master\nnetctl pods",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 1 {
			cmdimpl.PrintAllPods()
		} else {
			nodeName := args[0]
			cmdimpl.PrintPodsPerNode(nodeName)
		}

	},
}

//Execute will execute the command netctlcd
func Execute() {
	var rootCmd = &cobra.Command{Use: "netctl"}
	rootCmd.AddCommand(cmdNodes)
	rootCmd.AddCommand(cmdVppDump)
	rootCmd.AddCommand(cmdVppCLI)

	rootCmd.AddCommand(cmdNodeIPam)
	rootCmd.AddCommand(cmdPodInfo)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
