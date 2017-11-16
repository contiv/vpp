// Copyright (c) 2017 Cisco and/or its affiliates.
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

package vppdump

import (
	"fmt"
	"os"
	"testing"
)

func TestDumpL2(t *testing.T) {
	// Connect to VPP.
	conn, err := govpp.Connect()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer conn.Disconnect()

	// Create an API channel that will be used in the examples.
	ch, err := conn.NewAPIChannel()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer ch.Close()

	res, err := DumpBridgeDomains(ch)
	fmt.Printf("%+v\n", res)

	res2, err := DumpFIBTableEntries(ch)
	fmt.Printf("%+v\n", res2)
	for _, fib := range res2 {
		fmt.Printf("%+v\n", fib)
	}

	res3, _ := DumpXConnectPairs(ch)
	fmt.Printf("%+v\n", res3)
	for _, xconn := range res3 {
		fmt.Printf("%+v\n", xconn)
	}
}
