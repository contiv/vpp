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

package main

import (
	"flag"

	"github.com/contiv/vpp/flavors/crd"
	"github.com/ligato/cn-infra/core"
)

const (
	defaultEtcdCfgFile = "/etc/etcd/etcd.conf"
)

var (
	etcdCfgFile = flag.String("etcd-config", defaultEtcdCfgFile, "location of the ETCD config file")
)

// contiv-ksr main entry point.
func main() {
	// contiv-ksr is a CN-infra based agent.
	agentVar := crd.NewAgent()
	core.EventLoopWithInterrupt(agentVar, nil)
}
