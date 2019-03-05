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

// Contiv-init is the init process of the contiv vswitch POD. It starts VPP and
// contiv-agent processes in the correct order,
// and does the STN (Steal the NIC) pre-configuration on VPP and in the host stack.
//
// In STN case, the order of contiv-init operation is:
//   - read contiv YAML config,
//   - determine interface to be stolen from the config,
//   - request stealing the NIC from the STN Daemon,
//   - start VPP,
//   - pre-configure the stolen interface on VPP,
//   - configure VPP-host connectivity,
//   - connect to ETCD,
//   - persist the VPP and host config in ETCD,
//   - start the contiv-agent.
//
// In non-STN case, contiv init operates as follows:
//   - read contiv YAML config,
//   - start VPP,
//   - start contiv-agent.
//
// In order to request STN of an interface, specify requested Linux interface name
// in StealInterface in the NodeConfig part of the contiv-vpp deployment yaml, e.g.:
//
//      NodeConfig:
//		- NodeName: "ubuntu-1"
//		  StealInterface: "enp0s8"
//
// Also, do not forget to put proper PCI address into the VPP startup config file,
// e.g. in /etc/vpp/contiv-vswitch.conf
//   ...
//   dpdk {
//     dev 0000:00:08.0
//   }
//   ...
//
package main
