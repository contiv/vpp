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

// Package ipv4net configures VPP-based IPv4 network connectivity between Kubernetes
// pods and nodes.
//
// TODO: cleanup config
// The plugin is configurable via its config file that can be specified using
// `-contiv-config="<path to config>` argument when running the contiv-agent. This is usually being injected
// into the vswitch POD by a config map inside of the k8s deployment file of the contiv-VPP k8s networking plugin
// (see contiv-agent-cfg ConfigMap in ../../k8s/contiv-vpp.yaml).
//
// Based on the configuration, the plugin can wire PODs in 2 different ways:
//
//
// 1. VETH-based pod-VPP connectivity (default)
//
// Each POD is wired to VPP using a virtual ethernet interface pair, where one end is connected to VPP using AF_PACKET
// interface and the other end is placed into the POD's network namespace:
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |    VETH VPP  |____________|   VETH Host  |
// |          routing            |              |    |       |              |
// |                             +--------------+    |       +--------------+
// |    +------+       +------+                      |
// |    |  AF1 |       | AFn  |                      |
// |    |      |  ...  |      |                      |
// |    +------+       +------+                      |
// |      ^                                          |
// |      |                                          |
// +------|------------------------------------------+
//        v
//    +------------+
//    |            |
//    | VETH1-VPP  |
//    |            |
//    +------------+
//        ^
//        |              pod.go
// +------|------------+
// |  NS1 v            |
// |  +------------+   |
// |  |            |   |
// |  | VETH1-POD  |   |
// |  |            |   |
// |  +------------+   |
// |                   |
// +-------------------+
//
//
// 2. TAP-based pod-VPP connectivity
//
// Each POD is wired to VPP using a TAP interface created on VPP. Can be turned on by setting the UseTAPInterfaces: True
// in the config file. Legacy and  the new virtio-based TAP interfaces are supported, the latter can be turned on
// by setting the TAPInterfaceVersion: 2.
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |    VETH VPP  |____________|   VETH Host  |
// |          routing            |              |    |       |              |
// |                             +--------------+    |       +--------------+
// |    +-------+       +-------+                    |
// |    | TAP1  |       | TAPn  |                    |
// |    |       |  ...  |       |                    |
// |    +-------+       +-------+                    |
// |      ^                                          |
// |      |                                          |
// +------|------------------------------------------+
//        |
//        |              pod.go
// +------|------------+
// |  NS1 v            |
// |  +------------+   |
// |  |            |   |
// |  | TAP1-POD   |   |
// |  |            |   |
// |  +------------+   |
// |                   |
// +-------------------+
//
// Plugin Structure
// ================
//
// The plugin consists of these components:
//
//		1. Plugin base:
//			- plugin_*.go: plugin definition and setup
//			- node_events.go: handler of changes in nodes within the k8s cluster (node add / delete)
//
//		2. Remote CNI Server - the main logic of the plugin that is in charge of wiring the PODs.
//
//		3. Node ID Allocator - manages allocation/deallocation of unique number identifying a node within the k8s cluster.
//		Allocated identifier is used as an input of the IPAM calculations.
//
//		4. IPAM module (separate package, described in its own doc.go) - provides node-local IP address assignments.
//
//		5. Helper functions:
//			- host.go: provides host-related helper functions and VPP-Agent NB API builders
//			- pod.go: provides POD-related helper functions and VPP-Agent NB API builders
//
//
// Additionally, the package provides REST endpoint for getting some of the IPAM-related
// information for the node on the URL:
// GET /contiv/v1/ipam.
//
// Example:
//
//      $ curl localhost:9999/contiv/v1/ipam
//      {
//        "nodeId": 1,
//        "nodeName": "vagrant-arch.vagrantup.com",
//        "nodeIP": "192.168.16.1",
//        "podSubnetThisNode": "10.1.1.0/24",
//        "vppHostNetwork": "172.30.1.0/24"
//      }
package ipv4net
