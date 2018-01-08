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

// Package contiv implements plugin providing GRPC-server that accepts requests from the contiv-CNI
// (acting as a GRPC-client) and configures the networking between VPP and the PODs.
//
// The plugin is configurable via its config file that can be specified using
// `-contiv-config="<path to config>` argument when running the contiv-agent. This is usually being injected
// into the vswitch POD by a config map inside of the k8s deployment file of the contiv-VPP k8s networking plugin
// (see contiv-agent-cfg ConfigMap in ../../k8s/contiv-vpp.yaml).
//
// Based on the configuration, the plugin can wire PODs in 3 different ways:
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
//
// 3. VPP TCP stack based pod-VPP connectivity
//
// The PODs communicate with VPP via shared memory between VPP TCP stack and VCL library in PODs. To enable this,
// the plugin needs to be configured with TCPstackDisabled: False in the plugin config file
// and the POD needs to be deployed with ldpreload: "true" label. If the label is not specified for a POD,
// the communication between the POD and the VPP falls back to the option 1 or 2.
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |    VETH VPP  |____________|   VETH Host  |
// |          routing            |              |    |       |              |
// |                             +--------------+    |       +--------------+
// |    +-------+       +-------+                    |
// |    | LOOP1 |       | LOOPn |                    |
// |    |       |  ...  |       |                    |
// |    +-------+       +-------+                    |
// |      ^                 ^                        |
// |      |                 |                        |
// |      v                 v                        |
// |    +-----------------------+                    |
// |    |    VPP TCP Stack      |                    |
// |    +-----------------------+                    |
// |      ^                                          |
// |      |                                          |
// +------|------------------------------------------+
//        |
//        |                 pod.go
// +------|---------------+
// |  NS1 v               |
// |  +-----------------+ |
// |  |  VCL            | |
// |  | (LD_PRELOAD-ed) | |
// |  +-----------------+ |
// |          ^           |
// |          |           |
// |          v           |
// |       +------+       |
// |       | APP  |       |
// |       +------+       |
// +----------------------+
//
// Note: the picture above is simplified, each LD_PRELOAD-ed POD is actually wired also with the veth/tap (option 1/2),
// for the non-TCP/UDP communications, or not LD_PRELOAD-ed applications.
//
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
package contiv
