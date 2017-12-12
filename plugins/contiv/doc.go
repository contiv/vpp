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

// Package contiv implements plugin providing GRPC-server that accepts requests from CNI plugin.
//
// 1. VETH-based pod-VPP connectivity
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |     vethVPP  |____________|   veth Host  |
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
// +------------+
// |            |
// | Veth2      |
// |            |
// +------------+
//        ^
//        |              pod.go
// +------|------------+
// |  NS1 v            |
// |  +------------+   |
// |  |            |   |
// |  | Veth1      |   |
// |  |            |   |
// |  +------------+   |
// |                   |
// +-------------------+
//
//
// 2. TAP-based pod-VPP connectivity
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |     vethVPP  |____________|   veth Host  |
// |          routing            |              |    |       |              |
// |                             +--------------+    |       +--------------+
// |    +-------+       +-------+                    |
// |    |  TAP1 |       | TAPn  |                    |
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
// |  | Linux-TAP1 |   |
// |  |            |   |
// |  +------------+   |
// |                   |
// +-------------------+
//
//
// 3. VPP TCP stack based pod-VPP connectivity
//
// +-------------------------------------------------+
// |   vSwitch VPP                                 host.go
// |                             +--------------+    |       +--------------+
// |                             |     vethVPP  |____________|   veth Host  |
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
// |       | App  |       |
// |       +------+       |
// +----------------------+
package contiv
