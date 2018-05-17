/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

// Architecture
// ============
//
// Service plugin is split into multiple layers with the data moving
// in the direction from the up to the bottom. Each layer obtains service-related
// data from the layer above and outputs them processed in some way into
// the layer below. On the top there are K8s state data for endpoints and
// services as reflected into ETCD by KSR. With each layer the abstraction level
// decreases until at the very bottom the corresponding set of NAT rules
// is calculated and installed into the VPP via vpp-agent.
//
// Layers
// ------
//
//	1. Service Plugin:
//     - implements the Plugin interface for CN-Infra
//     - initializes all layers, performs dependency injection
//     - watches ETCD for changes written by KSR for endpoints and services
//     - propagates datasync events into the Service Processor without
//       any pre-processing
//     - postpones RESYNC until the Contiv plugin has finalized its RESYNC
//
//  2. Service Processor
//     - receives RESYNC and data-change events for endpoints and services
//       from the service plugin
//     - internally caches the current state of the configuration (since the last
//       RESYNC)
//     - uses the cache to match subsets of endpoints with the corresponding
//       service definition
//     - combines endpoint data with service data into a less abstract service
//       representation denoted as "ContivService":
//         * service port is matched with endpoint port by the assigned name
//         * based on the service type, collects all external IP addresses,
//           i.e. addresses on which the service should be exposed
//     - maintains the set of interfaces connecting frontends (physical
//	     interfaces and pods that do not run any service) and backends (pods
//       which act as replicas of some service)
//         * the set of physical interfaces is learned from the Contiv plugin
//         * Contiv plugin is also used to convert pod IDs to their associated
//           interfaces
//
//  3. Service Configurator
//     - until we have NAT44 supported in the vpp-agent, the configurator
//       installs the configuration directly via VPP/NAT plugin binary API
//     - translates ContivService into the corresponding NAT configuration
//     - applies out2in and in2out VPP/NAT's features on interfaces connecting
//       frontends and backends, respectively
//     - for each change, calculates the minimal diff, i.e. the smallest set
//       of binary API request that need to be executed to get the NAT
//       configuration in-sync with the state of K8s services
//
//
// Diagram
// -------
//
// +-----------------------------------+
// |                                   |
// |                                   |
// |               K8s                 |
// |                                   |
// |                |                  |
// +----------------|------------------+
//           watch via K8s API
// +----------------|------------------+
// |                v                  |
// |                                   |
// |               KSR                 |
// |                                   |
// |                |                  |
// +----------------|------------------+
//                write
// +----------------|------------------+
// |                v                  |
// |                                   |
// |              ETCD                 |
// |                                   |
// |                |                  |
// +----------------|------------------+
//                watch
// +----------------|------------------+
// |                v                  |
// |                                   |
// |       1. Service Plugin           |
// |                                   |
// |                 |                 |
// +-----------------|-----------------+
//         Data-change/RESYNC
// +-----------------|-----------------+
// |                 v                 |
// |                                   |
// |       2. Service Processor        |
// |                                   |
// |                 |                 |
// +-----------------|-----------------+
//       Configure Contiv Services
// +-----------------|-----------------+
// |                 v                 |
// |                                   |
// |       3. Service Configurator     |
// |                                   |
// |      |                     |      |
// +------|---------------------|------+
//   Install NAT configuration (currently via binary APIs, later via vpp-agent)
// +------|---------------------|------+
// |      v                     v      |
// |                                   |
// |                VPP                |
// |                                   |
// |                                   |
// +-----------------------------------+
//

// Package service implements support for Kubernetes services for VPP using
// the VPP NAT plugin (https://wiki.fd.io/view/VPP/NAT).
package service
