/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
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
// Policy plugin is split into multiple layers with the data moving
// in the direction from the up to the bottom. Each layer obtains policy-related
// data from the layer above and outputs them processed in some way into
// the layer below. With each layer the abstraction level decreases until it
// reaches the format of policies used by the target network stack.
//
// On the top there are K8s state data as reflected into ETCD by KSR.
// On the very bottom there is a virtual switch into which the policies
// are rendered. Layers in-between perform policy processing with the assistance
// of in-memory caches.
//
// Layers
// ------
//
//	1. Policy Plugin:
//     - implements the Plugin interface for CN-Infra
//     - initializes caches and all the layers, performs dependency injection
//     - watches ETCD for changes written by KSR
//     - propagates datasync events into the Policy Cache without any processing
//     - postpones RESYNC until the Contiv plugin has finalized its RESYNC
//
//  2. Policy Processor
//     - implements the PolicyCacheWatcher interface
//     - subscribes in the Policy Cache for watching changes and RESYNC events
//     - for each change, decides if the re-configuration should be postponed
//       until more data are available
//     - if a change carries enough information, processor determines the list
//       of pods with the outdated policy configuration (skipped for RESYNC)
//        - changes needed to be considered:
//           * new pod, policy, namespace
//           * removed pod, policy, namespace
//           * changed pod labels
//           * changed namespace labels
//           * changed/added/removed port names
//           * changed policy in any way
//           * pod migrated between hosts
//     - handles pod migration
//        - learns IP subnet assigned to the node from the Contiv plugin
//        - unlike Policy Configurator, the processor is aware of the
//          inter-host networking but not aware of the intra-host networking
//          details
//     - for each outdated pod, processor calculates the set of policies that
//       should be configured
//        - converts K8s Network Policies into less-abstract ContivPolicy type
//          used by the PolicyConfigurator
//           * evaluates Label Selectors
//           * translates port names into numbers
//           * expands namespaces into pods
//
//  3. Policy Configurator
//     - for a given pod, translates a set of Contiv Policies into ingress and
//       egress lists of Contiv Rules (n-tuples with the most basic policy rule
//       definition; order matters) and applies them into the target vswitch via
//       registered renderers
//     - allows to register multiple renderers for different network stacks
//     - uses the cache and the Contiv plugin to get the IP address and
//       the interface name associated with a pod, respectively
//        - i.e. unlike the processor, the configurator is aware of the
//          intra-host networking (but not aware of inter-host networking
//          details)
//     - for the best performance, creates a shortest possible sequence of rules
//       that implement a given policy
//     - for the sake of renderers that install rules into per-interface tables
//       (as opposed to one or more global tables), the configurator ensures
//       that the same set of policies always results in the same list of rules,
//       allowing renderers to group and share them across multiple interfaces
//       (if supported by the destination network stack)
//
//  4. Policy Renderer
//     - applies a list of Contiv Rules into the destination network stack
//
// Caches
// -------
//
// * Policy Cache
//    - stores K8s State data using idxmap-s
//    - processes datasync events generated when KSR reflects a change
//      in the K8s State into ETCD
//    - allows watching for changes
//    - changes are propagated via callbacks: watcher must implement
//      the PolicyCacheWatcher interface
//    - provides various lookup methods (e.g. by the label selector)
//
// * Renderer's own cache
//    - to accomplish the task of (efficient) rule rendering, renderers often
//      implement their own cache for rules (transparent for the layers above)
//    - the selection of the data structure for the cache depends on the policy
//      implementation in the destination network stack which limits
//      re-usability of caches between renderers
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
// +----------------|------------------+  +------------------------+
// |                v                  |  |                        |
// |                                   |  |                        |
// |       1. Policy Plugin        --update-->                     |
// |                                   |  |                        |
// |                                   |  |                        |
// +-----------------------------------+  |                        |
//                                        |                        |
// +-----------------------------------+  |                        |
// |                                   |  |                        |
// |                                   |  |                        |
// |       2. Policy Processor      <--watch--                     |
// |                                 <--get--                      |
// |                 |                 |  |                        |
// +-----------------|-----------------+  |      Policy Cache      |
//       Configure Contiv Policies        |                        |
// +-----------------|-----------------+  |                        |
// |                 v                 |  |                        |
// |                                   |  |                        |
// |       3. Policy Configurator    <--get--                      |
// |                                   |  |                        |
// |      |                     |      |  |                        |
// +------|---------------------|------+  +------------------------+
//        | Render Contiv Rules |
// +------v--------+   +--------v------+
// |               |   |               |
// | 4. Policy     |   | 4. Policy     |
// |   Renderer    |   |   Renderer    |
// |     +-------+ |   |     +-------+ |
// |     | cache | |   |     | cache | |
// |     +-------+ |   |     +-------+ |
// +-------|-------+   +-------|-------+
//      Render (via e.g. local client)
// +-------|-------------------|-------+
// |       v                   v       |
// |                                   |
// |            VPP / OVS / ...        |
// |                                   |
// |                                   |
// +-----------------------------------+

// Package policy implements plugin that processes and applies K8s Network
// policies into various destination network stacks. Support for a new network
// stack can be easily added into the plugin via so-called renderers.
package policy
