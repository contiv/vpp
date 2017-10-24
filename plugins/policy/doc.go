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
// 2. Policy Processor
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
//        - learns host IP from the Contiv plugin
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
// 3. Policy Configurator
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
//     - to allow renderers share a list of ingress or egress rules between
//       interfaces, the same set of policies always results in the same list
//       of rules
//
// 4. Policy Renderer
//     - applies a list of Contiv Rules into the destination network stack
//     - may use prepared ContivRuleCache to easily calculate the minimal set
//       of changes that need to be applied in a given transaction
//       (especially useful if the target stack allows to share rules between
//       interfaces)
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
// * Contiv-Rule Cache
//    - can be used by renderer to easily calculate the minimal set of changes
//      that need to be applied in a given transaction
//    - furthermore it groups equal ingress/egress rule lists to allow renderer
//      to install only one instance of the same list and share it among
//      multiple interfaces (if supported by the destination stack)
//
// Diagram
// -------
//
// +-----------------------------------+
// |                                   |
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
// +------v--------+   +--------v------+  +------------------------+
// |               |   |               |  |                        |
// | 4. Policy     |   | 4. Policy  --update-->  Contiv-Rule Cache |
// |   Renderer    |   |   Renderer  <--diff--                     |
// |               |   |               |  |                        |
// +-------|-------+   +-------|-------+  +------------------------+
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
