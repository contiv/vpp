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
//
// 2. Policy Processor
//     - implements the PolicyCacheWatcher interface
//     - subscribes in the Policy Cache for watching changes and RESYNC events
//     - for each change, decides if the re-configuration should be postponed
//       until more data are available
//     - for each change, determines the list of pods with outdated policy
//       configuration (skipped for RESYNC)
//        - changes needed to be considered:
//           * new pod, policy, namespace
//           * removed pod, policy, namespace
//           * changed pod labels
//           * changed namespace labels
//           * changed/added/removed port names
//           * changed policy in any way
//           * pod migrated between hosts
//     - for each outdated pod, processor calculates the list of policies that
//       should be configured
//        - converts K8s Network Policies into less-abstract ContivPolicy type
//          used by the PolicyConfigurator
//           * evaluates Label Selectors
//           * translates port names into numbers
//           * translates namespaces into pods
//
// 3. Policy Configurator
//     - for a given pod, translates a list of Contiv Policies into Contiv Rules
//       (n-tuple with the most basic policy rule definition) and applies them
//       into the target vswitch via registered renderers
//     - allows to register multiple renderers for different network stacks
//     - uses cache to get the IP address and the interface associated with
//       a pod
//        - i.e. unlike the processor, configurator is aware of the networking
//     - for the best performance, creates a shortest possible sequence of rules
//       that implement a given policy
//     - rules passed downwards are logically grouped to allow renderers
//       further minimize the size of the applied configuration by sharing and
//       re-ordering rules between interfaces (depends on what the target stack
//       actually supports)
//
// 4. Policy Renderer
//     - applies the Contiv Rules into the destination network stack
//     - may use prepared ContivRuleCache to easily calculate the minimal set
//       of changes that need to be applied in a given transaction
//       (if the target stack supports incremental changes)
//
// Caches
// -------
//
// * Policy Cache
//    - stores K8s State data using idxmap-s
//    - processes datasync events generated when KSR reflects a change
//      in the K8s State
//    - allows watching for changes
//    - changes are propagated via callbacks: watcher must implement
//      the PolicyCacheWatcher interface
//    - provides various lookup methods (e.g. by the label selector)
//
// * Contiv-Rule Cache
//    - a cache that renderer may use to easily calculate the minimal
//      set of changes that need to be applied in a given transaction
//      (provided that the target stack supports incremental changes)
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

package policy
