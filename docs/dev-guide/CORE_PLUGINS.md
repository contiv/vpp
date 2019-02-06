# Core plugins of Contiv/VPP

Contiv/VPP follows modular design - functionality is split across multiple core
plugins. Every plugin API is on one side defined by the set of events it produces
and handles, and on the other side by the state data it exposes. For example,
[nodesync](#nodesync) plugin processes `KubeStateChange` event with updates
related to K8s Node state data, pushes newly defined event `NodeUpdate`
to announce when another node joins or leaves cluster, and finally the plugin
exposes IPs and IDs of all nodes currently in the cluster through an [interface][nodesync-api].

This approach of decoupling the Contiv core functionality across multiple
plugins with a clear API defined in-between, allows to even replace an original
implementation of a core plugin and provide customized solution tailor-made for
a specific application. One may, for example, to replace the default [IPAM](#ipam)
plugin and provide custom IP address allocation mechanism. Even wiring between
pods is implemented by a separate [plugin](#ipv4net) and can be therefore easily
substituted with an alternative solution to the problem of connectivity.

Furthermore, the underlying [event loop][event-loop-guide] allows to plug-in new
event handlers, define new event types and even to alter transactions generated
for already defined core events. For example, new plugin can be appended into
the chain of event handlers, registered to process `AddPod` events and extend
connectivity between pods and VPP with additional data paths, multiple interfaces,
etc.

## Controller

[Controller plugin][controller-plugin] implements single-threaded main event loop
for Contiv. An in-depth look into the event loop can be found [here][event-loop-guide].

### Controller configuration

Controller plugin can be configured through the `controller.conf` configuration
file with the following set of options:

Parameter                      | Description        | Default
------------------------------ | ------------------ | -------
`enableRetry`                  | Enable retry of failed CRUD operations | `true`
`delayRetry`                   | Delay retry of failed CRUD operations by the given time interval in nanoseconds | `1000000000`
`maxRetryAttempts`             | Maximum number of retries to be performed for failed CRUD operations | `3`
`enableExpBackoffRetry`        | Every next retry of failed CRUD operations is delayed by twice as long time interval as the previous one | `true`
`delayLocalResync`             | How long to wait for etcd connection before using bolt DB as a fallback for startup resync | `5000000000`
`startupResyncDeadline`        | Deadline for the first resync to execute (in nanoseconds after startup) until the agent is restarted | `30000000000`
`enablePeriodicHealing`        | Enable periodic resync | `False`
`periodicHealingInterval`      | Periodic resync time interval in nanoseconds | `30000000000`
`delayAfterErrorHealing`       | How much to delay healing resync after a failure (in nanoseconds) | `5000000000`
`remoteDBProbingInterval`      | Time interval between probes triggered to test connectivity with the remote DB (in nanoseconds) | `3000000000`
`recordEventHistory`           | enable recording of processed events | `True`
`eventHistoryAgeLimit`         | event records older than the given age limit (in minutes) are periodically trimmed from the history | `1440`
`permanentlyRecordedInitPeriod`| time period (in minutes) from the start of the application with events permanently recorded | `60`

### Events

Controller [defines][controller-api] and sends several new events that other
plugins may want to react to:
* `DBResync`: carries full snapshot of Kubernetes state data, reflected into
  `etcd` by KSR, for the agent to re-synchronize against. It is sent from within
  the Controller, specifically by the internal component called [dbwatcher](#dbwatcher).
  The event is used to perform the startup resync, which the event loop guarantees
  to dispatch across handlers as the first event, even if it wasn't the first one
  to enter the queue. The list of Kubernetes resources watched and read from DB
  is defined in the top level package [dbresources][db-resources]. When a new
  resource is added for reflection into KSR, it is as simple as adding
  a specification into the list to have its state data automatically included
  in the payload for the `DBResync` event.
* `KubeStateChange` is a fellow of `DBResync`, representing an update of a single
  item from Kubernetes state data. Once again, the list of resources and the
  key prefixes under which their instances are reflected into KVDB by KSR is
  defined in the [dbresources][db-resources] package, and can be extended with
  an immediate effect for `KubeStateChange` and `DBResync` events.
* `ExternalConfigResync` and `ExternalConfigChange` are events that an adapter
  for external source of VPP/Linux configuration may use in order to deliver
  the externally-requested changes into the underlying [ligato/VPP-Agent][ligato-vpp-agent].
  More info on external configuration for developers can be found [here][external-config-guide].
  These events are processed by the Controller - the requested changes are merged
  with the configuration generated internally by Contiv plugins, before being
  applied through transactions into the VPP-Agent.
* `HealingResync` is event used to trigger re-synchronization that is supposed
  to "heal" previous errors and return the system into a healthy state.
  Whenever processing of any event results in error, the Healing resync is
  scheduled to run shortly afterwards. Healing can also run periodically,
  but this is disabled in the default configuration. During healing resync
  at least the VPP/Linux configuration is re-calculated and applied to the
  VPP-Agent to resynchronize the network plane against. The plugins can and
  should also refresh their internal states to ensure that no inconsistencies
  remain after the event is finalized. When healing resync fails, the Controller
  sends signal to the [statuscheck] plugin to mark the agent as **not-ready**,
  which will cause the `contiv-vswitch` pod to be restarted by Kubernetes.
* `Shutdown` event is used to announce that the agent is shutting down.
  Plugins have a last chance to perform some sort of cleanup - for example to
  add delete requests into the transaction for configuration items that would
  otherwise remain in the network plane even after the Contiv has been
  un-deployed.

### DBWatcher

[dbwatcher](#dbwatcher) is an internal component of the Controller plugin,
responsible for watching and reading Kubernetes state data and [the external
configuration][external-config-guide] from KVDB (`etcd` by default), and sending
`DBResync`, `KubeStateChange`, `ExternalConfigChange` events with data
snapshots/updates into the event loop.

*Note*: `ExternalConfigResync` is not used by `dbwatcher`, instead `DBResync` is
filled with both Kubernetes state data and the full snapshot of the external
configuration from KVDB.

`dbwatcher` learns about the set of KSR-reflected Kubernetes resources and their
specifications from the [dbresources][db-resources] top-level package. When
a new resource is defined and added into the list, the agent just needs to be
re-compiled for the state data to be watched and included in `DBResync` and
`KubeStateChange` events.

Furthermore, `dbwatcher` mirrors the content of the remote database into a
local DB (by default stored at `/var/bolt/bolt.db`). When remote DB is not
accessible (typically during early startup), the watcher will use local DB to
build the resync event from. Meanwhile, watching for changes is inactive.
Once the connection to remote DB is (re)gained, the watcher performs resync
against the remote database - also updating the locally mirrored data for
future outages - and re-actives the watcher.

First `DBResync` event sent from `dbwatcher` is guaranteed by the event loop
to be the first event dispatched altogether - events enqueued sooner will be
delayed.

### Input data caching

Controller plugin maintains 3 caches of input data in-memory:
* `kubeStateData (map resource -> (key -> value))`: cache of Kubernetes state
 data. For any resync event, even if it is not a resync of the K8s state, the
 controller gives reference to this cache as one of the arguments for the
 `EventHandler.Resync()` method, which event handlers should use read-only if
 needed for network configuration re-calculation.
* `externalConfig (map ext-source-label -> (key -> value))`: cache of the
 external configuration, kept separately for every source. This data are
 cached so that any change in the internal configuration can be checked for
 overlaps with the external data and merged before being submitted to the
 VPP-Agent.
* `internalConfig (map key -> value)`: cache of the internal configuration,
 kept for the same reason as the external configuration - to facilitate merging
 of internal configuration with the external data

### Controller REST API

Controller can be accessed from outside via REST API:

* [history of processed events][event-history-guide]: `GET /controller/event-history`
  - allows to read records of processed events, formatted using JSON
  - arguments (by precedence):
    * `seq-num`: event sequence numbers
    * `since` - `until`: Unix timestamps to select time window
    * `from` - `to`: sequence numbers to select interval of events
    * `first`: max. number of oldest records to return
    * `last`: max. number of latest records to return

* request KVDB resync: `POST /controller/resync`
  - sends signal to `dbwatcher` to reload K8s state data and external configuration
    from KVDB (`etcd`) and post `DBResync` event to the event loop
  - the actual resync will execute asynchronously from the client perspective

## ContivConf

[ContivConf][contivconf-plugin] plugins simplifies the Contiv configuration
processing for other plugins.

The problem is that Contiv has multiple sources of configuration:
  * configuration file, further split between the global options and node-specific
    sections
  * [NodeConfig CRD][nodeconfig-crd-model]
  * STN daemon (i.e. configuration of the stolen interface replicated from the
    host stack)
  * implicit values determined on run-time - e.g. use the first interface by
    name/index

ContivConf reads all the sources of the configuration and for each option
determines the right value based on priorities.
ContivConf is used not only within `contiv-agent`, but also for the initialization
container running [contiv-init][contiv-init] to determine whether to start the
agent in the STN mode or not.

### Events

ContivConf introduces single new event, called `NodeConfigChange`, triggered
when Node configuration provided via [CRD][nodeconfig-crd-model] changes.
The event is handled by [UpstreamResync][event-guide] (i.e. resync without SB
refresh) - the plugins should re-read the configuration provided by ContivConf
and re-calculate the state accordingly.

## NodeSync

[NodeSync plugin][nodesync-plugin] implements synchronization between Kubernetes
nodes running VPP vswitch, using a key-value database supporting atomic Put
operations (by default `etcd`).
Specifically, it allocates the first free positive integer, starting with `1`,
as a cluster-wide node identifier, primarily used for IP allocations for endpoints
inside the node that will not collide with other nodes.
Furthermore, NodeSync publishes allocations/changes of the VPP-side of node IP
address(es) - information that is not known to Kubernetes.

NodeSync defines new [resource][db-resources] called [VppNode][vppnode-model],
added into the list of items to watch for in KVDB and to dispatch across event
handlers using `DBResync` and `KubeStateChange` events.

### Events

NodeSync introduces single new event, called `NodeUpdate`, an update event that
represents change in the status of a K8s node.

For other nodes, the event is triggered when:
  * node joins the cluster
  * node leaves the cluster
  * VPP or management IP addresses of another node are updated

For the same node, the event is triggered only when:
  * the management IP addresses are updated

For update of this node VPP IP addresses, there is already resync event
`NodeIPv*Change`, that should be implemented by network connectivity plugins.

## PodManager

[PodManager][podmanager-plugin] plugin manages locally deployed pods.
It serves Add/Delete CNI requests, converts them to `AddPod` and `DeletePod`
events, and maintains a map of metadata for all locally deployed pods, with enough
information for other plugins to be able to (re)construct connectivity between
pods and the vswitch.

### Events

Request to establish connectivity with a newly created pod is received from
[contiv-cni][contiv-cni] through GRPC into PodManager, which then wraps the
request into an instance of the blocking event `AddPod`.
The event contain input parameters: *pod ID*, *container ID*, *namespace reference*,
and expects network plugins to fill-in *routes* and *interfaces* that were
configured and Kubernetes should be informed about.
Similarly, CNI request to delete pod is wrapped into blocking event `DeletePod`,
which is dispatched through the chain of event handlers in the *reverse* order.

## IPAM

[IPAM plugin][ipam-plugin] provides IP address allocation for various endpoints,
such as pods, VXLAN tunnels, VPP-host interconnect interfaces, etc.
The plugin API allows to perform allocations as well as to learn the current
state of IP address assignments.

Single IPAM instance is only responsible for node-local IP allocations.
Between nodes, however, IPAMs do not communicate with each other, instead,
the unique node ID (uint32), retrieved from the [nodesync plugin](#nodesync)
upon the first resync, is used to divide the IP address space and avoid
inter-node collisions.

Mapping between local pods and assigned IP addresses is maintained by the plugin
only in-memory, but still can be accessed from outside for reading through
the REST API:
```
GET "/contiv/v1/ipam"
```
Note: The IPAM REST API is actually implemented byt the [IPv4Net plugin](#ipv4net),
which extends the set of exposed information with some attributes specific to
network connectivity.

The in-memory cache of allocated IP addresses is lost during restart, however,
therefore the IPAM plugin must iterate through Kubernetes state data for Pods
carried by the `DBResync`, learn the IP address assignments from the previous run
and re-populate the cache.

## IPv4Net

[IPv4Net plugin][ipv4net-plugin] builds VPP and Linux network configuration
to be applied by [ligato/VPP-Agent][ligato-vpp-agent] for VPP-based IPv4 network
connectivity between Kubernetes pods and nodes.

Already with the first resync, the plugin must ensure [connectivity between VPP
and the host stack][ipv4net-host].
The plugin reacts to `AddPod`/`DeletePod` events to create or remove [link
between pod and VPP vswitch][ipv4net-pod], using `TAP` or `VETH`+`AF-PACKET`
interfaces.
It also needs to handle `NodeUpdate` events, to (re-)establish [connectivity
between the local and an updated remote node][ipv4net-node] in the cluster
(e.g. to establish/update VXLAN tunnels).
Finally, `Shutdown` event is processed to make sure that Contiv-specific
configuration items are removed from the Linux network stack when Contiv is
un-deployed.

### Events

IPv4Net plugin defines and publishes only one new event: `NodeIPv4Change`,
triggered when DHCP-assigned IPv4 address of the node changes. It is handled
using the [UpstreamResync][event-guide] as the implied configuration changes
are too complex to be determined and applied incrementally, instead it is far
easier to ask all event handlers to re-calculate the network configuration from
the scratch.

## StatsCollector

[StatsCollector plugin][statscollector-plugin] collects statistics of configured
VPP interfaces from the [vpp/ifplugin][ifplugin] of [ligato/VPP-Agent][ligato-vpp-agent],
and publishes them to the prometheus.

Inside the event loop, the plugin only needs to handle `DeletePod` to remove
gauges associated with the interface of the pod that is being un-deployed.

## Service plugin

A detailed developer guide about implementation of K8s services in Contiv/VPP
is available [here][services-guide].


## Policy plugin

An in-depth guide to policy rendering in Contiv/VPP can be found [here][policies-guide].


## GRPC plugin

Developer guide for GRPC plugin can be found in a [separate document][external-config-guide].


[event-loop-guide]: EVENT_LOOP.md
[event-guide]: EVENT_LOOP.md#event
[event-history-guide]: EVENT_LOOP.md#event-history
[external-config-guide]: EXTERNAL_CONFIG.md
[policies-guide]: POLICIES.md
[services-guide]: SERVICES.md
[nodesync-api]: https://github.com/contiv/vpp/blob/master/plugins/nodesync/nodesync_api.go
[controller-plugin]: https://github.com/contiv/vpp/tree/master/plugins/controller
[controller-api]: https://github.com/contiv/vpp/tree/master/plugins/controller/api
[contivconf-plugin]: https://github.com/contiv/vpp/tree/master/plugins/contivconf
[podmanager-plugin]: https://github.com/contiv/vpp/tree/master/plugins/podmanager
[nodesync-plugin]: https://github.com/contiv/vpp/tree/master/plugins/nodesync
[ipv4net-plugin]: https://github.com/contiv/vpp/tree/master/plugins/ipv4net
[ipv4net-host]: https://github.com/contiv/vpp/blob/master/plugins/ipv4net/host.go
[ipv4net-node]: https://github.com/contiv/vpp/blob/master/plugins/ipv4net/node.go
[ipv4net-pod]: https://github.com/contiv/vpp/blob/master/plugins/ipv4net/pod.go
[statscollector-plugin]: https://github.com/contiv/vpp/tree/master/plugins/statscollector
[ipam-plugin]: https://github.com/contiv/vpp/tree/master/plugins/ipam
[db-resources]: https://github.com/contiv/vpp/tree/master/dbresources
[statuscheck]: https://github.com/ligato/cn-infra/tree/master/health/statuscheck
[ligato-vpp-agent]: http://github.com/ligato/vpp-agent
[ifplugin]: https://github.com/ligato/vpp-agent/tree/dev/plugins/vpp/ifplugin
[nodeconfig-crd-model]: https://github.com/contiv/vpp/blob/master/plugins/crd/handler/nodeconfig/model/nodeconfig.proto
[vppnode-model]: https://github.com/contiv/vpp/blob/master/plugins/nodesync/vppnode/vppnode.proto
[contiv-init]: https://github.com/contiv/vpp/tree/master/cmd/contiv-init
[contiv-cni]: https://github.com/contiv/vpp/tree/master/cmd/contiv-cni
